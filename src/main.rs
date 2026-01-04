use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::error::Error;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
use hickory_resolver::system_conf;
use log::{info, warn};
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::ptr;
#[cfg(target_os = "linux")]
use std::sync::Once;

#[cfg(target_os = "linux")]
mod gnu_c {
    use libc::{addrinfo, c_char, c_int, sigevent};

    // Minimal glibc-compatible layout for getaddrinfo_a.
    #[repr(C)]
    pub struct Gaicb {
        pub ar_name: *const c_char,
        pub ar_service: *const c_char,
        pub ar_request: *const addrinfo,
        pub ar_result: *mut addrinfo,
        pub ar_errno: c_int,
        pub ar_cancel: c_int,
    }

    unsafe extern "C" {
        pub fn getaddrinfo_a(
            mode: c_int,
            list: *mut *mut Gaicb,
            nitems: c_int,
            sevp: *mut sigevent,
        ) -> c_int;
        pub fn gai_error(req: *mut Gaicb) -> c_int;
    }

    pub const GAI_WAIT: c_int = 0;
}

#[derive(Parser, Debug)]
#[command(about = "Check domain liveness via DNS lookups")]
struct Args {
    /// Input file with a list of URLs (one per line).
    #[arg(short, long)]
    input: PathBuf,
    /// Output file to write JSON results.
    #[arg(short, long)]
    output: PathBuf,
    /// DNS resolver backend to use.
    #[arg(long, value_enum, default_value_t = Backend::Hickory)]
    backend: Backend,
    /// Maximum number of concurrent DNS checks.
    #[arg(short = 'c', long, default_value_t = NonZeroUsize::new(100).unwrap())]
    concurrency: NonZeroUsize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Backend {
    Hickory,
    #[value(name = "gnu-c")]
    GnuC,
}

impl Backend {
    fn as_str(self) -> &'static str {
        match self {
            Backend::Hickory => "hickory",
            Backend::GnuC => "gnu-c",
        }
    }
}

#[derive(Debug)]
struct LineEntry {
    line: String,
    domain: Option<String>,
}

#[derive(Debug)]
enum LineResult {
    Checked { alive: bool },
    Invalid,
    Error,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Alive,
    Dead,
    Invalid,
    Error,
}

#[derive(Debug, Serialize)]
struct OutputRecord {
    input: String,
    domain: Option<String>,
    status: Status,
}

fn extract_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let without_scheme = trimmed.split("://").nth(1).unwrap_or(trimmed);
    let without_path = without_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let without_creds = without_path
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(without_path);

    if let Some(host) = without_creds.strip_prefix('[')
        && let Some(end) = host.find(']')
    {
        let ipv6 = &host[..end];
        if !ipv6.is_empty() {
            return Some(ipv6.to_ascii_lowercase());
        }
    }

    let host = without_creds.split(':').next().unwrap_or("");
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn tune_resolver_opts(opts: &mut ResolverOpts) {
    opts.cache_size = 1024;
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 1;
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    opts.positive_min_ttl = Some(Duration::from_secs(30));
    opts.negative_min_ttl = Some(Duration::from_secs(30));
}

#[cfg(target_os = "linux")]
fn resolve_domains_gnu_c(domains: &[String], ipv4_only: bool) -> HashMap<String, bool> {
    let mut results = HashMap::with_capacity(domains.len());
    let mut target_c_strings: Vec<CString> = Vec::new();
    let mut domain_refs: Vec<&String> = Vec::new();

    static RES_INIT: Once = Once::new();
    RES_INIT.call_once(|| {
        let res_init_result = unsafe { libc::res_init() };
        if res_init_result != 0 {
            warn!("res_init failed with code: {}", res_init_result);
        }
    });

    for domain in domains {
        match CString::new(domain.as_str()) {
            Ok(c_str) => {
                target_c_strings.push(c_str);
                domain_refs.push(domain);
            }
            Err(_) => {
                warn!("Skipping domain with NUL byte: {}", domain);
            }
        }
    }

    if target_c_strings.is_empty() {
        return results;
    }

    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = if ipv4_only {
        libc::AF_INET
    } else {
        libc::AF_UNSPEC
    };

    let mut gaicb_structs: Vec<gnu_c::Gaicb> = target_c_strings
        .iter()
        .map(|c_str| unsafe {
            let mut cb: gnu_c::Gaicb = std::mem::zeroed();
            cb.ar_name = c_str.as_ptr();
            cb.ar_request = &hints as *const libc::addrinfo;
            cb
        })
        .collect();

    let mut gaicb_ptrs: Vec<*mut gnu_c::Gaicb> = gaicb_structs
        .iter_mut()
        .map(|cb| cb as *mut gnu_c::Gaicb)
        .collect();

    let ret = unsafe {
        gnu_c::getaddrinfo_a(
            gnu_c::GAI_WAIT,
            gaicb_ptrs.as_mut_ptr(),
            gaicb_ptrs.len() as i32,
            ptr::null_mut(),
        )
    };

    if ret != 0 {
        warn!("getaddrinfo_a failed with code: {}", ret);
        for domain in &domain_refs {
            results.insert((*domain).clone(), false);
        }
        return results;
    }

    for (idx, cb) in gaicb_structs.iter().enumerate() {
        let err = unsafe { gnu_c::gai_error(cb as *const gnu_c::Gaicb as *mut gnu_c::Gaicb) };
        let alive = err == 0;
        results.insert(domain_refs[idx].to_string(), alive);

        if !cb.ar_result.is_null() {
            unsafe { libc::freeaddrinfo(cb.ar_result) };
        }
    }

    results
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let started = Instant::now();
    let args = Args::parse();
    info!("Reading input from {}", args.input.display());
    let input = tokio::fs::read_to_string(&args.input).await?;
    info!("Using backend {}", args.backend.as_str());

    let entries: Vec<LineEntry> = input
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let domain = extract_domain(trimmed);
            Some(LineEntry {
                line: trimmed.to_string(),
                domain,
            })
        })
        .collect();

    let total_entries = entries.len();
    info!("Parsed {} entries", total_entries);

    let mut results: Vec<Option<LineResult>> = (0..entries.len()).map(|_| None).collect();
    let mut domain_indices: HashMap<String, Vec<usize>> = HashMap::new();
    let mut unique_domains = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        if let Some(domain) = entry.domain.as_ref() {
            match domain_indices.entry(domain.clone()) {
                Entry::Occupied(mut existing) => existing.get_mut().push(idx),
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![idx]);
                    unique_domains.push(domain.clone());
                }
            }
        } else {
            results[idx] = Some(LineResult::Invalid);
        }
    }

    let unique_total = unique_domains.len();
    info!(
        "Unique domains: {} (deduped from {})",
        unique_total,
        entries.len()
    );
    let log_every = if unique_total < 10 {
        1
    } else {
        unique_total / 10
    };
    let mut processed = 0usize;
    let log_progress = |processed: usize| {
        if unique_total > 0 && (processed.is_multiple_of(log_every) || processed == unique_total) {
            let percent = processed * 100 / unique_total;
            info!("Progress: {}/{} ({}%)", processed, unique_total, percent);
        }
    };

    match args.backend {
        Backend::Hickory => {
            let concurrency = args.concurrency.get();
            info!("Using concurrency {}", concurrency);
            let resolver = match system_conf::read_system_conf() {
                Ok((config, mut opts)) => {
                    tune_resolver_opts(&mut opts);
                    info!(
                        "Resolver opts: cache_size={}, attempts={}, timeout={:?}, ipv4_only=true",
                        opts.cache_size, opts.attempts, opts.timeout
                    );
                    TokioAsyncResolver::tokio(config, opts)
                }
                Err(err) => {
                    warn!(
                        "Failed to load system DNS config ({}), falling back to default resolver",
                        err
                    );
                    let mut opts = ResolverOpts::default();
                    tune_resolver_opts(&mut opts);
                    info!(
                        "Resolver opts: cache_size={}, attempts={}, timeout={:?}, ipv4_only=true",
                        opts.cache_size, opts.attempts, opts.timeout
                    );
                    TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
                }
            };

            info!("Clearing Hickory resolver cache before lookups");
            resolver.clear_cache();

            let mut join_set = JoinSet::new();
            let semaphore = Arc::new(Semaphore::new(concurrency));
            info!(
                "Scheduling {} lookups (concurrency={}) for Hickory backend",
                unique_total, concurrency
            );

            for domain in unique_domains.iter().cloned() {
                let resolver = resolver.clone();
                let permit = semaphore.clone().acquire_owned().await?;
                join_set.spawn(async move {
                    let _permit = permit;
                    let alive = resolver
                        .lookup_ip(domain.as_str())
                        .await
                        .map(|ips| ips.iter().next().is_some())
                        .unwrap_or(false);
                    (domain, alive)
                });
            }

            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok((domain, alive)) => {
                        if let Some(indices) = domain_indices.remove(&domain) {
                            for idx in &indices {
                                results[*idx] = Some(LineResult::Checked { alive });
                            }
                            processed += 1;
                            log_progress(processed);
                        } else {
                            warn!("Received result for unknown domain {}", domain);
                        }
                    }
                    Err(err) => {
                        warn!("DNS check task failed: {}", err);
                    }
                }
            }
        }
        Backend::GnuC => {
            let concurrency = args.concurrency.get();
            let ipv4_only = true;
            info!(
                "GNU C backend batch_size {}, ipv4_only={}",
                concurrency, ipv4_only
            );
            #[cfg(target_os = "linux")]
            {
                let mut join_set = JoinSet::new();
                let total_batches =
                    (unique_domains.len() + concurrency.saturating_sub(1)) / concurrency;
                info!(
                    "Scheduling {} batches (batch_size={}) for GNU C backend",
                    total_batches, concurrency
                );
                let mut batch_idx = 0usize;

                for batch in unique_domains.chunks(concurrency) {
                    batch_idx += 1;
                    info!(
                        "Starting batch {}/{} ({} domains)",
                        batch_idx,
                        total_batches,
                        batch.len()
                    );
                    let batch = batch.to_vec();
                    join_set.spawn_blocking(move || resolve_domains_gnu_c(&batch, ipv4_only));
                }

                while let Some(result) = join_set.join_next().await {
                    match result {
                        Ok(resolved) => {
                            info!("Batch completed with {} results", resolved.len());
                            for (domain, alive) in resolved {
                                if let Some(indices) = domain_indices.remove(&domain) {
                                    for idx in &indices {
                                        results[*idx] = Some(LineResult::Checked { alive });
                                    }
                                    processed += 1;
                                    log_progress(processed);
                                } else {
                                    warn!("Received result for unknown domain {}", domain);
                                }
                            }
                        }
                        Err(err) => {
                            warn!("DNS check task failed: {}", err);
                        }
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err("gnu-c backend is only supported on Linux".into());
            }
        }
    }

    if !domain_indices.is_empty() {
        for (_, indices) in domain_indices.drain() {
            for idx in indices {
                results[idx] = Some(LineResult::Error);
            }
            processed += 1;
            log_progress(processed);
        }
    }

    for slot in results.iter_mut() {
        if slot.is_none() {
            *slot = Some(LineResult::Error);
        }
    }

    let mut alive_count = 0usize;
    let mut dead_count = 0usize;
    let mut invalid_count = 0usize;
    let mut error_count = 0usize;
    let mut records = Vec::with_capacity(entries.len());

    for (idx, result) in results.into_iter().enumerate() {
        let entry = &entries[idx];
        let (status, domain) = match result {
            Some(LineResult::Checked { alive }) => {
                if alive {
                    alive_count += 1;
                    (Status::Alive, entry.domain.clone())
                } else {
                    dead_count += 1;
                    (Status::Dead, entry.domain.clone())
                }
            }
            Some(LineResult::Invalid) => {
                invalid_count += 1;
                (Status::Invalid, None)
            }
            Some(LineResult::Error) | None => {
                error_count += 1;
                (Status::Error, entry.domain.clone())
            }
        };

        records.push(OutputRecord {
            input: entry.line.clone(),
            domain,
            status,
        });
    }

    let output = serde_json::to_string_pretty(&records)?;
    tokio::fs::write(&args.output, output).await?;

    info!(
        "Wrote {} results to {}",
        records.len(),
        args.output.display()
    );
    let elapsed = started.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let speed = if elapsed_secs > 0.0 {
        records.len() as f64 / elapsed_secs
    } else {
        0.0
    };
    info!(
        "Summary: alive={}, dead={}, invalid={}, error={}",
        alive_count, dead_count, invalid_count, error_count
    );
    info!("Elapsed: {:.2?}", elapsed);
    info!("Speed: {:.2} entries/sec", speed);
    Ok(())
}

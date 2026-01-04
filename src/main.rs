use std::error::Error;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use dns_checker::{Backend, Config};

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
    #[arg(long, value_enum, default_value_t = BackendArg::Hickory)]
    backend: BackendArg,
    /// Maximum number of concurrent DNS checks.
    #[arg(short = 'c', long, default_value_t = NonZeroUsize::new(100).unwrap())]
    concurrency: NonZeroUsize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackendArg {
    Hickory,
    #[value(name = "gnu-c")]
    #[cfg(all(target_os = "linux", feature = "gnu-c"))]
    GnuC,
}

impl From<BackendArg> for Backend {
    fn from(value: BackendArg) -> Self {
        match value {
            BackendArg::Hickory => Backend::Hickory,
            #[cfg(all(target_os = "linux", feature = "gnu-c"))]
            BackendArg::GnuC => Backend::GnuC,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let config = Config {
        input: args.input,
        output: args.output,
        backend: Backend::from(args.backend),
        concurrency: args.concurrency,
    };

    dns_checker::run(config).await
}

use std::ffi::CString;
use std::ptr;
use std::sync::Once;

use log::warn;

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
    }

    pub const GAI_WAIT: c_int = 0;
}

pub fn resolve_domains_gnu_c(domains: &[String], ipv4_only: bool) -> Vec<Option<bool>> {
    let mut results = vec![None; domains.len()];
    let mut target_c_strings: Vec<CString> = Vec::with_capacity(domains.len());
    let mut valid_indices: Vec<usize> = Vec::with_capacity(domains.len());

    static RES_INIT: Once = Once::new();
    RES_INIT.call_once(|| {
        let res_init_result = unsafe { libc::res_init() };
        if res_init_result != 0 {
            warn!("res_init failed with code: {}", res_init_result);
        }
    });

    for (idx, domain) in domains.iter().enumerate() {
        match CString::new(domain.as_str()) {
            Ok(c_str) => {
                target_c_strings.push(c_str);
                valid_indices.push(idx);
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
        for idx in valid_indices {
            results[idx] = Some(false);
        }
        return results;
    }

    let mut to_free: Vec<*mut libc::addrinfo> = Vec::with_capacity(gaicb_structs.len());
    for (idx, cb) in gaicb_structs.iter().enumerate() {
        let alive = cb.ar_errno == 0;
        results[valid_indices[idx]] = Some(alive);

        if !cb.ar_result.is_null() {
            to_free.push(cb.ar_result);
        }
    }

    for result in to_free {
        unsafe { libc::freeaddrinfo(result) };
    }

    results
}

use std::num::NonZeroUsize;
use std::path::PathBuf;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::{Backend, Config, run as run_inner};

fn backend_from_str(name: &str) -> PyResult<Backend> {
    if name == "hickory" {
        return Ok(Backend::Hickory);
    }
    if name == "gnu-c" {
        #[cfg(all(target_os = "linux", feature = "gnu-c"))]
        {
            return Ok(Backend::GnuC);
        }
        #[cfg(not(all(target_os = "linux", feature = "gnu-c")))]
        {
            return Err(PyValueError::new_err(
                "gnu-c backend not available in this build",
            ));
        }
    }
    Err(PyValueError::new_err(
        "backend must be 'hickory' or 'gnu-c'",
    ))
}

#[pyfunction]
#[pyo3(signature = (input, output, backend = "hickory", concurrency = 100))]
fn run(input: String, output: String, backend: &str, concurrency: usize) -> PyResult<()> {
    let backend = backend_from_str(backend)?;
    let concurrency = NonZeroUsize::new(concurrency)
        .ok_or_else(|| PyValueError::new_err("concurrency must be > 0"))?;
    let config = Config {
        input: PathBuf::from(input),
        output: PathBuf::from(output),
        backend,
        concurrency,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
    runtime
        .block_on(run_inner(config))
        .map_err(|err| PyRuntimeError::new_err(err.to_string()))
}

#[pymodule]
fn dns_checker(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(pyo3::wrap_pyfunction!(run, m)?)?;
    Ok(())
}

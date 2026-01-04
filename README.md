# dns-checker

[![Crates.io Version](https://img.shields.io/crates/v/dns-checker)](https://crates.io/crates/dns-checker)

CLI tool to check domain liveness via DNS lookups and emit JSON results.

## Installation

```bash
cargo install dns-checker
```

```bash
cargo add dns-checker
```

```toml
[dependencies]
dns-checker = "0.1.0"
```

## Usage

```bash
cargo run -- --input urls.txt --output results.json
```

## Options

- `--backend` DNS resolver backend (`hickory` default, `gnu-c` Linux only).
- `--concurrency` Maximum concurrent DNS checks (default: 100).

## Python bindings

Python 3.10+ bindings for the Rust library using PyO3.

## Build (maturin)

```bash
maturin develop --release --features "python gnu-c"
# or
maturin build --release --features "python gnu-c"
```

## Backends

- `hickory` (default)
- `gnu-c` (Linux only): build with `--features "python gnu-c"`

## Usage

```python
import dns_checker

dns_checker.run("links.txt", "results.json", backend="hickory", concurrency=100)

# or using the gnu-c backend (Linux only)
dns_checker.run("links.txt", "results.json", backend="gnu-c", concurrency=100)
```

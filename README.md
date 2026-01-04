# dns-checker

CLI tool to check domain liveness via DNS lookups and emit JSON results.

## Usage

```bash
cargo run -- --input urls.txt --output results.json
```

## Options

- `--backend` DNS resolver backend (`hickory` default, `gnu-c` Linux only).
- `--concurrency` Maximum concurrent DNS checks (default: 100).

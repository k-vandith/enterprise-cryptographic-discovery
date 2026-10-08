# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

Static analysis tool that scans source trees and configuration for cryptographic usage, weak algorithms, hardcoded secrets patterns, and policy violations — with severity scoring and report export.

## Problem Statement

Enterprises accumulate decades of code using mixed crypto libraries, deprecated algorithms (MD5, SHA-1, DES), and inconsistent key-management practices. Security teams need a repeatable, offline scanner that flags weak crypto and produces audit-ready reports without uploading source to external services.

## Overview

ECDAT walks a directory tree, applies rule-based detectors for algorithms, APIs, and secret-like patterns, assigns severity, and emits JSON / HTML reports.

## Features

- **Recursive directory scan** – source and config files
- **Algorithm detection** – MD5, SHA-1, DES, RC4, weak RSA sizes, etc.
- **Secret-pattern heuristics** – high-entropy strings, common key markers
- **Severity scoring** – CRITICAL / HIGH / MEDIUM / LOW / INFO
- **JSON + HTML reports** – CI-friendly and human-readable
- **CLI-first** – scriptable in pipelines
- **Demo fixtures** – sample vulnerable snippets for training

## Architecture

```
┌──────────┐     ┌─────────────┐     ┌──────────────┐
│   CLI    │────▶│   Scanner   │────▶│ Rule engine  │
└──────────┘     └──────┬──────┘     └──────────────┘
                        │
                 ┌──────▼──────┐
                 │ JSON / HTML │
                 │   reports   │
                 └─────────────┘
```

## Tech Stack

- Python 3.11+
- PyYAML, Jinja2, Rich
- Pydantic
- pytest

## Repository Structure

```
enterprise-cryptographic-discovery/
├── README.md
├── requirements.txt
├── src/
│   ├── cli.py
│   └── scanner.py
├── tests/
│   └── test_scanner.py
├── data/
├── scripts/
│   ├── setup_env.py
│   ├── setup.sh
│   ├── setup.ps1
│   └── generate_demo_data.py
└── docs/
```

## System Requirements

| Mode | CPU | RAM | Disk | GPU |
|------|-----|-----|------|-----|
| Demo | Any | 1 GB | 500 MB | Not needed |

## Installation

### Recommended (all platforms) — automated bootstrap

Handles missing `ensurepip`, symlink restrictions, and installs dependencies into `.venv`:

```bash
git clone https://github.com/k-vandith/enterprise-cryptographic-discovery.git
cd enterprise-cryptographic-discovery
python3 scripts/setup_env.py    # or:  python scripts/setup_env.py
```

Then activate:

```bash
# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

### Manual setup

#### Windows (PowerShell)

```powershell
git clone https://github.com/k-vandith/enterprise-cryptographic-discovery.git
cd enterprise-cryptographic-discovery
python -m venv .venv --copies
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Linux / macOS

```bash
git clone https://github.com/k-vandith/enterprise-cryptographic-discovery.git
cd enterprise-cryptographic-discovery
# If venv fails with ensurepip errors:
#   sudo apt install python3-venv python3-pip
python3 -m venv .venv --copies
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Why `--copies`?

Some environments cannot create symlinks inside a venv (`Operation not permitted` on `lib64 → lib`). Using `--copies` avoids that. `scripts/setup_env.py` tries `--copies` first automatically.

## Environment Variables

None required for default scans.

## Dataset / Demo Mode

```bash
python scripts/generate_demo_data.py
```

Creates sample files with intentional weak-crypto patterns under `data/`.

## Running the Application

```bash
python -m src.cli scan data/ --format json
python -m src.cli scan data/ --format html -o report.html
```

## API Usage

```python
from src.scanner import CryptoScanner
s = CryptoScanner()
findings = s.scan_path("data/")
print(s.to_json(findings))
```

## Testing

```bash
pytest -v
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError: src` | Run from project root; ensure `PYTHONPATH=.` |
| `venv` / ensurepip fails | Run `python3 scripts/setup_env.py` or install `python3-venv` |
| `Operation not permitted` on lib64 | Use `python3 -m venv .venv --copies` |
| Missing dependency | Activate `.venv` and re-run `pip install -r requirements.txt` |

## Limitations

- Pattern-based; not a full data-flow or taint analyzer.
- May produce false positives on test fixtures and documentation.
- Does not execute code or decrypt material.

## Security / Privacy

- Offline by design — source never leaves the machine.
- For defensive security assessment only.
- Do not scan production secrets into public CI logs.

## Future Improvements

- SARIF output for GitHub Code Scanning
- Language-specific AST parsers
- Custom policy packs

## License

MIT

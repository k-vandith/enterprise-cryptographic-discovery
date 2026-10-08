# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

Defensive static-analysis tool that scans software repositories for cryptographic usage, weak algorithms, and risky configurations.

## Features

- Rule-based detection of weak hashes (MD5, SHA-1), ciphers (DES, RC4), modes (ECB), TLS versions, hardcoded secrets, weak RNGs
- Severity + confidence labels: Detected / Suspicious / Unknown / Not enough evidence
- File/line evidence and remediation suggestions
- JSON and HTML reports
- Easy to extend with new rules

## Installation

```bash
# Linux/macOS
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Demo

```bash
python scripts/generate_demo_data.py
python -m src.cli data/sample/vulnerable_app --html report.html --json report.json
```

## Testing

```bash
pytest -v
```

## Limitations

Static pattern matching only — does not perform deep data-flow analysis. Confidence levels are explicit.

## License

MIT

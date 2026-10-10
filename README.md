<p align="center">
  <img src="assets/cipherscope-mark.svg" alt="CipherScope logo" width="92" />
</p>

<h1 align="center">CipherScope</h1>
<p align="center">
  <strong>Know what crypto is in your code. Know what to review first.</strong><br />
  Local-first cryptographic discovery for source code, configuration, and X.509 certificates.
</p>

<p align="center">
  <a href="https://github.com/k-vandith/enterprise-cryptographic-discovery/actions/workflows/tests.yml"><img src="https://github.com/k-vandith/enterprise-cryptographic-discovery/actions/workflows/tests.yml/badge.svg?branch=main" alt="Tests" /></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit&logoColor=white" alt="Streamlit" />
  <img src="https://img.shields.io/badge/processing-local--first-55c7d9?labelColor=0b0d14" alt="Local-first" />
  <img src="https://img.shields.io/badge/license-MIT-64748b" alt="MIT License" />
</p>

---

## What is CipherScope?

CipherScope is the guided workspace for **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**. It scans supported source and configuration files for cryptographic patterns that deserve human review, summarises those signals in plain English, inventories repeated patterns, inspects local certificate validity dates, and exports reports.

- **Upload real inputs:** multi-file upload or a ZIP from a project, plus an advanced local path option.
- **Understand the results:** severity totals, evidence locations, why a pattern matters, and a suggested next step.
- **Report and share:** HTML and PDF summaries, CSV findings, JSON results, and a CycloneDX-style CBOM export.

This is a rule-based triage tool, not a full static data-flow analyzer, compliance certification, or proof that a finding is exploitable.

## Quick start

Python 3.11 or newer is recommended. No paid API key or GPU is required.

~~~bash
git clone https://github.com/k-vandith/enterprise-cryptographic-discovery.git
cd enterprise-cryptographic-discovery
python scripts/setup_env.py
~~~

Activate the environment and start the workspace:

**Windows · PowerShell**
~~~powershell
.venv\Scripts\Activate.ps1
python run.py
~~~

**macOS · Linux**
~~~bash
source .venv/bin/activate
python run.py
~~~

Open **[http://127.0.0.1:8501](http://127.0.0.1:8501)**. The bootstrap script installs the app dependencies; use **pip install -r requirements-dev.txt** if you also want the development tools.

## Try it in five steps

1. Open **Overview** and choose **Load sample case**. The fictional case runs without reading your project folders or contacting a service.
2. Read the overview: files scanned, matched patterns, and the number of critical/high-priority review signals.
3. Open **Findings**. Filter by priority, search for a rule or filename, and inspect the evidence and recommended action.
4. Open **Inventory & PQC** to see recurring patterns and the legacy-pattern score. The score is a heuristic, not a formal post-quantum readiness assessment.
5. Open **Reports** to download HTML, PDF, CSV, JSON, or CBOM output. For your project, use **Scan files** and upload a ZIP or individual files.

You can also use **Download sample project ZIP** to examine the synthetic files or to practise the upload workflow.

## Supported inputs

| Input | Supported types | What the app does |
|---|---|---|
| Source and scripts | Python, JavaScript/TypeScript, Java, Go, Rust, C/C++, C#, Ruby, PHP, Swift, Kotlin, shell, SQL, Terraform, and related text formats | Applies text-pattern rules to supported file lines; it does not execute code. |
| Configuration | YAML, JSON, TOML, INI, CFG, CONF, ENV, properties, XML, TXT, Markdown | Looks for legacy crypto settings and key-like literal assignments. |
| Certificates and keys | PEM, CRT, CER, DER, KEY | Scans text markers and inspects readable X.509 certificate subject, issuer, and validity dates. Private-key bytes are not parsed or displayed. |
| Project bundle | ZIP | Stages supported files in a temporary directory, rejects unsafe traversal paths and archive symlinks, then scans the extracted text files. |
| TLS endpoint | Hostname or IP address, optional port | Initiates a live TLS connection only after the user confirms authorisation. An offline example is available and labelled as simulated. |

Upload limits are **25 MB per file**, **100 MB per batch**, **100 MB expanded ZIP content**, and **2,000 archive entries**. Unsupported file types are ignored; if no supported files are found, the app explains what to upload. Temporary upload copies are removed after analysis.

## Architecture

~~~mermaid
flowchart TD
    User[User] --> UI[Streamlit workspace]
    UI --> Upload[Upload and validate]
    Upload --> Temp[Temporary staging folder]
    Temp --> Scanner[Rule-based scanner]
    Temp --> Certs[Local X.509 inspection]
    Scanner --> Findings[Findings and severity summary]
    Certs --> Inventory[Crypto inventory and expiry view]
    Findings --> Inventory
    Inventory --> Exports[HTML / PDF / CSV / JSON / CBOM]
    UI --> Consent{Explicit permission}
    Consent -->|Confirmed| TLS[TLS endpoint probe]
    Consent -->|Not confirmed| NoNet[No live connection]
    TLS --> TLSReport[Protocol, cipher, certificate dates, issues]
    TLSReport --> Exports
~~~

## How to read a finding

Each finding includes:

- **Priority:** a rule-defined review priority (critical, high, medium, low, or info).
- **Location:** supported filename and line number.
- **Evidence:** the matched line excerpt. Literal values from the known hardcoded-key rule are redacted.
- **Why it matters:** a plain-English explanation for the detected pattern.
- **Suggested action:** a practical next step, to be checked against application requirements and the runtime configuration.

A match can come from a test fixture, migration path, comment, or example. Confirm context before changing production crypto.

## TLS and certificate checks

The **TLS & certificates** page has two modes. Local certificate inspection reads certificate metadata from an uploaded certificate file; it is offline. Live endpoint checking contacts the host and port that you entered and requires an explicit authorisation checkbox. The optional offline example makes no connection and is visibly labelled as illustrative.

Certificate expiry is calculated from the certificate validity dates or the endpoint result at the moment of the check. It does not prove that every deployed instance is using that certificate.

## CLI

The command-line interface remains available for repeatable local scans:

~~~bash
# Scan a source folder and write HTML, JSON, and CBOM reports
python -m src.cli scan ./my-project --html report.html --json findings.json --cbom inventory.cbom.json

# Run the TLS sample without contacting a host
python -m src.cli tls example.test --offline-demo --json tls-example.json
~~~

## Tests and development

~~~bash
python -m pip install -r requirements-dev.txt
ruff check src/app.py src/ui_theme.py run.py tests/test_ui_smoke.py
bandit -q -r src/app.py run.py -ll
pip-audit -r requirements.txt --progress-spinner off
pytest -q
~~~

The test suite includes scanner rules, sample-case coverage, safe ZIP extraction, secret redaction, certificate date parsing, PDF report output, and Streamlit AppTest smoke checks for each workspace page.

## Capture real page screenshots

The repository includes a small Playwright helper that starts the app, loads the synthetic case, and saves screenshots under docs/screenshots/. Playwright is an optional development tool.

~~~bash
python -m pip install playwright
python -m playwright install chromium
python scripts/capture_screenshots.py
~~~

This screenshot command must be run in an environment with the app dependencies and a browser installed. Screenshots are not generated automatically by the app or by the normal test suite.

## Privacy and limitations

- Source files are processed locally; the app does not upload source to a model or external analysis API.
- Uploaded file copies are temporary and removed after ingestion. Review reports before sharing because paths and matched context may still reveal internal details.
- Live TLS checks create outbound network connections only when explicitly requested.
- The rules are pattern-based and can miss issues or produce false positives. They do not fully analyse data flow, execute code, decrypt material, or replace a professional assessment.
- The legacy-pattern score is a prioritisation heuristic, not a NIST PQC assessment or a guarantee of post-quantum readiness.
- Do not commit production secrets or private keys to this repository or include them in screenshots and shared reports.

## Project map

~~~text
assets/cipherscope-mark.svg       Product logo
src/app.py                       Streamlit workspace and navigation
src/scanner.py                   Rule engine and HTML/JSON findings
src/upload_io.py                 Safe upload staging and certificate parsing
src/inventory.py                 Crypto inventory and legacy-pattern score
src/cbom.py                      CycloneDX-style CBOM export
src/tls_scan.py                  Offline example and optional live TLS checks
src/reports.py                   PDF report generation
src/ui_theme.py                  Shared LinkLens visual tokens, teal accent
tests/                           Core tests and page smoke checks
scripts/capture_screenshots.py   Optional Playwright screenshot helper
~~~

## License

MIT. See [LICENSE](LICENSE).

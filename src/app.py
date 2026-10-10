"""CipherScope: a local-first cryptographic discovery workspace."""
from __future__ import annotations

import base64
import ipaddress
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.cbom import cbom_to_json
from src.inventory import build_inventory, inventory_to_dict, post_quantum_readiness
from src.reports import build_pdf_report
from src.scanner import CryptoScanner, Finding, SCANNABLE_EXTENSIONS
from src.tls_scan import TLSResult, results_to_json, scan_tls_endpoint, scan_tls_offline_demo
from src.ui_theme import theme_css
from src.upload_io import inspect_certificates, stage_uploads, write_sample_case, SAMPLE_FILES

APP_NAME = "CipherScope"
ACCENT = "#55c7d9"
PAGES = [
    "Overview", "Scan files", "TLS & certificates", "Findings",
    "Inventory & PQC", "Reports", "Glossary",
]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": "#e06b75", "high": "#ee9864", "medium": "#e2b15a",
    "low": "#7eb6ff", "info": "#8d9ab1",
}
RULE_EXPLANATIONS = {
    "WEAK-MD5": "MD5 is too collision-prone for security-sensitive hashing. Check whether the use protects passwords, signatures, or integrity.",
    "WEAK-SHA1": "SHA-1 is legacy for collision-resistant use. Confirm the protocol and migration requirements before changing it.",
    "WEAK-DES": "DES and 3DES are legacy ciphers. Confirm whether this path is active and plan a modern authenticated-encryption migration.",
    "WEAK-RC4": "RC4 has serious known weaknesses. Replace it rather than relying on configuration tweaks.",
    "WEAK-ECB": "ECB can reveal repeated plaintext patterns because blocks are encrypted independently.",
    "SSL-V2V3": "SSLv2 and SSLv3 are obsolete protocol versions. Confirm the reference is active configuration, not documentation or test material.",
    "TLS10": "TLS 1.0 is legacy. Check client compatibility and prefer TLS 1.2 or TLS 1.3.",
    "HARDCODED-KEY": "A key-like variable appears to contain a literal value. The scanner redacts that value in evidence; verify safely and rotate it if real.",
    "PRIVATE-KEY-MATERIAL": "A private-key marker is present in a scanned file. If it is a real key, treat it as exposed and rotate it.",
    "CERTIFICATE-MATERIAL": "A PEM certificate marker was found. Review its validity period and deployment role.",
    "RSA-1024": "The reference may configure a small RSA key. Confirm the effective key size in the running system.",
    "CRYPTO-LIB": "A cryptographic library reference was found. Inventory the usage and verify dependency support and secure configuration.",
    "RANDOM-WEAK": "A general-purpose random generator appears near crypto-related code. Use a cryptographically secure generator for secrets and tokens.",
}


def _go_to(page: str) -> None:
    st.session_state["navigation"] = page


def _init_state() -> None:
    defaults = {
        "navigation": "Overview",
        "findings": [],
        "certificates": [],
        "files_scanned": 0,
        "source_label": "",
        "scan_time": "",
        "scan_finished": False,
        "tls_results": [],
        "tls_mode": "",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def _logo_data_uri() -> str:
    logo = ROOT / "assets" / "cipherscope-mark.svg"
    try:
        encoded = base64.b64encode(logo.read_bytes()).decode("ascii")
        return f"data:image/svg+xml;base64,{encoded}"
    except OSError:
        return ""


def _severity(finding: Finding) -> str:
    value = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    return value.lower().replace("severity.", "")


def _confidence(finding: Finding) -> str:
    value = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)
    return value.lower().replace("confidence.", "")


def _store_scan(root: Path, label: str) -> None:
    root = root.resolve()
    scanner = CryptoScanner()
    if root.is_file():
        findings = scanner.scan_file(root)
        file_count = 1
        for item in findings:
            item.file = root.name
    elif root.is_dir():
        candidates = [
            item for item in root.rglob("*")
            if item.is_file() and item.suffix.lower() in SCANNABLE_EXTENSIONS
            and not any(part in {".git", ".venv", "venv", "node_modules", "__pycache__"} for part in item.parts)
        ]
        if len(candidates) > 10_000:
            raise ValueError("This folder contains more than 10,000 supported files. Narrow the folder and scan again.")
        file_count = len(candidates)
        findings = scanner.scan_directory(root)
        for item in findings:
            try:
                item.file = Path(item.file).resolve().relative_to(root).as_posix()
            except (OSError, ValueError):
                item.file = Path(item.file).name
    else:
        raise ValueError("The selected path does not exist or cannot be read.")

    certificates = inspect_certificates([root])
    for cert in certificates:
        if root.is_dir():
            cert_path = root / str(cert["file"])
            if not cert_path.exists():
                matches = list(root.rglob(str(cert["file"])))
                if matches:
                    cert["file"] = matches[0].relative_to(root).as_posix()

    st.session_state["findings"] = findings
    st.session_state["certificates"] = certificates
    st.session_state["files_scanned"] = file_count
    st.session_state["source_label"] = label
    st.session_state["scan_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    st.session_state["scan_finished"] = True


def _scan_uploads(uploads: list[object]) -> None:
    with tempfile.TemporaryDirectory(prefix="cipherscope-") as temp_dir:
        root = Path(temp_dir)
        paths = stage_uploads(uploads, root)
        _store_scan(root, f"{len(uploads)} uploaded item(s)")
        st.session_state["files_scanned"] = len(paths)


def _scan_sample() -> None:
    with tempfile.TemporaryDirectory(prefix="cipherscope-sample-") as temp_dir:
        root = Path(temp_dir)
        write_sample_case(root)
        _store_scan(root, "Synthetic training sample")
    st.session_state["source_label"] = "Synthetic training sample"
    st.session_state["navigation"] = "Overview"


def _page_intro(title: str, purpose: str, how_to: str) -> None:
    st.markdown(f"<div class='cs-section'><div class='cs-eyebrow'>{title}</div></div>", unsafe_allow_html=True)
    st.caption(purpose)
    with st.expander("How to read this page"):
        st.write(how_to)


def _metric_card(label: str, value: object, detail: str) -> None:
    st.markdown(
        f"<div class='cs-card'><div class='cs-label'>{label}</div>"
        f"<div class='cs-value'>{value}</div><div class='cs-help'>{detail}</div></div>",
        unsafe_allow_html=True,
    )


def _findings() -> list[Finding]:
    values = st.session_state.get("findings", [])
    return values if isinstance(values, list) else []


def _finding_rows(findings: list[Finding]) -> list[dict[str, object]]:
    rows = []
    for finding in findings:
        rows.append({
            "Severity": _severity(finding).title(),
            "Finding": finding.title,
            "Rule": finding.rule_id,
            "File": finding.file,
            "Line": int(finding.line),
            "Confidence": _confidence(finding).replace("_", " "),
            "Evidence": finding.evidence,
            "Why it matters": RULE_EXPLANATIONS.get(finding.rule_id, "Review this pattern against the surrounding implementation."),
            "Suggested action": finding.remediation,
            "Category": finding.category.title(),
        })
    return rows


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {level: sum(1 for item in findings if _severity(item) == level) for level in SEVERITY_ORDER}


def _summary_takeaway(findings: list[Finding]) -> str:
    if not findings:
        return "No known patterns matched the scanned files. This does not prove the system is cryptographically secure."
    counts = _severity_counts(findings)
    urgent = counts["critical"] + counts["high"]
    top = sorted(findings, key=lambda item: SEVERITY_ORDER.index(_severity(item)))[0]
    if urgent:
        return (
            f"{urgent} finding(s) are marked critical or high priority for review. "
            f"The most severe pattern is “{top.title}” in {top.file}:{top.line}; "
            "validate it in context before treating it as a confirmed weakness."
        )
    return (
        f"The highest-severity matched pattern is “{top.title}” in {top.file}:{top.line}. "
        "Review whether the use is active code, configuration, a fixture, or documentation."
    )


def _render_results_summary(findings: list[Finding]) -> None:
    if not st.session_state.get("scan_finished"):
        st.info("No scan has been run in this session. Load the synthetic case or upload files to begin.")
        return
    counts = _severity_counts(findings)
    critical_high = counts["critical"] + counts["high"]
    cols = st.columns(4)
    with cols[0]:
        _metric_card("Files scanned", f"{int(st.session_state.get('files_scanned', 0)):,}", "Supported source and config files")
    with cols[1]:
        _metric_card("Matched patterns", f"{len(findings):,}", "Signals for human review")
    with cols[2]:
        _metric_card("Critical / high", f"{critical_high:,}", "Prioritise verification")
    with cols[3]:
        pq = post_quantum_readiness(findings)
        _metric_card("Legacy-pattern score", f"{pq['score']}/100", "Heuristic only · not certification")
    note_class = "danger" if critical_high else ""
    st.markdown(
        f"<div class='cs-note {note_class}'><b>Key takeaway</b><br>{_summary_takeaway(findings)}</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Source: {st.session_state.get('source_label') or 'Not recorded'} · "
        f"Scanned {st.session_state.get('scan_time') or '—'} · "
        "File contents are processed locally; live TLS checks are separate and require explicit consent."
    )


def _severity_chart(findings: list[Finding], *, compact: bool = False) -> None:
    counts = _severity_counts(findings)
    df = pd.DataFrame([
        {"Priority": level.title(), "Findings": counts[level]}
        for level in SEVERITY_ORDER
    ])
    fig = px.bar(
        df, x="Priority", y="Findings", color="Priority",
        color_discrete_map={key.title(): value for key, value in SEVERITY_COLORS.items()},
        category_orders={"Priority": [item.title() for item in SEVERITY_ORDER]},
    )
    fig.update_layout(
        title="Matched patterns by priority", height=330 if compact else 380,
        showlegend=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#d9e2f0"), margin=dict(l=8, r=8, t=48, b=8),
        xaxis_title=None, yaxis_title="Number of matches",
    )
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridcolor="rgba(150,170,195,.15)", rangemode="tozero")
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    st.caption("This chart counts matched lines, not confirmed exploitable vulnerabilities.")
    first = next(((level, counts[level]) for level in SEVERITY_ORDER if counts[level]), None)
    if first:
        st.markdown(f"<div class='cs-muted'><b>Key takeaway:</b> {first[1]} match(es) are {first[0]} priority.</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='cs-muted'><b>Key takeaway:</b> no known patterns matched this input.</div>", unsafe_allow_html=True)


def _render_top_findings(findings: list[Finding], limit: int = 5) -> None:
    if not findings:
        st.success("No known patterns were matched. Check your scan coverage and file types before concluding the code is safe.")
        return
    ordered = sorted(findings, key=lambda item: (SEVERITY_ORDER.index(_severity(item)), item.file, item.line))
    for item in ordered[:limit]:
        level = _severity(item)
        css_class = "danger" if level in {"critical", "high"} else ("warn" if level == "medium" else "")
        st.markdown(
            f"<div class='cs-note {css_class}'><span class='cs-badge'>{level.upper()}</span>"
            f"<b>{item.title}</b><div class='cs-muted'>{item.file}:{item.line} · {item.rule_id}</div>"
            f"<p>{RULE_EXPLANATIONS.get(item.rule_id, 'Review this pattern in context.')}</p>"
            f"<div class='cs-muted'><b>Next step:</b> {item.remediation}</div></div>",
            unsafe_allow_html=True,
        )


def _build_tls_frame(results: list[TLSResult]) -> pd.DataFrame:
    rows = []
    for result in results:
        if "demo_data" in result.issues:
            status = "Illustrative demo"
        elif not result.ok:
            status = "Connection failed"
        elif result.issues:
            status = "Review recommended"
        else:
            status = "No matched issue"
        rows.append({
            "Host": f"{result.host}:{result.port}",
            "Status": status,
            "Negotiated protocol": result.protocol or "—",
            "Cipher": result.cipher or "—",
            "Cipher strength (bits)": result.cipher_bits or "—",
            "Certificate subject": result.subject or "—",
            "Issuer": result.issuer or "—",
            "Expires in (days)": result.days_to_expiry if result.days_to_expiry is not None else "—",
            "Issues": ", ".join(result.issues) if result.issues else "No issues matched",
            "Connection note": "Not a live result" if "demo_data" in result.issues else (result.error or "—"),
        })
    return pd.DataFrame(rows)


def _parse_host_entry(value: str) -> tuple[str, int]:
    raw = value.strip()
    if not raw:
        raise ValueError("Enter a hostname on each line.")
    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.scheme not in {"https", "tls"}:
            raise ValueError("Use a hostname, host:port, or an https:// URL.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Enter only a hostname and optional port, not a full URL path.")
    else:
        parsed = urlsplit("//" + raw)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Enter only a hostname and optional port.")
    host = parsed.hostname
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError(f"Invalid port in {raw!r}.") from exc
    if not host or any(char.isspace() for char in host):
        raise ValueError(f"Could not read a hostname from {raw!r}.")
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
            raise ValueError(f"{host!r} does not look like a valid DNS hostname or IP address.")
    return host, port


def _overview(findings: list[Finding]) -> None:
    st.markdown(
        "<div class='cs-hero'><div class='cs-eyebrow'>Cryptographic posture · local-first</div>"
        "<h1>CipherScope</h1><p>Find weak cryptography, risky configuration patterns, and aging certificates "
        "before they become expensive surprises. Scan source files on your machine and turn matches into a clear review plan.</p>"
        "<span class='cs-chip'>CPU-only</span><span class='cs-chip'>Local source scanning</span>"
        "<span class='cs-chip'>No API key</span></div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div class='cs-flow'><span>1 · Upload<small>Source, configs, certificates</small></span>"
        "<span>2 · Review coverage<small>Confirm what was scanned</small></span>"
        "<span>3 · Analyze<small>Rules + local certificate metadata</small></span>"
        "<span>4 · Report<small>HTML, PDF, and CBOM</small></span></div>",
        unsafe_allow_html=True,
    )
    left, right = st.columns([1.2, 1])
    with left:
        st.markdown("### Start with a real input")
        st.write("Use your own ZIP or files, or load the built-in fictional case to see the full workflow.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Load sample case", type="primary", use_container_width=True, help="Scan fictional files that intentionally contain weak-crypto examples."):
                _scan_sample()
                st.rerun()
        with c2:
            if st.button("Upload my files", use_container_width=True, help="Open the upload and scan workspace."):
                _go_to("Scan files")
                st.rerun()
        st.download_button(
            "Download sample project ZIP", data=_sample_zip_bytes(),
            file_name="cipherscope-training-sample.zip", mime="application/zip",
            use_container_width=True,
            help="Download the same synthetic project, including intentionally weak examples.",
        )
    with right:
        st.markdown("### Who is this for?")
        st.markdown(
            "<div class='cs-card'><b>Security engineers</b><p class='cs-muted'>Find legacy crypto and potential secret leaks during review.</p>"
            "<b>Platform teams</b><p class='cs-muted'>Inventory crypto-related code and configuration before modernization.</p>"
            "<b>Educators and auditors</b><p class='cs-muted'>Use a fictional case to explain findings, evidence, and remediation.</p></div>",
            unsafe_allow_html=True,
        )
    st.markdown("<div class='cs-section'><h3>Current scan</h3></div>", unsafe_allow_html=True)
    if st.session_state.get("scan_finished"):
        _render_results_summary(findings)
        c1, c2 = st.columns([1, 1])
        with c1:
            _severity_chart(findings, compact=True)
        with c2:
            st.markdown("#### Highest-priority signals")
            _render_top_findings(findings, 4)
    else:
        st.markdown(
            "<div class='cs-card'><div class='cs-label'>Ready when you are</div>"
            "<div class='cs-value'>No project scanned yet</div>"
            "<div class='cs-help'>Your files are not uploaded anywhere by this app. Select a sample or begin with your own files.</div></div>",
            unsafe_allow_html=True,
        )
    st.caption("Pattern-based analysis helps prioritise review. It is not a full data-flow analyzer, compliance certification, or proof of exploitability.")


def _scan_files_page() -> None:
    _page_intro(
        "Scan files",
        "Upload a project ZIP, source files, configuration files, certificates, or private-key files for local pattern scanning.",
        "Choose a ZIP exported from your repository, or select multiple individual files. The app validates extensions and size limits, stages files in a temporary directory, scans them, inspects certificate metadata, then removes the temporary upload copy. Suspected secret values are redacted in displayed evidence.",
    )
    st.markdown("#### Upload source or configuration")
    uploaded = st.file_uploader(
        "Choose ZIP or files",
        type=[suffix.lstrip(".") for suffix in sorted(SCANNABLE_EXTENSIONS)] + ["zip"],
        accept_multiple_files=True,
        key="source_uploads",
        help="Maximum 25 MB per file and 100 MB per batch. Supported types include .zip, .py, .js, .java, .yaml, .json, .env, .pem, .crt, and .key.",
    )
    st.caption("Supported: source code, YAML/JSON/TOML, properties/config files, text, PEM/CRT/CER/DER certificates, keys, and ZIP archives.")
    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("Scan uploaded files", type="primary", use_container_width=True, disabled=not uploaded,
                     help="Scan the selected files without executing them."):
            try:
                with st.spinner("Validating files and checking cryptographic patterns…"):
                    _scan_uploads(uploaded or [])
                st.success(f"Scan complete. Checked {st.session_state['files_scanned']:,} supported files.")
            except (ValueError, OSError) as exc:
                st.error(str(exc))
            except Exception:
                st.error("The upload could not be processed. Try a smaller ZIP or upload the files individually.")
    with c2:
        st.download_button(
            "Download sample project ZIP", data=_sample_zip_bytes(),
            file_name="cipherscope-training-sample.zip", mime="application/zip",
            use_container_width=True, help="Fictional files for practicing the workflow.",
        )
    with st.expander("Scan an existing local path instead"):
        st.caption("Only use a path on the machine running this Streamlit app. The app will not upload the folder to a service.")
        path_value = st.text_input("Local file or folder path", placeholder=r"C:\projects\my-service or /home/me/my-service", key="local_scan_path",
                                   help="Enter a path readable by the computer running this app.")
        if st.button("Scan local path", help="Scan supported files under the local folder."):
            try:
                with st.spinner("Scanning the selected local path…"):
                    _store_scan(Path(path_value).expanduser(), path_value.strip())
                st.success(f"Scan complete. Checked {st.session_state['files_scanned']:,} supported files.")
            except (ValueError, OSError) as exc:
                st.error(str(exc))
            except Exception:
                st.error("The local path could not be scanned. Check the path and file permissions.")
    if st.session_state.get("scan_finished"):
        st.markdown("<div class='cs-section'><h3>Most recent scan</h3></div>", unsafe_allow_html=True)
        _render_results_summary(_findings())
        _render_top_findings(_findings(), 3)
        if st.button("Open findings", help="Review and filter the complete finding list."):
            _go_to("Findings")
            st.rerun()


def _tls_page() -> None:
    _page_intro(
        "TLS & certificates",
        "Inspect local X.509 certificate expiry or explicitly check public TLS endpoints you own or are authorised to assess.",
        "Local certificate metadata is read from uploaded PEM/CRT/CER/DER files and never requires a network connection. Live endpoint checks initiate a TLS connection to each host you enter; only run them against systems you own or have permission to test. The offline example is labelled as illustrative data.",
    )
    certificates = st.session_state.get("certificates", [])
    if certificates:
        st.markdown("#### Certificates in the latest file scan")
        cert_frame = pd.DataFrame(certificates)
        st.dataframe(cert_frame, hide_index=True, use_container_width=True)
        soon = [item for item in certificates if int(item.get("days_to_expiry", 99999)) < 30]
        if soon:
            st.warning(f"{len(soon)} certificate(s) are expired or due to expire within 30 days. Confirm renewal owners and deployment coverage.")
        else:
            st.success("No uploaded certificate in this scan is expired or inside the 30-day renewal window.")
        st.caption("Expiry comes from the certificate's encoded validity date. Confirm it against the deployed certificate and renewal process.")
    else:
        st.info("No local X.509 certificate metadata in the latest scan. Upload a PEM, CRT, CER, or DER certificate on the Scan files page.")

    st.markdown("<div class='cs-section'><h3>Check TLS endpoints</h3></div>", unsafe_allow_html=True)
    st.warning("Live checks contact the host you provide. Keep the list to systems in your scope; results reflect the endpoint at check time.")
    hosts_text = st.text_area(
        "Hostnames (one per line)",
        placeholder="example.com\napi.example.com:8443",
        height=100,
        help="Enter a DNS hostname or IP address, optionally with a port. Do not include credentials or URL paths. Maximum five targets per run.",
        key="tls_hosts",
    )
    authorised = st.checkbox(
        "I own these systems or have permission to check their TLS configuration.",
        key="tls_authorised",
        help="The live scan starts only after you explicitly confirm scope.",
    )
    live_col, demo_col = st.columns(2)
    with live_col:
        if st.button("Run live TLS checks", type="primary", disabled=not authorised,
                     help="Initiate a short TLS connection to each listed hostname."):
            lines = [line.strip() for line in hosts_text.splitlines() if line.strip()]
            if not lines:
                st.error("Enter at least one hostname first.")
            elif len(lines) > 5:
                st.error("Run at most five hosts at a time.")
            else:
                try:
                    targets = [_parse_host_entry(line) for line in lines]
                    results = []
                    with st.spinner("Checking TLS endpoints…"):
                        for host, port in targets:
                            results.append(scan_tls_endpoint(host, port, timeout=2.5))
                    st.session_state["tls_results"] = results
                    st.session_state["tls_mode"] = "live"
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
                except Exception:
                    st.error("The endpoint checks could not be completed. Verify hostnames, ports, and network access.")
    with demo_col:
        if st.button("Load offline TLS example", help="Show sample TLS results without making a network connection."):
            st.session_state["tls_results"] = [scan_tls_offline_demo("demo.example.test")]
            st.session_state["tls_mode"] = "demo"
            st.rerun()
    results = st.session_state.get("tls_results", [])
    if results:
        st.markdown("<div class='cs-section'><h3>Endpoint results</h3></div>", unsafe_allow_html=True)
        if st.session_state.get("tls_mode") == "demo":
            st.info("Illustrative offline example only. These values are fictional and were not observed from a live endpoint.")
        tls_df = _build_tls_frame(results)
        st.dataframe(tls_df, hide_index=True, use_container_width=True)
        expiry = [
            {"Host": f"{item.host}:{item.port}", "Days to expiry": item.days_to_expiry}
            for item in results if item.days_to_expiry is not None
        ]
        if expiry:
            st.markdown("#### Certificate expiry window")
            expiry_df = pd.DataFrame(expiry).sort_values("Days to expiry")
            fig = px.bar(expiry_df, x="Days to expiry", y="Host", orientation="h",
                         title="Days remaining before certificate expiry",
                         color="Days to expiry", color_continuous_scale=["#e06b75", "#e2b15a", "#55c7d9"])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font=dict(color="#d9e2f0"), margin=dict(l=8, r=8, t=48, b=8),
                              coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            days = min(int(item["Days to expiry"]) for item in expiry)
            st.caption(f"Key takeaway: the shortest reported validity window is {days} day(s). This is based on the endpoint result shown above.")
        st.download_button("Download TLS results JSON", results_to_json(results), file_name="cipherscope-tls-results.json", mime="application/json")
        if any(item.error for item in results):
            st.caption("Connection failures may reflect DNS, firewall, certificate trust, protocol negotiation, or endpoint availability. Check the detailed note per host.")


def _findings_page(findings: list[Finding]) -> None:
    _page_intro(
        "Findings",
        "Filter matched patterns by severity, inspect the evidence line, and follow a suggested action.",
        "Critical and high are priority labels assigned by rules; they are not exploitability scores. Evidence is a short line excerpt, and probable secret assignments are redacted. False positives can appear in tests, docs, migration code, or unreachable code.",
    )
    if not st.session_state.get("scan_finished"):
        st.info("Run a scan first. Your complete findings will appear here.")
        if st.button("Load sample case", type="primary"):
            _scan_sample()
            st.rerun()
        return
    st.markdown(f"**{len(findings):,} matched pattern(s)** from {st.session_state.get('source_label')}.")
    rows = _finding_rows(findings)
    df = pd.DataFrame(rows)
    c1, c2 = st.columns([1, 1.5])
    with c1:
        selected_levels = st.multiselect("Priority", [item.title() for item in SEVERITY_ORDER],
                                         default=[item.title() for item in SEVERITY_ORDER],
                                         help="Filter matched lines by the rule's review priority.")
    with c2:
        query = st.text_input("Search findings", placeholder="Try MD5, auth.py, secret, TLS…",
                              help="Search the finding title, rule, file, evidence, or suggested action.")
    view = df[df["Severity"].isin(selected_levels)] if not df.empty else df
    if query and not view.empty:
        mask = view.astype(str).apply(lambda column: column.str.contains(query, case=False, regex=False)).any(axis=1)
        view = view[mask]
    st.dataframe(
        view[["Severity", "Finding", "File", "Line", "Rule", "Evidence", "Why it matters", "Suggested action"]],
        hide_index=True, use_container_width=True,
        column_config={
            "Evidence": st.column_config.TextColumn("Evidence (secret values redacted)", width="medium"),
            "Why it matters": st.column_config.TextColumn("Why this was flagged", width="large"),
            "Suggested action": st.column_config.TextColumn("Suggested next step", width="large"),
        },
    )
    st.caption("Each row represents a matched rule on a file line. It is a lead for review, not a confirmed vulnerability.")
    takeaway = f"{len(view)} row(s) remain after these filters. "
    if not view.empty:
        highest = view.iloc[0]
        takeaway += f"First visible result: {highest['Finding']} in {highest['File']}:{highest['Line']}."
    else:
        takeaway += "No rows match the current filters."
    st.markdown(f"<div class='cs-note'><b>Key takeaway</b><br>{takeaway}</div>", unsafe_allow_html=True)
    st.download_button(
        "Download filtered findings CSV", view.to_csv(index=False).encode("utf-8"),
        file_name="cipherscope-findings.csv", mime="text/csv",
        help="Exports only the currently visible, filtered findings. Secret values detected by the scanner are redacted.",
    )
    with st.expander("Finding details and remediation"):
        if not view.empty:
            choice = st.selectbox("Choose a finding", view.index.tolist(),
                                  format_func=lambda ix: f"{view.loc[ix, 'Severity']} · {view.loc[ix, 'Finding']} · {view.loc[ix, 'File']}:{view.loc[ix, 'Line']}")
            row = view.loc[choice]
            st.markdown(f"### {row['Finding']}")
            st.write(row["Why it matters"])
            st.code(f"{row['File']}:{row['Line']}\n{row['Evidence']}", language="text")
            st.markdown("**Suggested next step**")
            st.write(row["Suggested action"])
            st.caption(f"Rule: {row['Rule']} · confidence label: {row['Confidence']} · category: {row['Category']}")


def _inventory_page(findings: list[Finding]) -> None:
    _page_intro(
        "Crypto inventory & PQC",
        "Group the scan results into cryptographic asset categories and review the legacy-pattern score.",
        "The inventory groups matching rules and reports where they appeared. The 0–100 score is a simple penalty heuristic applied to selected legacy patterns; a high score does not mean a service is post-quantum ready. It is not a NIST assessment or an inventory of runtime algorithms.",
    )
    if not st.session_state.get("scan_finished"):
        st.info("Run a scan to build an inventory.")
        return
    assets = inventory_to_dict(build_inventory(findings))
    pq = post_quantum_readiness(findings)
    left, right = st.columns([1, 1.25])
    with left:
        gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=int(pq["score"]),
            number={"suffix": "/100", "font": {"color": "#f4f5fb", "size": 32}},
            title={"text": "Legacy-pattern score", "font": {"color": "#d9e2f0", "size": 16}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#9ba3bb"},
                "bar": {"color": ACCENT},
                "bgcolor": "#141824",
                "bordercolor": "#282d40",
                "steps": [
                    {"range": [0, 49], "color": "#432b36"},
                    {"range": [50, 79], "color": "#3b3425"},
                    {"range": [80, 100], "color": "#1e3a3c"},
                ],
            },
        ))
        gauge.update_layout(height=280, paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#f4f5fb"),
                            margin=dict(l=10, r=10, t=52, b=8))
        st.plotly_chart(gauge, use_container_width=True, config={"displayModeBar": False})
        st.caption("Higher scores mean fewer penalties from selected patterns in this scan; they do not prove post-quantum readiness.")
        st.markdown(f"<div class='cs-note'><b>Interpretation: {pq['band'].title()}</b><br>{pq['notes']}</div>", unsafe_allow_html=True)
    with right:
        st.markdown("#### Repeated crypto patterns")
        if assets:
            asset_df = pd.DataFrame(assets)
            asset_df = asset_df.rename(columns={
                "asset_type": "Category", "name": "Pattern", "severity_max": "Highest priority",
                "count": "Occurrences", "locations": "Locations",
            })
            asset_df["Locations"] = asset_df["Locations"].map(lambda items: ", ".join(items[:5]) + (" …" if len(items) > 5 else ""))
            st.dataframe(asset_df, hide_index=True, use_container_width=True)
            st.caption("A pattern's occurrence count helps identify repeated uses; check every listed location.")
        else:
            st.info("No inventory entries were produced because no patterns matched.")
    if assets:
        chart_df = pd.DataFrame(assets).sort_values("count", ascending=True).tail(12)
        chart_df = chart_df.rename(columns={"name": "Crypto pattern", "count": "Occurrences"})
        fig = px.bar(chart_df, x="Occurrences", y="Crypto pattern", orientation="h",
                     title="Most frequent crypto-related patterns",
                     color="severity_max",
                     color_discrete_map=SEVERITY_COLORS)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          font=dict(color="#d9e2f0"), margin=dict(l=8, r=8, t=48, b=8),
                          yaxis_title=None, xaxis_title="Matched lines", legend_title="Highest priority")
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        highest = max(assets, key=lambda item: item["count"])
        st.caption(f"Key takeaway: {highest['name']} appears {highest['count']} time(s) in the scan, making it the most repeated pattern to review.")
    with st.expander("What contributes to the score?"):
        penalties = pq.get("penalties", [])
        if penalties:
            st.dataframe(pd.DataFrame(penalties).rename(columns={
                "rule_id": "Rule", "count": "Occurrences", "penalty": "Score penalty",
            }), hide_index=True, use_container_width=True)
        else:
            st.write("No configured legacy-pattern penalties were applied in this scan.")
        st.caption("This is an educational prioritisation aid. It does not inspect every cryptographic algorithm, key exchange, key size, or runtime path.")


def _reports_page(findings: list[Finding]) -> None:
    _page_intro(
        "Reports",
        "Export a compact human-readable report, structured JSON, or a cryptography bill of materials (CBOM).",
        "Reports are produced locally from the latest scan. Review paths and evidence before sharing a report because even redacted output can reveal internal structure. CBOM output follows a CycloneDX-style format and includes heuristic metadata, not a formal certification.",
    )
    if not st.session_state.get("scan_finished"):
        st.info("Run a scan before exporting reports.")
        if st.button("Load sample case", type="primary"):
            _scan_sample()
            st.rerun()
        return
    _render_results_summary(findings)
    scanner = CryptoScanner()
    html_report = scanner.to_html(findings, title="CipherScope Cryptographic Review")
    json_report = scanner.to_json(findings)
    cbom_report = cbom_to_json(findings, project_name="cipherscope")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("Download HTML report", html_report.encode("utf-8"),
                           file_name="cipherscope-report.html", mime="text/html", use_container_width=True)
        st.caption("Styled report with severity totals, evidence excerpts, and suggested actions.")
    with c2:
        st.download_button("Download PDF report", _pdf_or_message(findings),
                           file_name="cipherscope-report.pdf", mime="application/pdf",
                           use_container_width=True,
                           disabled=not _reportlab_available())
        st.caption("Portable report for sharing. ReportLab is required; install it if the PDF option is unavailable.")
    with c3:
        st.download_button("Download CBOM JSON", cbom_report.encode("utf-8"),
                           file_name="cipherscope-cbom.json", mime="application/json", use_container_width=True)
        st.caption("Machine-readable crypto inventory and selected high-priority matches.")
    with st.expander("Download all raw finding metadata as JSON"):
        st.download_button("Download findings JSON", json_report.encode("utf-8"),
                           file_name="cipherscope-findings.json", mime="application/json")
    st.markdown("<div class='cs-section'><h3>Recommended next steps</h3></div>", unsafe_allow_html=True)
    next_steps = []
    counts = _severity_counts(findings)
    if counts["critical"] + counts["high"]:
        next_steps.append("Verify critical/high signals first; rotate any real secret that may have been exposed.")
    if any(item.rule_id in {"WEAK-MD5", "WEAK-SHA1", "WEAK-DES", "WEAK-RC4", "WEAK-ECB"} for item in findings):
        next_steps.append("Trace the use of legacy hash/cipher patterns and plan a context-appropriate migration.")
    if any(item.rule_id in {"TLS10", "SSL-V2V3"} for item in findings):
        next_steps.append("Confirm the effective TLS configuration and supported-client requirements.")
    if st.session_state.get("certificates"):
        next_steps.append("Review certificate expiry windows and confirm ownership of renewals.")
    next_steps.append("Re-scan after remediation and compare the new results to the current report.")
    for number, step in enumerate(next_steps, 1):
        st.markdown(f"<div class='cs-note'><b>{number}.</b> {step}</div>", unsafe_allow_html=True)
    st.caption("Reports are generated from the latest scan session; re-run analysis after changing source files.")


def _reportlab_available() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def _pdf_or_message(findings: list[Finding]) -> bytes:
    try:
        return build_pdf_report(findings, st.session_state.get("certificates", []),
                                st.session_state.get("source_label", "Uploaded project"))
    except RuntimeError as exc:
        st.error(str(exc))
        return b""


def _glossary_page() -> None:
    _page_intro(
        "Glossary",
        "Plain-English definitions for the terms used in scan results and reports.",
        "Use this page when explaining findings to application owners, developers, or reviewers. Scanner priority is a rule-defined triage label; it should not be presented as proof that a system is exploitable.",
    )
    entries = [
        ("CBOM", "Cryptography Bill of Materials — a structured inventory of cryptographic components and related observations."),
        ("Cipher", "The algorithm used to encrypt and decrypt data."),
        ("ECB mode", "A block-cipher mode that encrypts identical blocks the same way, potentially exposing repeated patterns."),
        ("Hash function", "A function that maps data to a fixed-size digest; some older hashes are unsuitable for modern security guarantees."),
        ("Hardcoded secret", "A credential or key written directly into source or configuration rather than managed as a secret."),
        ("Heuristic", "A practical rule or approximation that helps prioritise review but can be wrong or incomplete."),
        ("PQC", "Post-quantum cryptography — cryptographic algorithms designed to resist attacks by large-scale quantum computers."),
        ("Private key", "Secret key material that must be protected; exposure may allow impersonation, decryption, or signing depending on its purpose."),
        ("Severity", "The scanner rule's review priority, not a measured probability of exploitation."),
        ("TLS", "Transport Layer Security, the protocol used to protect many network connections."),
        ("X.509 certificate", "A signed identity document that binds a public key to names or other subject information for systems such as TLS."),
    ]
    for term, meaning in entries:
        st.markdown(f"<div class='cs-card' style='margin-bottom:9px'><b>{term}</b><p class='cs-muted'>{meaning}</p></div>", unsafe_allow_html=True)
    st.markdown("<div class='cs-section'><h3>Limits to remember</h3></div>", unsafe_allow_html=True)
    st.write("CipherScope scans text patterns; it does not execute your code, fully trace data flow, prove a vulnerability, decrypt files, or certify compliance. Review the matched line and the surrounding implementation before remediation.")


def _sample_zip_bytes() -> bytes:
    import io
    import zipfile

    data = io.BytesIO()
    with zipfile.ZipFile(data, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, contents in SAMPLE_FILES.items():
            archive.writestr(name, contents)
    return data.getvalue()


def main() -> None:
    st.set_page_config(page_title="CipherScope · ECDAT", page_icon="🔐", layout="wide", initial_sidebar_state="expanded")
    _init_state()
    st.markdown(theme_css(ACCENT), unsafe_allow_html=True)
    logo_uri = _logo_data_uri()
    with st.sidebar:
        if logo_uri:
            st.markdown(
                f"<div style='display:flex;align-items:center;gap:11px;margin:4px 0 8px'>"
                f"<img src='{logo_uri}' alt='CipherScope logo' width='54' height='54'>"
                f"<div><div class='cs-brand'>CIPHERSCOPE</div><div class='cs-muted'>ECDAT · LOCAL ANALYSIS</div></div></div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown("### 🔐 CipherScope")
        st.caption("Cryptographic discovery")
        st.radio("Workspace", PAGES, key="navigation", label_visibility="collapsed",
                 help="Move between overview, scans, TLS, findings, inventory, reports, and the glossary.")
        st.divider()
        status = "SCAN READY" if st.session_state.get("scan_finished") else "AWAITING INPUT"
        st.markdown(f"<span class='cs-badge'>{status}</span>", unsafe_allow_html=True)
        st.caption("Local-first · No API key")
        if st.session_state.get("scan_finished"):
            st.caption(f"{len(_findings())} matched patterns · {st.session_state.get('files_scanned', 0)} files scanned")
        if st.button("Reset this session", help="Clear results from the current Streamlit session. It does not change original files."):
            for key in ("findings", "certificates", "files_scanned", "source_label", "scan_time", "scan_finished", "tls_results", "tls_mode"):
                st.session_state[key] = [] if key in {"findings", "certificates", "tls_results"} else (0 if key == "files_scanned" else (False if key == "scan_finished" else ""))
            st.session_state["navigation"] = "Overview"
            st.rerun()

    st.markdown(
        "<div class='cs-topbar'><div class='cs-brand'>CIPHERSCOPE</div>"
        "<div class='cs-topnote'>Cryptographic discovery &amp; analysis</div>"
        "<div class='cs-local'>● LOCAL-FIRST</div></div>",
        unsafe_allow_html=True,
    )
    page = st.session_state["navigation"]
    findings = _findings()
    if page == "Overview":
        _overview(findings)
    elif page == "Scan files":
        _scan_files_page()
    elif page == "TLS & certificates":
        _tls_page()
    elif page == "Findings":
        _findings_page(findings)
    elif page == "Inventory & PQC":
        _inventory_page(findings)
    elif page == "Reports":
        _reports_page(findings)
    else:
        _glossary_page()
    st.markdown(
        "<div class='cs-muted' style='margin-top:24px'>Rule-based signals help focus review; they are not legal findings, audit certification, or proof of exploitability. "
        "Keep real credentials out of shared reports.</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()

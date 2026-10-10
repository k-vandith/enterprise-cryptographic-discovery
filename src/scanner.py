"""Rule-based cryptographic discovery scanner (CipherScope / ECDAT)."""
from __future__ import annotations

import html
import json
import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    DETECTED = "detected"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    INSUFFICIENT = "not_enough_evidence"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    file: str
    line: int
    evidence: str
    remediation: str
    category: str = "crypto"


SCANNABLE_EXTENSIONS = (
    ".py", ".pyi", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java",
    ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cs", ".rb", ".php", ".swift",
    ".kt", ".scala", ".sh", ".bash", ".ps1", ".bat", ".sql", ".tf", ".gradle",
    ".properties", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".txt", ".md", ".json", ".xml", ".pem", ".crt", ".cer", ".key", ".der",
)


@dataclass
class Rule:
    id: str
    title: str
    pattern: re.Pattern
    severity: Severity
    confidence: Confidence
    category: str
    remediation: str
    extensions: tuple[str, ...] = SCANNABLE_EXTENSIONS


def _extension(path: Path) -> str:
    return ".env" if path.name.lower() == ".env" else path.suffix.lower()


DEFAULT_RULES: list[Rule] = [
    Rule("WEAK-MD5", "MD5 hash usage", re.compile(r"\bmd5\b|hashlib\.md5|MessageDigest\.getInstance\([\"']MD5", re.I), Severity.HIGH, Confidence.DETECTED, "hash", "Replace MD5 with SHA-256 or SHA-3."),
    Rule("WEAK-SHA1", "SHA-1 hash usage", re.compile(r"\bsha1\b|hashlib\.sha1|MessageDigest\.getInstance\([\"']SHA-?1", re.I), Severity.MEDIUM, Confidence.DETECTED, "hash", "Prefer SHA-256 or stronger where collision resistance is required."),
    Rule("WEAK-DES", "DES / 3DES encryption", re.compile(r"\b(DES|3DES|TripleDES|DESede)\b", re.I), Severity.CRITICAL, Confidence.DETECTED, "cipher", "Migrate to a modern authenticated cipher such as AES-GCM or ChaCha20-Poly1305."),
    Rule("WEAK-RC4", "RC4 stream cipher", re.compile(r"\bRC4\b|ARC4|arcfour", re.I), Severity.CRITICAL, Confidence.DETECTED, "cipher", "RC4 is broken; migrate to a modern authenticated cipher."),
    Rule("WEAK-ECB", "ECB mode detected", re.compile(r"MODE_ECB|AES/ECB|[\"']ECB[\"']|aes[^\n]{0,40}ecb", re.I), Severity.HIGH, Confidence.DETECTED, "mode", "Avoid ECB because it reveals repeated data patterns; use an authenticated encryption mode."),
    Rule("SSL-V2V3", "SSLv2 / SSLv3 reference", re.compile(r"SSLv[23]|PROTOCOL_SSLv[23]", re.I), Severity.CRITICAL, Confidence.DETECTED, "tls", "Disable SSLv2 and SSLv3; use a supported TLS version."),
    Rule("TLS10", "TLS 1.0 reference", re.compile(r"TLSv1(?:\.0)?\b|PROTOCOL_TLSv1\b|TLS1_VERSION", re.I), Severity.HIGH, Confidence.SUSPICIOUS, "tls", "Prefer TLS 1.2 or TLS 1.3 and verify compatibility before removing legacy support."),
    Rule("HARDCODED-KEY", "Possible hardcoded key or secret", re.compile(r"""(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret)\s*[:=]\s*(?:"[^"]{8,}"|'[^']{8,}'|[^\s#;]{8,})"""), Severity.CRITICAL, Confidence.SUSPICIOUS, "secrets", "If the value is real, rotate it and move secret material to a secret manager or environment variable."),
    Rule("PRIVATE-KEY-MATERIAL", "Private key material present", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.I), Severity.CRITICAL, Confidence.DETECTED, "secrets", "Treat the key as exposed: revoke or rotate it, remove it from active use, and review repository history."),
    Rule("CERTIFICATE-MATERIAL", "X.509 certificate material present", re.compile(r"-----BEGIN CERTIFICATE-----", re.I), Severity.INFO, Confidence.DETECTED, "certificate", "Review the certificate subject, issuer, validity dates, and deployment context."),
    Rule("RSA-1024", "RSA key size ≤ 1024", re.compile(r"RSA.*(1024|512)|key_size\s*=\s*(512|1024)", re.I), Severity.HIGH, Confidence.SUSPICIOUS, "asymmetric", "Use RSA at 2048 bits or stronger, or evaluate an appropriate modern alternative."),
    Rule("CRYPTO-LIB", "Cryptographic library reference", re.compile(r"from cryptography|import crypto|require\(['\"]crypto|javax\.crypto|openssl", re.I), Severity.INFO, Confidence.DETECTED, "library", "Inventory this dependency and confirm that it is supported and securely configured."),
    Rule("RANDOM-WEAK", "Weak random-number generator", re.compile(r"random\.random\(|Math\.random\(|\brand\(\)", re.I), Severity.MEDIUM, Confidence.SUSPICIOUS, "rng", "Use a cryptographically secure generator such as secrets, SecureRandom, or crypto.randomBytes."),
]


class CryptoScanner:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES

    def scan_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        if _extension(path) not in SCANNABLE_EXTENSIONS:
            return findings
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return findings
        for line_number, line in enumerate(text.splitlines(), 1):
            for rule in self.rules:
                if rule.extensions and _extension(path) not in rule.extensions:
                    continue
                if rule.pattern.search(line):
                    evidence = line.strip()[:200]
                    if rule.id == "HARDCODED-KEY":
                        evidence = re.sub(
                            r"""(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s#;]+)""",
                            r'\1\2"[REDACTED]"',
                            evidence,
                        )
                    elif rule.id == "PRIVATE-KEY-MATERIAL":
                        evidence = "[REDACTED: private key material detected]"
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            file=str(path),
                            line=line_number,
                            evidence=evidence,
                            remediation=rule.remediation,
                            category=rule.category,
                        )
                    )
        return findings

    def scan_directory(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        skip = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", ".mypy_cache"}
        for path in root.rglob("*"):
            if not path.is_file() or any(part in skip for part in path.parts):
                continue
            if _extension(path) not in SCANNABLE_EXTENSIONS:
                continue
            findings.extend(self.scan_file(path))
        return findings

    def to_json(self, findings: list[Finding]) -> str:
        rows = []
        for finding in findings:
            row = asdict(finding)
            row["severity"] = finding.severity.value
            row["confidence"] = finding.confidence.value
            rows.append(row)
        return json.dumps(rows, indent=2)

    def to_html(self, findings: list[Finding], title: str = "CipherScope Report") -> str:
        sorted_findings = sorted(findings, key=lambda item: _severity_order(item.severity.value))
        rows: list[str] = []
        for finding in sorted_findings:
            severity = _esc(finding.severity.value.upper())
            rows.append(
                f"<tr><td><span class='sev {severity.lower()}'>{severity}</span></td>"
                f"<td>{_esc(finding.title)}</td><td>{_esc(finding.rule_id)}</td>"
                f"<td>{_esc(finding.file)}:{int(finding.line)}</td>"
                f"<td><code>{_esc(finding.evidence)}</code></td>"
                f"<td>{_esc(finding.remediation)}</td></tr>"
            )
        counts = {
            level: sum(1 for item in findings if item.severity.value == level)
            for level in ("critical", "high", "medium", "low", "info")
        }
        escaped_title = _esc(title)
        metrics = "".join(
            f"<div class='metric'><span class='muted'>{_esc(level.title())}</span><b>{counts[level]}</b></div>"
            for level in ("critical", "high", "medium", "low", "info")
        )
        table_rows = "".join(rows) or '<tr><td colspan="6">No matching patterns were found in the scanned files.</td></tr>'
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escaped_title}</title>
<style>
:root{{--ink:#111827;--muted:#64748b;--line:#dbe3ed;--surface:#f8fafc}}
body{{font:15px/1.55 Inter,Segoe UI,Arial,sans-serif;color:var(--ink);max-width:1200px;margin:36px auto;padding:0 22px}}
header{{padding:24px;border-radius:18px;background:#0b0d14;color:#f4f5fb;margin-bottom:24px}}
header small{{color:#55c7d9;text-transform:uppercase;letter-spacing:.15em;font-weight:700}}
h1{{margin:.2rem 0;font-size:2rem}}.muted{{color:var(--muted)}}.metrics{{display:grid;grid-template-columns:repeat(5,minmax(110px,1fr));gap:12px;margin:18px 0}}
.metric{{border:1px solid var(--line);border-radius:12px;padding:14px;background:var(--surface)}}.metric b{{display:block;font-size:1.5rem}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}}
th{{background:#f1f5f9}}code{{white-space:pre-wrap;overflow-wrap:anywhere}}.sev{{font-size:.75rem;font-weight:700}}
.critical{{color:#b91c1c}}.high{{color:#c2410c}}.medium{{color:#a16207}}.low{{color:#0369a1}}.info{{color:#475569}}
@media(max-width:700px){{.metrics{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body>
<header><small>Local cryptographic review · heuristic analysis</small><h1>{escaped_title}</h1>
<p>Review each signal against its surrounding code and deployment context before taking action.</p></header>
<p><b>{len(findings)} findings</b> · Generated by CipherScope / ECDAT</p>
<div class="metrics">{metrics}</div>
<p class="muted">Pattern-based results can be false positives. This report is not a formal certification or a complete data-flow analysis.</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Rule</th><th>Location</th><th>Redacted evidence</th><th>Suggested action</th></tr></thead>
<tbody>{table_rows}</tbody></table>
</body></html>"""


def _severity_order(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(value.lower(), 9)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)

"""Rule-based cryptographic discovery scanner (ECDAT)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
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


@dataclass
class Rule:
    id: str
    title: str
    pattern: re.Pattern
    severity: Severity
    confidence: Confidence
    category: str
    remediation: str
    extensions: tuple[str, ...] = (".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".cs", ".rb", ".php")


DEFAULT_RULES: list[Rule] = [
    Rule("WEAK-MD5", "MD5 hash usage", re.compile(r"\b(md5|MD5)\b|hashlib\.md5|MessageDigest\.getInstance\([\"']MD5", re.I), Severity.HIGH, Confidence.DETECTED, "hash", "Replace MD5 with SHA-256 or SHA-3."),
    Rule("WEAK-SHA1", "SHA-1 hash usage", re.compile(r"\bsha1\b|hashlib\.sha1|MessageDigest\.getInstance\([\"']SHA-?1", re.I), Severity.MEDIUM, Confidence.DETECTED, "hash", "Prefer SHA-256 or stronger."),
    Rule("WEAK-DES", "DES / 3DES encryption", re.compile(r"\b(DES|3DES|TripleDES|DESede)\b", re.I), Severity.CRITICAL, Confidence.DETECTED, "cipher", "Use AES-GCM or ChaCha20-Poly1305."),
    Rule("WEAK-RC4", "RC4 stream cipher", re.compile(r"\bRC4\b|ARC4|arcfour", re.I), Severity.CRITICAL, Confidence.DETECTED, "cipher", "RC4 is broken; migrate to modern AEAD ciphers."),
    Rule("WEAK-ECB", "ECB mode detected", re.compile(r"MODE_ECB|AES/ECB|\"ECB\"|'ECB'", re.I), Severity.HIGH, Confidence.DETECTED, "mode", "Never use ECB; use GCM or CBC with random IV."),
    Rule("SSL-V2V3", "SSLv2/SSLv3 reference", re.compile(r"SSLv[23]|PROTOCOL_SSLv[23]", re.I), Severity.CRITICAL, Confidence.DETECTED, "tls", "Disable SSLv2/SSLv3; use TLS 1.2+."),
    Rule("TLS10", "TLS 1.0 reference", re.compile(r"TLSv1[^.]|PROTOCOL_TLSv1[^1]", re.I), Severity.HIGH, Confidence.SUSPICIOUS, "tls", "Prefer TLS 1.2 or 1.3."),
    Rule("HARDCODED-KEY", "Possible hardcoded key/secret", re.compile(r"(api[_-]?key|secret[_-]?key|private[_-]?key)\s*=\s*[\"'][^\"']{8,}[\"']", re.I), Severity.CRITICAL, Confidence.SUSPICIOUS, "secrets", "Move secrets to environment variables or a vault."),
    Rule("RSA-1024", "RSA key size ≤ 1024", re.compile(r"RSA.*(1024|512)|key_size\s*=\s*(512|1024)", re.I), Severity.HIGH, Confidence.SUSPICIOUS, "asymmetric", "Use RSA ≥ 2048 or switch to Ed25519/X25519."),
    Rule("CRYPTO-LIB", "Cryptographic library import", re.compile(r"from cryptography|import crypto|require\(['\"]crypto|javax\.crypto|openssl", re.I), Severity.INFO, Confidence.DETECTED, "library", "Ensure library is up to date and configured securely."),
    Rule("RANDOM-WEAK", "Weak RNG (random.random / Math.random)", re.compile(r"random\.random\(|Math\.random\(|rand\(\)", re.I), Severity.MEDIUM, Confidence.SUSPICIOUS, "rng", "Use cryptographically secure RNG (secrets, SecureRandom, crypto.randomBytes)."),
]


class CryptoScanner:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES

    def scan_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings
        lines = text.splitlines()
        for rule in self.rules:
            if path.suffix.lower() not in rule.extensions and rule.extensions:
                if path.suffix.lower() not in {".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".cs", ".rb", ".php", ".txt", ".md"}:
                    continue
            for i, line in enumerate(lines, 1):
                if rule.pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            title=rule.title,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            file=str(path),
                            line=i,
                            evidence=line.strip()[:200],
                            remediation=rule.remediation,
                            category=rule.category,
                        )
                    )
        return findings

    def scan_directory(self, root: Path) -> list[Finding]:
        all_findings: list[Finding] = []
        skip = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"}
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(s in p.parts for s in skip):
                continue
            all_findings.extend(self.scan_file(p))
        return all_findings

    def to_json(self, findings: list[Finding]) -> str:
        return json.dumps([asdict(f) for f in findings], indent=2, default=str)

    def to_html(self, findings: list[Finding], title: str = "ECDAT Report") -> str:
        rows = ""
        for f in findings:
            rows += (
                f"<tr><td>{f.severity.value}</td><td>{f.confidence.value}</td>"
                f"<td>{f.rule_id}</td><td>{f.file}:{f.line}</td>"
                f"<td><code>{_esc(f.evidence)}</code></td><td>{_esc(f.remediation)}</td></tr>\n"
            )
        return f"""<!DOCTYPE html><html><head><title>{title}</title>
<style>body{{font-family:sans-serif}} table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ccc;padding:6px;text-align:left}}
.critical{{background:#fdd}}.high{{background:#fed}}.medium{{background:#ffd}}</style>
</head><body><h1>{title}</h1><p>{len(findings)} findings</p>
<table><tr><th>Severity</th><th>Confidence</th><th>Rule</th><th>Location</th><th>Evidence</th><th>Remediation</th></tr>
{rows}</table></body></html>"""


def _esc(s: str) -> str:
    return s.replace("&", "&").replace("<", "<").replace(">", ">")

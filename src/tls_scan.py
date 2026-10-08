"""TLS endpoint and certificate scanning (stdlib only, optional live connect)."""
from __future__ import annotations

import json
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TLSResult:
    host: str
    port: int
    ok: bool
    protocol: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: int | None = None
    san: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    error: str = ""


WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHER_HINTS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon")


def scan_tls_endpoint(host: str, port: int = 443, timeout: float = 5.0) -> TLSResult:
    result = TLSResult(host=host, port=port, ok=False)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result.ok = True
                result.protocol = ssock.version() or ""
                cipher_info = ssock.cipher()
                if cipher_info:
                    result.cipher = cipher_info[0] or ""
                    result.cipher_bits = int(cipher_info[2] or 0)
                cert = ssock.getpeercert()
                if cert:
                    result.subject = _name(cert.get("subject"))
                    result.issuer = _name(cert.get("issuer"))
                    result.not_before = cert.get("notBefore", "")
                    result.not_after = cert.get("notAfter", "")
                    result.san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                    result.days_to_expiry = _days_to_expiry(result.not_after)
        result.issues = _assess(result)
    except Exception as exc:
        result.error = str(exc)
        result.issues.append(f"connection_failed: {exc}")
    return result


def scan_tls_offline_demo(host: str = "demo.local", port: int = 443) -> TLSResult:
    return TLSResult(
        host=host, port=port, ok=True, protocol="TLSv1.2",
        cipher="ECDHE-RSA-AES128-GCM-SHA256", cipher_bits=128,
        subject="CN=demo.local", issuer="CN=Demo CA",
        not_before="Jan  1 00:00:00 2025 GMT", not_after="Jan  1 00:00:00 2027 GMT",
        days_to_expiry=120, san=["demo.local", "www.demo.local"], issues=["demo_data"],
    )


def _name(parts: Any) -> str:
    if not parts:
        return ""
    try:
        return ",".join(f"{a}={b}" for tup in parts for a, b in tup)
    except Exception:
        return str(parts)


def _days_to_expiry(not_after: str) -> int | None:
    if not not_after:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S"):
        try:
            exp = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
            return (exp - datetime.now(timezone.utc)).days
        except ValueError:
            continue
    return None


def _assess(r: TLSResult) -> list[str]:
    issues = []
    if r.protocol in WEAK_PROTOCOLS:
        issues.append(f"weak_protocol:{r.protocol}")
    for hint in WEAK_CIPHER_HINTS:
        if hint.lower() in r.cipher.lower():
            issues.append(f"weak_cipher:{r.cipher}")
            break
    if r.cipher_bits and r.cipher_bits < 128:
        issues.append(f"short_key:{r.cipher_bits}")
    if r.days_to_expiry is not None and r.days_to_expiry < 30:
        issues.append(f"cert_expiring_soon:{r.days_to_expiry}d")
    return issues


def results_to_json(results: list[TLSResult]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2)

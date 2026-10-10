from __future__ import annotations

import io
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from src.reports import build_pdf_report
from src.scanner import CryptoScanner
from src.upload_io import inspect_certificates, stage_uploads, write_sample_case


class FakeUpload:
    def __init__(self, name: str, payload: bytes) -> None:
        self.name = name
        self._payload = payload

    def getvalue(self) -> bytes:
        return self._payload


def test_sample_case_has_explanatory_findings_and_redacts_secrets(tmp_path: Path) -> None:
    write_sample_case(tmp_path)
    findings = CryptoScanner().scan_directory(tmp_path)
    rules = {item.rule_id for item in findings}

    assert {"WEAK-MD5", "WEAK-ECB", "TLS10", "HARDCODED-KEY"} <= rules
    secret_finding = next(item for item in findings if item.rule_id == "HARDCODED-KEY")
    assert "TRAINING_ONLY" not in secret_finding.evidence
    assert "[REDACTED]" in secret_finding.evidence


def test_stages_individual_source_file(tmp_path: Path) -> None:
    uploaded = FakeUpload("legacy.py", b"import hashlib\nhashlib.md5(b'demo')\n")
    paths = stage_uploads([uploaded], tmp_path / "stage")

    assert len(paths) == 1
    assert paths[0].name == "legacy.py"
    assert any(item.rule_id == "WEAK-MD5" for item in CryptoScanner().scan_file(paths[0]))


def test_rejects_zip_path_traversal(tmp_path: Path) -> None:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("../outside.py", "import hashlib")
    with pytest.raises(ValueError, match="Unsafe path"):
        stage_uploads([FakeUpload("project.zip", data.getvalue())], tmp_path / "stage")
    assert not (tmp_path / "outside.py").exists()


def test_certificate_expiry_metadata(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "training.invalid")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=15)).replace(tzinfo=None))
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "training.crt"
    cert_file.write_bytes(cert.public_bytes(Encoding.PEM))

    results = inspect_certificates([cert_file])
    assert len(results) == 1
    assert results[0]["subject"] == "CN=training.invalid"
    assert results[0]["days_to_expiry"] <= 15
    assert results[0]["status"] == "Renew soon"


def test_pdf_report_is_a_real_pdf(tmp_path: Path) -> None:
    source = tmp_path / "service.py"
    source.write_text("hashlib.md5(b'demo')\n", encoding="utf-8")
    findings = CryptoScanner().scan_file(source)
    pdf = build_pdf_report(findings, source_label="test input")
    assert pdf.startswith(b"%PDF")


def test_redacts_unquoted_env_secret_and_private_key_material(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=sk-training-fake-secret-should-not-leak\n", encoding="utf-8")
    env_findings = CryptoScanner().scan_file(env_file)
    secret = next(item for item in env_findings if item.rule_id == "HARDCODED-KEY")
    assert "sk-training-fake-secret" not in secret.evidence
    assert "[REDACTED]" in secret.evidence

    key_file = tmp_path / "private.pem"
    key_file.write_text(
        "-----BEGIN PRIVATE KEY-----SECRET_PRIVATE_KEY_BODY_DO_NOT_LEAK-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    key_findings = CryptoScanner().scan_file(key_file)
    private_key = next(item for item in key_findings if item.rule_id == "PRIVATE-KEY-MATERIAL")
    assert "SECRET_PRIVATE_KEY_BODY" not in private_key.evidence
    assert "REDACTED" in private_key.evidence

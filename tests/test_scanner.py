from pathlib import Path
from src.scanner import Confidence, CryptoScanner, Severity, is_scannable_path, iter_scannable_files


def test_scan_md5(tmp_path: Path):
    f = tmp_path / "a.py"
    f.write_text("import hashlib\nhashlib.md5(b'data')\n")
    findings = CryptoScanner().scan_file(f)
    assert any(x.rule_id == "WEAK-MD5" for x in findings)


def test_scan_dir(tmp_path: Path):
    (tmp_path / "b.py").write_text("cipher = AES.new(key, AES.MODE_ECB)\n")
    findings = CryptoScanner().scan_directory(tmp_path)
    assert any(x.rule_id == "WEAK-ECB" for x in findings)


def test_json_html(tmp_path: Path):
    f = tmp_path / "c.py"
    f.write_text("hashlib.sha1(b'x')\n")
    sc = CryptoScanner()
    findings = sc.scan_file(f)
    js = sc.to_json(findings)
    assert "WEAK-SHA1" in js
    html = sc.to_html(findings)
    assert "<table>" in html



def test_redacts_long_quoted_secret_before_truncating_evidence(tmp_path: Path):
    secret = "LONG_SECRET_MARKER_" + ("x" * 260)
    f = tmp_path / "settings.py"
    f.write_text(f'api_key = "{secret}"\n', encoding="utf-8")

    scanner = CryptoScanner()
    findings = scanner.scan_file(f)
    finding = next(item for item in findings if item.rule_id == "HARDCODED-KEY")

    assert secret not in finding.evidence
    assert "LONG_SECRET_MARKER_" not in finding.evidence
    assert "[REDACTED]" in finding.evidence
    assert secret not in scanner.to_json(findings)
    assert secret not in scanner.to_html(findings)


def test_tls_12_and_tls_13_are_not_flagged_as_tls_10(tmp_path: Path):
    f = tmp_path / "tls.yaml"
    f.write_text('minimum: TLSv1.2\nrecommended: TLSv1.3\n', encoding="utf-8")
    scanner = CryptoScanner()

    assert not any(item.rule_id == "TLS10" for item in scanner.scan_file(f))

    f.write_text('minimum: TLSv1.0\n', encoding="utf-8")
    assert any(item.rule_id == "TLS10" for item in scanner.scan_file(f))


def test_empty_custom_rule_list_disables_all_rules(tmp_path: Path):
    f = tmp_path / "a.py"
    f.write_text("hashlib.md5(b'data')\n", encoding="utf-8")

    assert CryptoScanner(rules=[]).scan_file(f) == []


def test_scannable_file_iterator_counts_env_and_skips_generated_directories(tmp_path: Path):
    (tmp_path / ".env").write_text("API_KEY=training-only-value\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / ".tox" / "env").mkdir(parents=True)
    (tmp_path / ".tox" / "env" / "ignored.py").write_text("hashlib.md5(x)\n", encoding="utf-8")
    (tmp_path / ".mypy_cache").mkdir()
    (tmp_path / ".mypy_cache" / "ignored.py").write_text("hashlib.sha1(x)\n", encoding="utf-8")

    actual = {path.relative_to(tmp_path).as_posix() for path in iter_scannable_files(tmp_path)}

    assert actual == {".env", "main.py"}
    assert is_scannable_path(tmp_path / ".env")



def test_secret_evidence_is_redacted_for_overlapping_rules_and_long_lines(tmp_path: Path):
    secret = "LONG_SECRET_SENTINEL_" + ("x" * 300)
    source = tmp_path / "overlapping.py"
    source.write_text(f'API_KEY = "{secret}"  # random.random()\n', encoding="utf-8")

    findings = CryptoScanner().scan_file(source)
    assert {item.rule_id for item in findings} >= {"HARDCODED-KEY", "RANDOM-WEAK"}
    assert all(secret not in item.evidence for item in findings)
    assert all("[REDACTED]" in item.evidence for item in findings)


def test_encrypted_private_key_marker_is_redacted_for_every_matching_rule(tmp_path: Path):
    source = tmp_path / "encrypted-key.py"
    source.write_text(
        'private_key = "-----BEGIN ENCRYPTED PRIVATE KEY-----"  # random.random()\n',
        encoding="utf-8",
    )

    findings = CryptoScanner().scan_file(source)
    assert {item.rule_id for item in findings} >= {
        "HARDCODED-KEY", "PRIVATE-KEY-MATERIAL", "RANDOM-WEAK"
    }
    assert all("ENCRYPTED PRIVATE KEY" not in item.evidence for item in findings)
    assert all("random.random()" not in item.evidence for item in findings)


def test_directory_scan_is_relative_to_selected_root_even_when_parent_is_named_venv(tmp_path: Path):
    root = tmp_path / "venv" / "project"
    (root / "src").mkdir(parents=True)
    (root / ".venv").mkdir()
    (root / ".env").write_text('API_KEY="training-secret-value-123456"\n', encoding="utf-8")
    (root / "src" / "auth.py").write_text("hashlib.md5(b'demo')\n", encoding="utf-8")
    (root / ".venv" / "ignored.py").write_text("hashlib.md5(b'ignored')\n", encoding="utf-8")
    (root / "notes.exe").write_text("hashlib.md5(b'unsupported')\n", encoding="utf-8")

    paths = {path.relative_to(root).as_posix() for path in iter_scannable_files(root)}
    assert paths == {".env", "src/auth.py"}
    findings = CryptoScanner().scan_directory(root)
    assert any(item.rule_id == "HARDCODED-KEY" and item.file.endswith(".env") for item in findings)
    assert any(item.rule_id == "WEAK-MD5" and item.file.endswith("auth.py") for item in findings)
    assert all("ignored.py" not in item.file for item in findings)



def test_directory_scan_order_is_stable_by_relative_path(tmp_path: Path):
    (tmp_path / "z-last.py").write_text("hashlib.md5(b'x')\n", encoding="utf-8")
    (tmp_path / "a-first.py").write_text("hashlib.sha1(b'x')\n", encoding="utf-8")

    findings = CryptoScanner().scan_directory(tmp_path)

    assert [Path(item.file).name for item in findings] == ["a-first.py", "z-last.py"]



def test_empty_scan_report_does_not_claim_the_files_are_safe():
    report = CryptoScanner().to_html([])

    assert "No configured patterns matched" in report
    assert "not proof" in report
    assert "cryptographically safe" in report



def test_unreadable_file_is_reported_as_not_scanned(tmp_path: Path, monkeypatch):
    source = tmp_path / "locked.py"
    source.write_text("hashlib.md5(data)\n", encoding="utf-8")
    original = Path.read_text

    def denied(path: Path, *args, **kwargs):
        if path == source:
            raise PermissionError("test permission error")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    findings = CryptoScanner().scan_file(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SCAN-ERROR"
    assert findings[0].confidence == Confidence.INSUFFICIENT
    assert "not analyzed" in findings[0].evidence

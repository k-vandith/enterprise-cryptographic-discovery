from pathlib import Path
from src.scanner import CryptoScanner, Severity, is_scannable_path, iter_scannable_files


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

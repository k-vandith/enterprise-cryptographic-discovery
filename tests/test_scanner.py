from pathlib import Path
from src.scanner import CryptoScanner, Severity


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



def test_secret_evidence_is_redacted_for_overlapping_rules_and_long_lines(tmp_path: Path):
    secret = "unique-training-secret-should-never-appear-in-evidence"
    short_file = tmp_path / "short.py"
    short_file.write_text(
        f'API_KEY = "{secret}"  # random.random()\n', encoding="utf-8"
    )
    findings = CryptoScanner().scan_file(short_file)
    assert {item.rule_id for item in findings} >= {"HARDCODED-KEY", "RANDOM-WEAK"}
    assert all(secret not in item.evidence for item in findings)
    assert all("[REDACTED]" in item.evidence for item in findings)

    long_secret = "LONG_SECRET_SENTINEL_" + ("x" * 300)
    long_file = tmp_path / "long.py"
    long_file.write_text(
        f'API_KEY = "{long_secret}"  # random.random()\n', encoding="utf-8"
    )
    long_findings = CryptoScanner().scan_file(long_file)
    assert {item.rule_id for item in long_findings} >= {"HARDCODED-KEY", "RANDOM-WEAK"}
    assert all(long_secret not in item.evidence for item in long_findings)
    assert all("[REDACTED]" in item.evidence for item in long_findings)


def test_private_key_marker_is_redacted_for_overlapping_rules(tmp_path: Path):
    source = tmp_path / "key.py"
    source.write_text(
        'private_key = "-----BEGIN PRIVATE KEY-----"  # random.random()\n',
        encoding="utf-8",
    )
    findings = CryptoScanner().scan_file(source)
    assert {item.rule_id for item in findings} >= {
        "HARDCODED-KEY", "PRIVATE-KEY-MATERIAL", "RANDOM-WEAK"
    }
    assert all("BEGIN PRIVATE KEY" not in item.evidence for item in findings)
    assert all("random.random()" not in item.evidence for item in findings)



def test_directory_scan_includes_dotenv_and_skips_only_root_relative_dependency_folders(tmp_path: Path):
    root = tmp_path / "venv" / "project"
    (root / "src").mkdir(parents=True)
    (root / ".venv").mkdir()
    (root / ".env").write_text('API_KEY="training-secret-value-123456"\n', encoding="utf-8")
    (root / "src" / "auth.py").write_text("hashlib.md5(b'demo')\n", encoding="utf-8")
    (root / ".venv" / "ignored.py").write_text("hashlib.md5(b'ignored')\n", encoding="utf-8")
    (root / "notes.exe").write_text("hashlib.md5(b'unsupported')\n", encoding="utf-8")

    paths = {path.relative_to(root).as_posix() for path in iter_scannable_files(root)}
    assert paths == {".env", "src/auth.py"}
    assert not is_scannable_path(root / "notes.exe")

    findings = CryptoScanner().scan_directory(root)
    assert any(item.rule_id == "HARDCODED-KEY" and item.file.endswith(".env") for item in findings)
    assert any(item.rule_id == "WEAK-MD5" and item.file.endswith("auth.py") for item in findings)
    assert all("ignored.py" not in item.file for item in findings)

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

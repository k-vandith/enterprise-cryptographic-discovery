"""Tests for TLS demo, inventory, PQ score, CBOM."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.app import _safe_csv_export
from src.scanner import CryptoScanner
from src.inventory import build_inventory, post_quantum_readiness
from src.cbom import build_cbom, cbom_to_json
from src.tls_scan import scan_tls_offline_demo


def test_tls_offline_demo():
    r = scan_tls_offline_demo("example.test")
    assert r.ok and r.protocol.startswith("TLS") and r.cipher_bits >= 128


def test_inventory_and_pq(tmp_path: Path):
    f = tmp_path / "bad.py"
    f.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    findings = CryptoScanner().scan_file(f)
    assert findings
    inv = build_inventory(findings)
    assert inv
    pq = post_quantum_readiness(findings)
    assert 0 <= pq["score"] <= 100
    assert pq["band"] in {"good", "moderate", "poor"}


def test_cbom(tmp_path: Path):
    f = tmp_path / "c.py"
    f.write_text("DES.encrypt(data)\n", encoding="utf-8")
    findings = CryptoScanner().scan_file(f)
    bom = build_cbom(findings, project_name="unit")
    assert bom["bomFormat"] == "CycloneDX"
    assert "CycloneDX" in cbom_to_json(findings)



def test_cbom_vulnerability_references_declared_component(tmp_path: Path):
    f = tmp_path / "crypto.py"
    f.write_text("DES.encrypt(data)\n", encoding="utf-8")
    findings = CryptoScanner().scan_file(f)

    bom = build_cbom(findings, project_name="unit")
    component_refs = {component["bom-ref"] for component in bom["components"]}
    vulnerabilities = bom["vulnerabilities"]

    assert vulnerabilities
    assert all(
        affected["ref"] in component_refs
        for vulnerability in vulnerabilities
        for affected in vulnerability["affects"]
    )
    assert any(
        prop["name"] == "ecdat:location" and prop["value"].endswith(":1")
        for vulnerability in vulnerabilities
        for prop in vulnerability.get("properties", [])
    )


def test_csv_export_neutralizes_formula_like_cells():
    frame = pd.DataFrame({
        "Evidence": ['=HYPERLINK("https://evil.invalid","click")', "  @SUM(1,1)", "ordinary text"],
    })

    exported = _safe_csv_export(frame).decode("utf-8")

    assert "'=HYPERLINK" in exported
    assert "'  @SUM" in exported
    assert "ordinary text" in exported

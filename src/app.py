"""Streamlit UI for ECDAT."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st
import pandas as pd

from src.scanner import CryptoScanner
from src.inventory import build_inventory, post_quantum_readiness, inventory_to_dict
from src.cbom import cbom_to_json
from src.tls_scan import scan_tls_endpoint, scan_tls_offline_demo, results_to_json

st.set_page_config(page_title="ECDAT", page_icon="🔐", layout="wide")
st.title("🔐 Enterprise Cryptographic Discovery & Analysis Tool")
st.caption("Offline static crypto scan · Inventory · PQ readiness · CBOM · TLS probe")

scanner = CryptoScanner()
demo_dir = ROOT / "data" / "sample" / "vulnerable_app"

tab1, tab2, tab3, tab4 = st.tabs(["Source scan", "Inventory / PQ", "TLS", "CBOM export"])

with tab1:
    path_str = st.text_input("Path to scan", value=str(demo_dir))
    if st.button("Scan"):
        p = Path(path_str)
        findings = scanner.scan_file(p) if p.is_file() else (scanner.scan_directory(p) if p.is_dir() else [])
        if not p.exists():
            st.error("Path not found")
        else:
            st.session_state["findings"] = findings
            st.success(f"{len(findings)} findings")
            if findings:
                st.dataframe(pd.DataFrame([f.__dict__ for f in findings]), use_container_width=True)
                st.download_button("Download HTML report", scanner.to_html(findings), file_name="ecdat_report.html")

with tab2:
    findings = st.session_state.get("findings") or []
    if not findings and demo_dir.exists():
        findings = scanner.scan_directory(demo_dir)
    inv = build_inventory(findings)
    pq = post_quantum_readiness(findings)
    st.metric("PQ readiness score", pq["score"], help=pq["notes"])
    st.write("Band:", pq["band"])
    st.dataframe(pd.DataFrame(inventory_to_dict(inv)), use_container_width=True)

with tab3:
    offline = st.checkbox("Offline demo TLS result (no network)", value=True)
    host = st.text_input("Host", value="demo.local")
    port = st.number_input("Port", value=443, min_value=1, max_value=65535)
    if st.button("Probe TLS"):
        res = scan_tls_offline_demo(host, int(port)) if offline else scan_tls_endpoint(host, int(port))
        st.json(res.__dict__)
        st.download_button("TLS JSON", results_to_json([res]), file_name="tls.json")

with tab4:
    findings = st.session_state.get("findings") or (scanner.scan_directory(demo_dir) if demo_dir.exists() else [])
    cbom = cbom_to_json(findings, project_name="ecdat-demo")
    st.code(cbom[:2000] + ("…" if len(cbom) > 2000 else ""), language="json")
    st.download_button("Download CBOM JSON", cbom, file_name="cbom.json")

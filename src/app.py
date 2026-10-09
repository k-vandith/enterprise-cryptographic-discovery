"""ECDAT findings workspace."""
from __future__ import annotations
import sys
from dataclasses import asdict
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import pandas as pd
import streamlit as st
from src.cbom import cbom_to_json
from src.inventory import build_inventory, inventory_to_dict, post_quantum_readiness
from src.scanner import CryptoScanner
from src.tls_scan import results_to_json, scan_tls_offline_demo
from src.ui_theme import theme_css

def _scan(path_str: str) -> list[dict]:
    scanner = CryptoScanner()
    p = Path(path_str)
    if not p.exists():
        return []
    findings = scanner.scan_file(p) if p.is_file() else scanner.scan_directory(p)
    rows = []
    for f in findings:
        row = asdict(f)
        row["severity"] = str(row["severity"])
        row["confidence"] = str(row["confidence"])
        rows.append(row)
    return rows

def main() -> None:
    st.set_page_config(page_title="ECDAT", layout="wide")
    st.markdown(theme_css("#d06a4f"), unsafe_allow_html=True)
    demo = ROOT / "data" / "sample" / "vulnerable_app"
    st.markdown('<div class="top"><div><div class="kicker">Cryptographic discovery</div><p class="title">ECDAT</p></div><div class="pill">Offline rules · local files</div></div>', unsafe_allow_html=True)
    path = st.sidebar.text_input("Scan path", value=str(demo))
    if st.sidebar.button("Scan", type="primary"):
        st.session_state["rows"] = _scan(path)
    rows = st.session_state.get("rows")
    if rows is None and demo.exists():
        rows = _scan(str(demo))
        st.session_state["rows"] = rows
    rows = rows or []
    if not rows:
        st.markdown('<div class="panel"><p class="muted">No findings yet. Point the scan at a source tree or generate the sample app.</p></div>', unsafe_allow_html=True)
        return
    df = pd.DataFrame(rows)
    counts = df["severity"].value_counts().to_dict() if "severity" in df else {}
    critical = int(counts.get("critical", 0) + counts.get("Severity.CRITICAL", 0))
    st.markdown(f'<div class="panel"><div class="kicker">Primary</div><p class="title">{critical} critical · {len(df)} findings</p><p class="muted">Highest severity first. Evidence stays on this machine.</p></div>', unsafe_allow_html=True)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    if "severity" in df:
        df = df.assign(_o=df["severity"].map(lambda s: order.get(str(s), 9))).sort_values("_o").drop(columns="_o")
    st.dataframe(df, width="stretch", hide_index=True)
    # rebuild objects only for inventory helpers via a fresh scan (cached in session)
    scanner = CryptoScanner()
    p = Path(path)
    findings = scanner.scan_file(p) if p.is_file() else scanner.scan_directory(p) if p.exists() else []
    pq = post_quantum_readiness(findings)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f'<div class="panel"><div class="kicker">Post-quantum readiness</div><p class="title">{pq.get("score")}</p><p class="muted">{pq.get("band")} · {pq.get("notes")}</p></div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(inventory_to_dict(build_inventory(findings))), width="stretch", hide_index=True)
    with c2:
        st.markdown('<div class="panel"><div class="kicker">TLS</div><p class="muted">Default probe is an offline demo result. Live TLS is optional.</p></div>', unsafe_allow_html=True)
        res = scan_tls_offline_demo()
        st.json({k: v for k, v in res.__dict__.items() if k != "findings"} if hasattr(res, "__dict__") else {})
        st.download_button("CBOM JSON", cbom_to_json(findings, project_name="ecdat"), file_name="cbom.json")
        st.download_button("TLS JSON", results_to_json([res]), file_name="tls.json")

if __name__ == "__main__":
    main()

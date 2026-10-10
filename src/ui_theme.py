"""CipherScope theme using the shared LinkLens visual language."""
from __future__ import annotations


def theme_css(
    accent: str = "#55c7d9",
    danger: str = "#e06b75",
    ok: str = "#6fbfa0",
    warn: str = "#e2b15a",
) -> str:
    return f"""
<style>
:root {{
  --cs-bg:#0b0d14; --cs-card:#141824; --cs-panel:#10131d;
  --cs-line:#282d40; --cs-text:#f4f5fb; --cs-muted:#9ba3bb;
  --cs-accent:{accent}; --cs-danger:{danger}; --cs-ok:{ok}; --cs-warn:{warn};
}}
html,body,[data-testid="stAppViewContainer"],.stApp {{
  background:var(--cs-bg); color:var(--cs-text);
  font-family:Inter,"Segoe UI",system-ui,sans-serif;
}}
[data-testid="stHeader"] {{ background:transparent; }}
#MainMenu,footer {{ visibility:hidden; }}
[data-testid="stSidebar"] {{ background:#10131d; border-right:1px solid var(--cs-line); }}
.block-container {{ max-width:1440px; padding-top:1.2rem; padding-bottom:3rem; }}
h1,h2,h3 {{ letter-spacing:-.035em; }}
.cs-topbar {{ display:flex; align-items:center; gap:14px; border:1px solid var(--cs-line);
  background:#10131d; border-radius:14px; padding:12px 16px; margin-bottom:16px; }}
.cs-brand {{ font-size:.8rem; font-weight:800; letter-spacing:.14em; color:var(--cs-accent); }}
.cs-topnote {{ color:var(--cs-muted); font-size:.78rem; }}
.cs-local {{ margin-left:auto; font-size:.72rem; letter-spacing:.1em; color:var(--cs-ok); }}
.cs-hero {{ padding:28px 30px; border:1px solid #2b4650; border-radius:20px;
  background:radial-gradient(circle at 92% 8%,#174252 0,transparent 34%),linear-gradient(135deg,#151f2c,#111521 72%);
  margin:4px 0 18px; }}
.cs-eyebrow {{ font-size:.72rem; letter-spacing:.16em; text-transform:uppercase;
  color:var(--cs-accent); font-weight:800; }}
.cs-hero h1 {{ font-size:2.35rem; margin:.4rem 0; line-height:1.1; }}
.cs-hero p {{ color:#c2c8da; font-size:1.02rem; max-width:820px; margin:.35rem 0 0; }}
.cs-chip {{ display:inline-block; padding:4px 9px; border-radius:999px; border:1px solid #35505c;
  font-size:.72rem; color:#bdebf1; margin:8px 6px 0 0; }}
.cs-card {{ background:var(--cs-card); border:1px solid var(--cs-line); border-radius:16px;
  padding:18px 20px; min-height:112px; }}
.cs-label {{ font-size:.72rem; color:var(--cs-muted); letter-spacing:.09em; text-transform:uppercase; }}
.cs-value {{ font-size:1.85rem; font-weight:750; margin:5px 0; line-height:1.15; }}
.cs-help {{ font-size:.82rem; color:var(--cs-muted); }}
.cs-section {{ border-bottom:1px solid var(--cs-line); padding-bottom:9px; margin:26px 0 14px; }}
.cs-note {{ border-left:3px solid var(--cs-accent); background:#101923; border-radius:8px;
  padding:10px 13px; margin:8px 0 14px; }}
.cs-note.warn {{ border-left-color:var(--cs-warn); }}
.cs-note.danger {{ border-left-color:var(--cs-danger); }}
.cs-badge {{ display:inline-block; padding:4px 9px; border-radius:999px; border:1px solid var(--cs-line);
  font-size:.72rem; color:var(--cs-muted); margin-right:5px; }}
.cs-muted {{ color:var(--cs-muted); font-size:.82rem; }}
.cs-flow {{ display:flex; flex-wrap:wrap; gap:8px; margin:12px 0 22px; }}
.cs-flow span {{ flex:1; min-width:110px; border:1px solid var(--cs-line); background:#111720;
  padding:12px; border-radius:12px; text-align:center; font-weight:650; }}
.cs-flow small {{ display:block; color:var(--cs-muted); font-weight:400; margin-top:4px; }}
div[data-testid="stDataFrame"],div[data-testid="stPlotlyChart"] {{ border:1px solid var(--cs-line); border-radius:14px; overflow:hidden; }}
.stButton>button,.stDownloadButton>button {{ border-radius:10px; border:1px solid #35505c; font-weight:650; min-height:2.55rem; }}
.stButton>button[kind="primary"] {{ background:var(--cs-accent); color:#071317; border-color:var(--cs-accent); }}
[data-testid="stMetric"] {{ background:var(--cs-card); border:1px solid var(--cs-line); border-radius:14px; padding:14px; }}
[data-testid="stAlert"] {{ border-radius:12px; }}
[data-testid="stFileUploader"] {{ border:1px dashed #49606d; border-radius:14px; padding:8px; }}
[data-testid="stExpander"] {{ border:1px solid var(--cs-line); border-radius:12px; }}
[data-testid="stRadio"] label {{ font-size:.9rem; }}
hr {{ border-color:var(--cs-line); }}
@media(max-width:760px) {{
  .block-container {{ padding:1rem .8rem 2rem; }}
  .cs-hero {{ padding:22px 18px; }}
  .cs-hero h1 {{ font-size:1.8rem; }}
  .cs-local {{ display:none; }}
}}
</style>
"""

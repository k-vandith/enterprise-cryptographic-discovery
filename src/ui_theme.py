"""Local visual system. No remote fonts."""

def theme_css(accent: str, danger: str = "#e06c75", ok: str = "#3dbe8b", warn: str = "#e0b15a") -> str:
    return f"""
<style>
:root {{
  --bg:#0e1116; --surface:#161b22; --text:#e7ecf3; --muted:#9aa6b2;
  --border:#2a3340; --accent:{accent}; --ok:{ok}; --warn:{warn}; --danger:{danger};
}}
html, body, .stApp {{ background:var(--bg); color:var(--text);
  font-family:"Segoe UI", ui-sans-serif, system-ui, sans-serif; }}
[data-testid="stHeader"] {{ background:transparent; }}
[data-testid="stSidebar"] {{ background:var(--surface); border-right:1px solid var(--border); }}
.block-container {{ padding-top:1.2rem; max-width:1100px; }}
.top {{ display:flex; justify-content:space-between; gap:12px; align-items:flex-end; margin-bottom:12px; }}
.kicker {{ color:var(--muted); letter-spacing:.12em; text-transform:uppercase; font-size:.75rem; }}
.title {{ font-size:1.55rem; font-weight:600; margin:0; }}
.pill {{ border:1px solid var(--border); border-radius:999px; padding:4px 10px; color:var(--muted); font-size:.78rem; }}
.panel {{ background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:14px 16px; margin-bottom:12px; }}
.muted {{ color:var(--muted); }}
</style>
"""

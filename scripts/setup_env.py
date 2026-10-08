#!/usr/bin/env python3
"""Cross-platform virtualenv bootstrap. Usage: python3 scripts/setup_env.py"""
from __future__ import annotations
import os, platform, shutil, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
REQ = ROOT / "requirements.txt"
IS_WIN = platform.system() == "Windows"
def _run(cmd, **kw):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, check=True, **kw)
def create_venv():
    if VENV.exists():
        print(f"[ok] Virtualenv already exists: {VENV}"); return
    print(f"[..] Creating virtualenv at {VENV}")
    last_err = None
    for cmd in [[sys.executable, "-m", "venv", str(VENV), "--copies"], [sys.executable, "-m", "venv", str(VENV)], [sys.executable, "-m", "venv", str(VENV), "--copies", "--without-pip"], [sys.executable, "-m", "venv", str(VENV), "--without-pip"]]:
        try:
            _run(cmd); print(f"[ok] Created with: {' '.join(cmd[3:])}"); return
        except (subprocess.CalledProcessError, OSError) as exc:
            last_err = exc
            if VENV.exists(): shutil.rmtree(VENV, ignore_errors=True)
            print(f"[warn] Strategy failed: {exc}")
    raise SystemExit(f"Could not create venv. Install python3-venv/python3-pip. Last error: {last_err}")
def venv_python():
    return VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")
def ensure_pip(py):
    try:
        _run([str(py), "-m", "pip", "--version"], capture_output=True); print("[ok] pip available"); return
    except Exception:
        pass
    print("[..] Bootstrapping pip …")
    try:
        _run([str(py), "-m", "ensurepip", "--upgrade"]); return
    except Exception:
        pass
    get_pip = ROOT / "scripts" / "_get_pip.py"
    try:
        import urllib.request
        urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", str(get_pip))
        _run([str(py), str(get_pip)])
    except Exception as exc:
        raise SystemExit(f"pip bootstrap failed: {exc}") from exc
    finally:
        if get_pip.exists(): get_pip.unlink(missing_ok=True)
def install_requirements(py):
    if not REQ.exists(): raise SystemExit(f"Missing {REQ}")
    print(f"[..] Installing from {REQ.name}")
    _run([str(py), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    _run([str(py), "-m", "pip", "install", "-r", str(REQ)])
    print("[ok] Dependencies installed")
def main():
    os.chdir(ROOT)
    print(f"Project root: {ROOT}\nPython: {sys.executable} ({sys.version.split()[0]})\nPlatform: {platform.system()} {platform.machine()}\n")
    create_venv()
    py = venv_python()
    if not py.exists(): raise SystemExit(f"Missing {py}")
    ensure_pip(py); install_requirements(py)
    print("\n" + "=" * 60)
    print("Setup complete. Activate:")
    print(r"  .venv\Scripts\Activate.ps1" if IS_WIN else "  source .venv/bin/activate")
    print("Then:  pytest -v")
    print("=" * 60)
if __name__ == "__main__":
    main()

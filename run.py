"""Launch the local UI. `python run.py`."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    # Scans may handle proprietary source and key material. Until an identity
    # layer exists, bind only to loopback and keep Streamlit's CSRF checks on.
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(ROOT / "src" / "app.py"),
        "--server.address",
        "127.0.0.1",
        "--server.port",
        "8501",
        "--server.headless",
        "true",
        "--server.enableCORS",
        "true",
        "--server.enableXsrfProtection",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]
    raise SystemExit(subprocess.call(cmd, cwd=ROOT))


if __name__ == "__main__":
    main()

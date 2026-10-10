"""Capture screenshots of the Streamlit workspace pages with a local headless browser.

Install the optional tooling first:
    python -m pip install playwright
    python -m playwright install chromium
Then run:
    python scripts/capture_screenshots.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8501"
PAGES = [
    ("Scan files", "02-scan-files.png"),
    ("TLS & certificates", "03-tls-certificates.png"),
    ("Findings", "04-findings.png"),
    ("Inventory & PQC", "05-inventory-pqc.png"),
    ("Reports", "06-reports.png"),
    ("Glossary", "07-glossary.png"),
]


def wait_for_server(process: subprocess.Popen[bytes], timeout: float = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Streamlit exited before the local page became ready. Run python run.py to inspect its startup message.")
        try:
            with urlopen(BASE_URL + "/_stcore/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError, OSError):
            time.sleep(0.4)
    raise RuntimeError("CipherScope did not start in time. Check whether port 8501 is already in use.")


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed. Run: python -m pip install playwright")
        return 2

    output_dir = ROOT / "docs" / "screenshots"
    output_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.setdefault("STREAMLIT_BROWSER_GATHER_USAGE_STATS", "false")
    env.setdefault("STREAMLIT_SERVER_HEADLESS", "true")
    process = subprocess.Popen(
        [
            sys.executable, "-m", "streamlit", "run", str(ROOT / "src" / "app.py"),
            "--server.port", "8501", "--server.headless", "true",
        ],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_server(process)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1050}, device_scale_factor=1)
            page.goto(BASE_URL, wait_until="domcontentloaded", timeout=45_000)
            page.locator("[data-testid='stAppViewContainer']").wait_for(timeout=30_000)
            page.wait_for_timeout(1500)
            page.screenshot(path=str(output_dir / "01-overview.png"), full_page=True)

            sample_button = page.get_by_role("button", name="Load sample case")
            if sample_button.count():
                sample_button.first.click()
                page.wait_for_timeout(1600)
            page.screenshot(path=str(output_dir / "01b-overview-sample.png"), full_page=True)

            for page_name, filename in PAGES:
                radio = page.get_by_role("radio", name=page_name)
                if not radio.count():
                    raise RuntimeError(f"Could not find sidebar navigation item {page_name!r}.")
                radio.first.click()
                page.wait_for_timeout(1200)
                if page_name == "TLS & certificates":
                    demo_button = page.get_by_role("button", name="Load offline TLS example")
                    if demo_button.count():
                        demo_button.click()
                        page.wait_for_timeout(900)
                page.screenshot(path=str(output_dir / filename), full_page=True)
                print(f"Saved {output_dir / filename}")
            browser.close()
    except Exception as exc:
        print(f"Screenshot capture failed: {exc}")
        return 1
    finally:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
    print(f"Saved local walkthrough screenshots to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

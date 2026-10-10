"""Streamlit AppTest smoke coverage for every first-level workspace page."""
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest


APP_FILE = Path(__file__).resolve().parents[1] / "src" / "app.py"
PAGES = [
    "Overview",
    "Scan files",
    "TLS & certificates",
    "Findings",
    "Inventory & PQC",
    "Reports",
    "Glossary",
]


@pytest.mark.parametrize("page", PAGES)
def test_ui_page_smoke(page: str) -> None:
    app = AppTest.from_file(str(APP_FILE), default_timeout=30)
    app.session_state["navigation"] = page
    app.run()
    assert not app.exception, "\\n".join(str(item.message) for item in app.exception)

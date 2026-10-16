import os
from datetime import date

import pytest

# Tests never reach the Palo Alto Networks advisory feed; tests that need advisories set them directly.
os.environ.setdefault("PAN_ADVISORY_FEED", "off")


@pytest.fixture(autouse=True)
def _no_sign_in(monkeypatch):
    """Tests run without sign-in unless they turn it on (test_auth.py), whatever the shell has set."""
    monkeypatch.delenv("BASIC_AUTH_HASH", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)


@pytest.fixture(autouse=True)
def _pin_lifecycle_date(monkeypatch):
    """End-of-life findings depend on today's date; pin it so results don't change as time passes."""
    from app.rules import pan_os_lifecycle
    monkeypatch.setattr(pan_os_lifecycle, "today", lambda: date(2026, 10, 14))

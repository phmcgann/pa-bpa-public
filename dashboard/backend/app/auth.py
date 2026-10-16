"""Signing in to the dashboard.

The username and bcrypt password hash are the ones the installer writes to .env
(BASIC_AUTH_USER, BASIC_AUTH_HASH). Signing in sets a signed, HttpOnly session cookie that every
/api request must carry. The cookie's key is derived from the password hash, so changing the
password signs everyone out.

Sign-in is on whenever BASIC_AUTH_HASH is set. The Docker Compose files require it, so a deployed
dashboard always has it; a development server started without it has no sign-in (and says so).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time

import bcrypt

COOKIE = "pa_bpa_session"
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 15 * 60

_lock = threading.Lock()
_failures: dict[str, list[float]] = {}


def _hash() -> str:
    return (os.environ.get("BASIC_AUTH_HASH") or "").strip()


def enabled() -> bool:
    return bool(_hash())


def username() -> str:
    return (os.environ.get("BASIC_AUTH_USER") or "admin").strip()


def session_hours() -> float:
    try:
        return max(0.25, float(os.environ.get("SESSION_HOURS") or 12))
    except ValueError:
        return 12.0


def _key() -> bytes:
    secret = os.environ.get("SESSION_SECRET") or _hash()
    return hashlib.sha256(b"pa-bpa session v1\0" + secret.encode()).digest()


def _sign(user: str, expires: int) -> str:
    return hmac.new(_key(), f"{user}\0{expires}".encode(), hashlib.sha256).hexdigest()


def make_session(user: str, now: float | None = None) -> tuple[str, int]:
    """The cookie value and its lifetime in seconds."""
    max_age = int(session_hours() * 3600)
    expires = int(now if now is not None else time.time()) + max_age
    name = base64.urlsafe_b64encode(user.encode()).decode().rstrip("=")
    return f"v1.{name}.{expires}.{_sign(user, expires)}", max_age


def session_user(cookie: str | None, now: float | None = None) -> str | None:
    """The signed-in user, or None if the cookie is missing, tampered with, expired or from an old password."""
    if not cookie:
        return None
    try:
        version, name, expires_s, sig = cookie.split(".")
        user = base64.urlsafe_b64decode(name + "=" * (-len(name) % 4)).decode()
        expires = int(expires_s)
    except (ValueError, UnicodeDecodeError):
        return None
    if version != "v1" or not hmac.compare_digest(sig, _sign(user, expires)):
        return None
    if expires < (now if now is not None else time.time()) or user != username():
        return None
    return user


def check_password(user: str, password: str) -> bool:
    ok_user = hmac.compare_digest(user.strip().encode(), username().encode())
    try:
        ok_password = bcrypt.checkpw(password.encode(), _hash().encode())
    except ValueError:  # not a bcrypt hash: nothing can match it
        ok_password = False
    return ok_user and ok_password


def blocked_for(client: str, now: float | None = None) -> int:
    """Seconds until `client` may try again after too many wrong passwords (0 = not blocked)."""
    now = now if now is not None else time.time()
    with _lock:
        recent = [t for t in _failures.get(client, []) if now - t < FAILURE_WINDOW_SECONDS]
        _failures[client] = recent
        if len(recent) < MAX_FAILURES:
            return 0
        return int(FAILURE_WINDOW_SECONDS - (now - recent[0])) + 1


def record_failure(client: str, now: float | None = None) -> None:
    with _lock:
        _failures.setdefault(client, []).append(now if now is not None else time.time())


def clear_failures(client: str) -> None:
    with _lock:
        _failures.pop(client, None)


def reset_for_tests() -> None:
    with _lock:
        _failures.clear()

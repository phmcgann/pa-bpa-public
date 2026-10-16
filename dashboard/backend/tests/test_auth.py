"""Signing in: a session cookie instead of the browser's Basic Auth box."""
import importlib
import os

import bcrypt
import pytest

from app import auth

PASSWORD = "Correct-Horse-9"
HASH = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4, prefix=b"2a")).decode()  # same format as Caddy's


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("BASIC_AUTH_USER", "admin")
    monkeypatch.setenv("BASIC_AUTH_HASH", HASH)
    auth.reset_for_tests()
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app, base_url="https://testserver") as c:
        yield c


def _login(client, password=PASSWORD, user="admin"):
    return client.post("/api/auth/login", json={"username": user, "password": password})


def test_api_needs_a_session(client):
    assert client.get("/api/assessments").status_code == 401
    assert client.get("/api/auth/session").json() == {"enabled": True, "authenticated": False, "user": None}
    assert client.get("/health").status_code == 200  # the container health check stays open


def test_sign_in_then_out(client):
    r = _login(client)
    assert r.status_code == 200 and r.json() == {"user": "admin"}
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Secure" in cookie
    assert client.get("/api/assessments").status_code == 200
    assert client.get("/api/auth/session").json()["authenticated"] is True
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/assessments").status_code == 401


def test_wrong_password_or_user(client):
    assert _login(client, "nope").status_code == 401
    assert _login(client, user="root").status_code == 401
    assert client.get("/api/assessments").status_code == 401


def test_too_many_wrong_passwords_locks_out_for_a_while(client):
    for _ in range(auth.MAX_FAILURES):
        assert _login(client, "nope").status_code == 401
    r = _login(client)  # even the right password waits
    assert r.status_code == 429 and "Try again in" in r.json()["detail"]


def test_cookie_over_plain_http_is_not_secure(client):
    r = client.post("http://testserver/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert r.status_code == 200 and "Secure" not in r.headers["set-cookie"]


def test_sessions_expire_and_reject_tampering(monkeypatch):
    monkeypatch.setenv("BASIC_AUTH_HASH", HASH)
    value, max_age = auth.make_session("admin", now=1_000_000)
    assert auth.session_user(value, now=1_000_000 + max_age - 1) == "admin"
    assert auth.session_user(value, now=1_000_000 + max_age + 1) is None
    assert auth.session_user(value[:-1] + ("0" if value[-1] != "0" else "1"), now=1_000_000) is None
    assert auth.session_user("garbage", now=1_000_000) is None
    # A new password signs everyone out.
    monkeypatch.setenv("BASIC_AUTH_HASH", bcrypt.hashpw(b"other", bcrypt.gensalt(rounds=4)).decode())
    assert auth.session_user(value, now=1_000_000) is None


def test_without_a_password_hash_there_is_no_sign_in(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.delenv("BASIC_AUTH_HASH", raising=False)
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        assert c.get("/api/assessments").status_code == 200
        assert c.get("/api/auth/session").json() == {"enabled": False, "authenticated": True, "user": None}


def test_a_value_that_is_not_bcrypt_never_matches(monkeypatch):
    monkeypatch.setenv("BASIC_AUTH_HASH", "changeme")
    assert auth.check_password("admin", "changeme") is False

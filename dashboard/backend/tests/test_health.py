"""The health check reports the running release, so installers and admins can tell which one is live."""
import importlib

import pytest


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


def test_health_reports_dev_without_a_release_version(client, monkeypatch):
    monkeypatch.delenv("PA_BPA_VERSION", raising=False)
    assert client.get("/health").json() == {"status": "ok", "version": "dev"}


def test_health_reports_the_release_version(client, monkeypatch):
    monkeypatch.setenv("PA_BPA_VERSION", "v1.2.0")
    assert client.get("/health").json() == {"status": "ok", "version": "v1.2.0"}

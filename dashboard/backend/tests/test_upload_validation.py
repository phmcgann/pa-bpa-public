"""Uploads must be PAN-OS configuration exports; other XML is rejected before anything is stored."""
import importlib
import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


def _post(client, name, body: bytes):
    return client.post("/api/assessments/upload", files={"file": (name, body)})


@pytest.mark.parametrize("body, expect", [
    (b"<nope/>", "starts with <nope>"),
    (b"<?xml version='1.0'?><html><body>hi</body></html>", "starts with <html>"),
    (b"<config version='11.1.0'><unrelated/></config>", "none of the sections"),
    (b"<config/>", "none of the sections"),
    (b"<response status='success'><result><config><devices/></config></result></response>", "XML API response"),
])
def test_non_pan_os_xml_is_rejected(client, body, expect):
    resp = _post(client, "notes.xml", body)
    assert resp.status_code == 400
    assert expect in resp.json()["detail"]
    assert "Export named configuration snapshot" in resp.json()["detail"]
    assert client.get("/api/assessments").json() == []


def test_malformed_xml_still_reports_the_parse_error(client):
    resp = _post(client, "broken.xml", b"<config><devices>")
    assert resp.status_code == 400
    assert resp.json()["detail"].startswith("Could not parse XML")


@pytest.mark.parametrize("name", [
    "sample_config.xml", "security_profile_settings.xml", "network_decryption_settings.xml",
    "panorama_managed_config.xml",
])
def test_real_config_exports_are_accepted(client, name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        resp = _post(client, name, f.read())
    assert resp.status_code == 200, resp.text
    assert "id" in resp.json()


def test_panorama_export_still_goes_to_the_device_group_picker(client):
    with open(os.path.join(FIXTURES, "panorama_export_config.xml"), "rb") as f:
        resp = _post(client, "panorama_export_config.xml", f.read())
    assert resp.status_code == 200, resp.text
    assert resp.json()["panorama_export"] is True


def test_minimal_config_with_one_known_section_is_accepted():
    import xml.etree.ElementTree as ET
    from app.parser import config_rejection
    for section in ("devices", "shared", "mgt-config"):
        assert config_rejection(ET.fromstring(f"<config><{section}/></config>")) is None

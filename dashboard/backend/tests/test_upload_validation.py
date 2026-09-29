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


def test_panorama_managed_firewall_is_offered_no_cli_commands(client):
    with open(os.path.join(FIXTURES, "panorama_managed_config.xml"), "rb") as fh:
        up = _post(client, "managed.xml", fh.read())
    assert up.status_code == 200, up.text
    body = client.get(f"/api/assessments/{up.json()['id']}").json()
    assert body["data"]["panorama_managed"] is True
    assert "Panorama" in body["cli_unavailable"]
    assert all(f["cli"] is None for f in body["findings"])


def test_standalone_firewall_keeps_cli_commands(client):
    with open(os.path.join(FIXTURES, "sample_config.xml"), "rb") as fh:
        up = _post(client, "fw.xml", fh.read())
    body = client.get(f"/api/assessments/{up.json()['id']}").json()
    assert body["cli_unavailable"] is None
    assert any(f["cli"] for f in body["findings"])


# ── Panorama's own tech support file ─────────────────────────────────────

def _panorama_tsf() -> bytes:
    """A tech support file shaped like Panorama's: its running config is a Panorama export."""
    import io
    import tarfile
    with open(os.path.join(FIXTURES, "panorama_export_config.xml"), "rb") as fh:
        config = fh.read()
    cli_text = b"> show system info\n\nhostname: pano-01\nmodel: Panorama\nsw-version: 12.1.8\nserial: 000000000001\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, body in (("opt/pancfg/mgmt/saved-configs/running-config.xml", config),
                           ("x/tmp/cli/techsupport_pano_01.txt", cli_text)):
            info = tarfile.TarInfo(name=name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def test_panorama_tech_support_file_goes_to_the_device_group_picker(client):
    resp = client.post("/api/assessments/upload", files={"file": ("pano_techsupport.tgz", _panorama_tsf())})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["panorama_export"] is True
    group = body["device_groups"][0]["name"]
    made = client.post("/api/assessments/from-panorama", json={"upload_id": body["upload_id"], "device_group": group})
    assert made.status_code == 200, made.text
    detail = client.get(f"/api/assessments/{made.json()['id']}").json()
    assert detail["source"] == "panorama_export" and detail["panorama_appliance"] is False
    assert detail["cli_unavailable"] is None


def test_older_panorama_tech_support_upload_asks_for_a_reupload(client):
    """Before the fix, Panorama's tech support file was parsed as one device, mixing every device group."""
    import gzip
    from sqlmodel import Session
    from app import db, main, models, tsf_parser
    with open(os.path.join(FIXTURES, "panorama_export_config.xml"), "rb") as fh:
        config = fh.read()
    cli_text = "> show system info\n\nhostname: pano-01\nmodel: Panorama\n"
    data = tsf_parser.build_assessment_data_from_parts(config, cli_text)
    data.pop("panorama_appliance", None)  # as stored by older versions
    with Session(db.engine) as s:
        a = models.Assessment(filename="old.tgz", hostname="pano-01", source="tsf_upload", parsed_data=data)
        s.add(a)
        s.commit()
        s.refresh(a)
        s.add(models.AssessmentConfig(assessment_id=a.id, platform="ngfw", config_gz=gzip.compress(config),
                                      cli_text_gz=gzip.compress(cli_text.encode())))
        s.commit()
        aid = a.id
    detail = client.get(f"/api/assessments/{aid}").json()
    assert detail["panorama_appliance"] is True
    assert "Panorama's own tech support file" in detail["cli_unavailable"]
    assert all(f["cli"] is None for f in detail["findings"])
    listed = next(x for x in client.get("/api/assessments").json() if x["id"] == aid)
    assert listed["panorama_managed"] is False
    again = client.post(f"/api/assessments/{aid}/reanalyze")
    assert again.status_code == 400 and "Upload it again" in again.json()["detail"]

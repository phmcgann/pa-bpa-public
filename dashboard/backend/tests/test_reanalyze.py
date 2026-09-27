"""Re-analyzing an assessment from its stored source, without uploading the file again."""
import importlib
import os

import pytest
from sqlmodel import Session

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


def _upload(client, name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        resp = client.post("/api/assessments/upload", files={"file": (name, f.read())})
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _edit(aid, fn):
    """Changes the stored row directly, as an older app version would have left it."""
    from app import db
    from app.models import Assessment, AssessmentConfig
    with Session(db.engine) as s:
        fn(s, s.get(Assessment, aid), s.get(AssessmentConfig, aid))
        s.commit()


def _stale(s, a, cfg):
    # A section a newer parser reads, missing because the file was parsed by an older one.
    a.parsed_data = {k: v for k, v in a.parsed_data.items() if k != "nat_rules"}
    s.add(a)


def test_reanalyze_reparses_in_place_and_keeps_dismissals_and_notes(client):
    aid = _upload(client, "sample_config.xml")
    detail = client.get(f"/api/assessments/{aid}").json()
    key = detail["findings"][0]["finding_key"]
    client.post(f"/api/assessments/{aid}/findings/{key}/dismiss", json={})
    client.post(f"/api/assessments/{aid}/notes",
                json={"target_kind": "finding", "target_key": key, "target_label": "x", "body": "Keep me"})
    _edit(aid, _stale)
    assert "nat_rules" not in client.get(f"/api/assessments/{aid}").json()["data"]

    resp = client.post(f"/api/assessments/{aid}/reanalyze")
    assert resp.status_code == 200
    assert resp.json()["full_source"] is True and set(resp.json()["after"]) == {"score", "total"}

    after = client.get(f"/api/assessments/{aid}").json()
    assert "nat_rules" in after["data"] and after["reanalyzed_at"]
    assert after["uploaded_at"] == detail["uploaded_at"]
    assert next(f for f in after["findings"] if f["finding_key"] == key)["dismissed"]
    assert [n["body"] for n in after["notes"]] == ["Keep me"]
    assert len(client.get("/api/assessments").json()) == 1  # no new run


def test_reanalyze_tech_support_file_keeps_cli_data(client):
    aid = _upload(client, "sample_techsupport.tgz")
    before = client.get(f"/api/assessments/{aid}").json()["data"]
    assert client.post(f"/api/assessments/{aid}/reanalyze").json()["full_source"] is True
    after = client.get(f"/api/assessments/{aid}").json()["data"]
    for k in ("system_info", "licenses", "ha"):
        assert after[k] == before[k]


def test_older_tech_support_upload_keeps_its_cli_data(client):
    aid = _upload(client, "sample_techsupport.tgz")
    before = client.get(f"/api/assessments/{aid}").json()["data"]

    def forget_cli(s, a, cfg):
        cfg.cli_text_gz = None
        s.add(cfg)
    _edit(aid, forget_cli)
    assert client.post(f"/api/assessments/{aid}/reanalyze").json()["full_source"] is False
    after = client.get(f"/api/assessments/{aid}").json()["data"]
    assert after["system_info"] == before["system_info"] and after["licenses"] == before["licenses"]


def test_reanalyze_needs_the_stored_file(client):
    aid = _upload(client, "sample_config.xml")

    def drop_config(s, a, cfg):
        s.delete(cfg)
    _edit(aid, drop_config)
    resp = client.post(f"/api/assessments/{aid}/reanalyze")
    assert resp.status_code == 409 and "upload the file again" in resp.json()["detail"]
    assert client.post("/api/assessments/9999/reanalyze").status_code == 404


def test_reanalyze_panorama_device_group(client):
    with open(os.path.join(FIXTURES, "panorama_export_config.xml"), "rb") as f:
        staged = client.post("/api/assessments/upload", files={"file": ("pano.xml", f.read())}).json()
    group = staged["device_groups"][0]
    group = group["name"] if isinstance(group, dict) else group
    aid = client.post("/api/assessments/from-panorama",
                      json={"upload_id": staged["upload_id"], "device_group": group}).json()["id"]
    before = client.get(f"/api/assessments/{aid}").json()
    _edit(aid, _stale)
    assert client.post(f"/api/assessments/{aid}/reanalyze").status_code == 200
    after = client.get(f"/api/assessments/{aid}").json()
    assert after["data"]["device_group"] == group
    assert after["data"]["security_rules"] == before["data"]["security_rules"]
    assert "nat_rules" in after["data"]

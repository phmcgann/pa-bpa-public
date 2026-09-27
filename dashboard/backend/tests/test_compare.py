"""Comparing two assessments: new / resolved / changed findings, per-rule point changes, and notes."""
import json
import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    import importlib
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


def _upload(client, name: str, body: bytes | None = None) -> int:
    data = body if body is not None else open(os.path.join(FIXTURES, name), "rb").read()
    r = client.post("/api/assessments/upload", files={"file": (name, data, "text/xml")})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_compare_same_config_is_empty(client):
    a = _upload(client, "vpn_hardened.xml")
    b = _upload(client, "vpn_hardened.xml")
    r = client.get(f"/api/compare?base={a}&target={b}").json()
    assert r["score_delta"] == 0 and r["new"] == [] and r["resolved"] == [] and r["changed"] == [] and r["by_rule"] == []
    assert r["notes"] == []


def test_compare_explains_the_score_change(client):
    hardened = open(os.path.join(FIXTURES, "vpn_hardened.xml"), "rb").read()
    weak = hardened.replace(b"<version>ikev2</version>", b"<version>ikev1</version>") \
                   .replace(b"<member>aes-256-gcm</member></encryption>\n                <hash>",
                            b"<member>3des</member></encryption>\n                <hash>")
    a = _upload(client, "vpn_hardened.xml", hardened)
    b = _upload(client, "vpn_hardened.xml", weak)
    r = client.get(f"/api/compare?base={a}&target={b}").json()
    new = {f["rule_id"] for f in r["new"]}
    assert {"ike_v1_only", "vpn_weak_encryption"} <= new
    assert r["resolved"] == []
    delta = sum(x["target_points"] - x["base_points"] for x in r["by_rule"])
    assert delta == r["score_delta"] == r["target"]["summary"]["score"] - r["base"]["summary"]["score"] > 0
    assert r["by_rule"][0]["target_points"] - r["by_rule"][0]["base_points"] == max(
        abs(x["target_points"] - x["base_points"]) for x in r["by_rule"])

    # The reverse direction lists them as resolved.
    back = client.get(f"/api/compare?base={b}&target={a}").json()
    assert {f["rule_id"] for f in back["resolved"]} == new and back["score_delta"] == -r["score_delta"]


def test_dismissal_shows_as_changed(client):
    a = _upload(client, "vpn_hardened.xml")
    hardened = open(os.path.join(FIXTURES, "vpn_hardened.xml"), "rb").read()
    b = _upload(client, "vpn_hardened.xml", hardened.replace(b"<version>ikev2</version>", b"<version>ikev1</version>"))
    c = _upload(client, "vpn_hardened.xml", hardened.replace(b"<version>ikev2</version>", b"<version>ikev1</version>"))
    key = next(f["finding_key"] for f in client.get(f"/api/assessments/{c}").json()["findings"] if f["rule_id"] == "ike_v1_only")
    assert client.post(f"/api/assessments/{c}/findings/{key}/dismiss", json={}).status_code == 200
    r = client.get(f"/api/compare?base={b}&target={c}").json()
    change = next(x for x in r["changed"] if x["finding"]["finding_key"] == key)
    assert change["before"]["counted"] and not change["after"]["counted"] and change["after"]["dismissed"]
    assert a  # first upload only exercises the identity path


def test_notes_flag_different_firewalls(client):
    a = _upload(client, "vpn_hardened.xml")
    b = _upload(client, "ha_hardened.xml")
    notes = [n["kind"] for n in client.get(f"/api/compare?base={a}&target={b}").json()["notes"]]
    assert "different_firewall" in notes


def test_notes_flag_sections_missing_from_an_older_upload(client):
    from app import db
    from app.models import Assessment
    from sqlmodel import Session
    a = _upload(client, "vpn_hardened.xml")
    b = _upload(client, "vpn_hardened.xml")
    with Session(db.engine) as s:
        old = s.get(Assessment, a)
        data = dict(old.parsed_data)
        data.pop("vpn")
        old.parsed_data = data
        s.add(old)
        s.commit()
    notes = client.get(f"/api/compare?base={a}&target={b}").json()["notes"]
    cov = [n for n in notes if n["kind"] == "parser_coverage"]
    assert len(cov) == 1 and "site-to-site VPN" in cov[0]["text"] and "earlier" in cov[0]["text"]


def test_unknown_assessment_is_404(client):
    a = _upload(client, "vpn_hardened.xml")
    assert client.get(f"/api/compare?base={a}&target=99999").status_code == 404


def test_assessment_names_its_previous_run(client):
    a = _upload(client, "vpn_hardened.xml")
    other = _upload(client, "ha_hardened.xml")
    b = _upload(client, "vpn_hardened.xml")
    assert client.get(f"/api/assessments/{a}").json()["previous_run"] is None
    assert client.get(f"/api/assessments/{b}").json()["previous_run"]["id"] == a
    assert client.get(f"/api/assessments/{other}").json()["previous_run"] is None

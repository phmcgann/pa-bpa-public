"""Analyst notes on findings and other entries, numbered as endnotes in the report."""
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


@pytest.fixture
def aid(client):
    with open(os.path.join(FIXTURES, "sample_config.xml"), "rb") as f:
        resp = client.post("/api/assessments/upload", files={"file": ("sample_config.xml", f.read())})
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _note(kind, key, body, label="Some finding"):
    return {"target_kind": kind, "target_key": key, "target_label": label, "body": body}


def test_notes_are_numbered_in_order_added_and_returned_with_the_assessment(client, aid):
    client.post(f"/api/assessments/{aid}/notes", json=_note("finding", "rule_a:x/y", "First"))
    notes = client.post(f"/api/assessments/{aid}/notes", json=_note("remediation", "upgrade", "Second")).json()
    assert [(n["number"], n["target_key"], n["body"]) for n in notes] == [
        (1, "rule_a:x/y", "First"), (2, "upgrade", "Second")]
    assert client.get(f"/api/assessments/{aid}").json()["notes"] == notes
    assert notes[0]["created_at"] == notes[0]["updated_at"]  # not shown as edited


def test_one_note_per_entry_posting_again_replaces_it(client, aid):
    client.post(f"/api/assessments/{aid}/notes", json=_note("finding", "k", "Old"))
    notes = client.post(f"/api/assessments/{aid}/notes", json=_note("finding", "k", "  New text \n")).json()
    assert [(n["number"], n["body"]) for n in notes] == [(1, "New text")]


def test_edit_and_delete_renumber(client, aid):
    for key in ("a", "b", "c"):
        notes = client.post(f"/api/assessments/{aid}/notes", json=_note("finding", key, key.upper())).json()
    notes = client.patch(f"/api/assessments/{aid}/notes/{notes[2]['id']}", json={"body": "C2"}).json()
    assert notes[2]["body"] == "C2"
    notes = client.delete(f"/api/assessments/{aid}/notes/{notes[0]['id']}").json()
    assert [(n["number"], n["target_key"]) for n in notes] == [(1, "b"), (2, "c")]


def test_rejects_bad_input(client, aid):
    assert client.post(f"/api/assessments/{aid}/notes", json=_note("finding", "k", "   ")).status_code == 422
    assert client.post(f"/api/assessments/{aid}/notes", json=_note("bogus", "k", "x")).status_code == 422
    assert client.post("/api/assessments/9999/notes", json=_note("finding", "k", "x")).status_code == 404
    assert client.patch(f"/api/assessments/{aid}/notes/9999", json={"body": "x"}).status_code == 404


def test_deleting_the_assessment_deletes_its_notes(client, aid):
    client.post(f"/api/assessments/{aid}/notes", json=_note("finding", "k", "x"))
    assert client.delete(f"/api/assessments/{aid}").status_code in (200, 204)
    from sqlmodel import Session, select
    from app import db
    from app.models import AssessmentNote
    with Session(db.engine) as s:
        assert s.exec(select(AssessmentNote)).all() == []


def _upload(client):
    with open(os.path.join(FIXTURES, "sample_config.xml"), "rb") as f:
        return client.post("/api/assessments/upload", files={"file": ("sample_config.xml", f.read())}).json()["id"]


def test_notes_carry_over_to_the_next_run_when_the_entry_still_exists(client, aid):
    finding_key = client.get(f"/api/assessments/{aid}").json()["findings"][0]["finding_key"]
    rule = client.get(f"/api/assessments/{aid}").json()["data"]["security_rules"][0]
    client.post(f"/api/assessments/{aid}/notes", json=_note("finding", finding_key, "Risk accepted"))
    client.post(f"/api/assessments/{aid}/notes", json=_note("finding", "gone_rule:fixed", "Was fixed"))
    client.post(f"/api/assessments/{aid}/notes",
                json=_note("security_rule", f"{rule.get('rule_scope') or ''}:{rule['name']}", "Owner: app team"))

    second = _upload(client)
    notes = client.get(f"/api/assessments/{second}").json()["notes"]
    assert [(n["number"], n["body"]) for n in notes] == [(1, "Risk accepted"), (2, "Owner: app team")]
    assert all(n["carried_from"]["id"] == aid for n in notes)
    assert notes[0]["created_at"] == notes[0]["updated_at"]

    # Carried notes are independent copies, and a third run still credits the run they were written on.
    client.patch(f"/api/assessments/{second}/notes/{notes[0]['id']}", json={"body": "Risk accepted until Q3"})
    assert client.get(f"/api/assessments/{aid}").json()["notes"][0]["body"] == "Risk accepted"
    third = _upload(client)
    notes3 = client.get(f"/api/assessments/{third}").json()["notes"]
    assert notes3[0]["body"] == "Risk accepted until Q3" and notes3[0]["carried_from"]["id"] == aid

import importlib
import os

import pytest
from sqlalchemy import create_engine, text

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


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
    resp = client.post("/api/assessments/upload", files={"file": (name, _fixture(name))})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_tsf_upload_carries_serial_and_model(client):
    body = _upload(client, "sample_techsupport.tgz")
    assert body["serial"] and body["model"]
    assert body["client_name"] is None
    listed = client.get("/api/assessments").json()[0]
    assert (listed["serial"], listed["model"]) == (body["serial"], body["model"])


def test_config_export_has_no_serial_but_one_can_be_entered(client):
    aid = _upload(client, "sample_config.xml")["id"]
    detail = client.get(f"/api/assessments/{aid}").json()
    assert detail["serial"] is None and detail["model"] is None
    resp = client.patch(f"/api/assessments/{aid}", json={"serial": "  0123456789  "})
    assert resp.json()["serial"] == "0123456789"


def test_client_name_set_changed_and_cleared(client):
    aid = _upload(client, "sample_config.xml")["id"]
    assert client.patch(f"/api/assessments/{aid}", json={"client_name": "Acme Corp"}).json()["client_name"] == "Acme Corp"
    # Changing one field leaves the other alone
    client.patch(f"/api/assessments/{aid}", json={"serial": "X1"})
    assert client.get(f"/api/assessments/{aid}").json()["client_name"] == "Acme Corp"
    assert client.patch(f"/api/assessments/{aid}", json={"client_name": ""}).json()["client_name"] is None
    assert client.patch("/api/assessments/9999", json={"client_name": "x"}).status_code == 404
    assert client.patch(f"/api/assessments/{aid}", json={"client_name": "x" * 201}).status_code == 400


def test_client_list_counts_and_sorts(client):
    ids = [_upload(client, "sample_config.xml")["id"] for _ in range(3)]
    client.patch(f"/api/assessments/{ids[0]}", json={"client_name": "beta LLC"})
    client.patch(f"/api/assessments/{ids[1]}", json={"client_name": "Acme Corp"})
    client.patch(f"/api/assessments/{ids[2]}", json={"client_name": "Acme Corp"})
    assert client.get("/api/clients").json() == [
        {"name": "Acme Corp", "assessments": 2}, {"name": "beta LLC", "assessments": 1},
    ]


def test_new_upload_of_same_serial_inherits_client(client):
    first = _upload(client, "sample_techsupport.tgz")
    client.patch(f"/api/assessments/{first['id']}", json={"client_name": "Acme Corp"})
    second = _upload(client, "sample_techsupport.tgz")
    assert second["client_name"] == "Acme Corp"
    # No serial in a plain config export -> nothing to match on
    assert _upload(client, "sample_config.xml")["client_name"] is None


def test_setting_a_client_covers_the_firewalls_other_unassigned_runs(client):
    a = _upload(client, "sample_techsupport.tgz")["id"]
    b = _upload(client, "sample_techsupport.tgz")["id"]
    c = _upload(client, "sample_techsupport.tgz")["id"]
    other = _upload(client, "sample_config.xml")["id"]

    assert client.patch(f"/api/assessments/{a}", json={"client_name": "Acme Corp"}).json()["also_applied"] == 2
    names = {x["id"]: x["client_name"] for x in client.get("/api/assessments").json()}
    assert (names[a], names[b], names[c], names[other]) == ("Acme Corp", "Acme Corp", "Acme Corp", None)

    # Only unassigned runs are filled in: runs that already have a client keep it
    client.patch(f"/api/assessments/{c}", json={"client_name": ""})
    assert client.patch(f"/api/assessments/{b}", json={"client_name": "Globex"}).json()["also_applied"] == 1
    names = {x["id"]: x["client_name"] for x in client.get("/api/assessments").json()}
    assert (names[a], names[b], names[c]) == ("Acme Corp", "Globex", "Globex")


def test_existing_database_gets_the_new_columns(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'old.db'}"
    old = create_engine(url)
    with old.begin() as conn:
        conn.execute(text(
            "CREATE TABLE assessment (id INTEGER PRIMARY KEY, filename VARCHAR, hostname VARCHAR, "
            "source VARCHAR, uploaded_at DATETIME, parsed_data JSON)"
        ))
        conn.execute(text(
            "INSERT INTO assessment VALUES (1, 'old.tgz', 'fw1', 'tsf_upload', '2026-01-01 00:00:00', "
            "'{\"system_info\": {\"serial\": \"0001\", \"model\": \"PA-440\"}}')"
        ))
    old.dispose()
    monkeypatch.setenv("DATABASE_URL", url)
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        row = c.get("/api/assessments").json()[0]
    # Serial/model fall back to the parsed data for rows saved before the columns existed
    assert (row["serial"], row["model"], row["client_name"]) == ("0001", "PA-440", None)


def _set_serial_column_null(assessment_id: int):
    """Make a row look like it was saved before the serial column existed."""
    from app import db
    with db.engine.begin() as conn:
        conn.execute(text("UPDATE assessment SET serial = NULL WHERE id = :id"), {"id": assessment_id})


def test_run_saved_before_the_serial_column_still_passes_its_client_on(client):
    first = _upload(client, "sample_techsupport.tgz")
    client.patch(f"/api/assessments/{first['id']}", json={"client_name": "Acme Corp"})
    _set_serial_column_null(first["id"])
    assert _upload(client, "sample_techsupport.tgz")["client_name"] == "Acme Corp"


def test_config_export_without_serial_inherits_by_hostname(client):
    first = _upload(client, "sample_config.xml")                        # hostname fw01, no serial
    client.patch(f"/api/assessments/{first['id']}", json={"client_name": "Acme Corp", "serial": "012801000123"})
    second = _upload(client, "sample_config.xml")
    assert (second["client_name"], second["serial"]) == ("Acme Corp", "012801000123")


def test_hostname_shared_by_two_clients_is_not_guessed(client):
    a = _upload(client, "sample_config.xml")["id"]
    b = _upload(client, "sample_config.xml")["id"]
    client.patch(f"/api/assessments/{a}", json={"client_name": "Acme Corp"})
    client.patch(f"/api/assessments/{b}", json={"client_name": "Globex"})
    assert _upload(client, "sample_config.xml")["client_name"] is None


def test_hostname_match_takes_no_serial_when_earlier_runs_disagree(client):
    a = _upload(client, "sample_config.xml")["id"]
    b = _upload(client, "sample_config.xml")["id"]
    client.patch(f"/api/assessments/{a}", json={"client_name": "Acme Corp", "serial": "111"})
    client.patch(f"/api/assessments/{b}", json={"client_name": "Acme Corp", "serial": "222"})
    third = _upload(client, "sample_config.xml")
    assert (third["client_name"], third["serial"]) == ("Acme Corp", None)


def test_generic_hostname_is_never_matched():
    from app.main import _GENERIC_HOSTNAME
    for host in ("", "N/A", "PA-VM", "pa-440", "PA-3260", "localhost.localdomain"):
        assert _GENERIC_HOSTNAME.match(host), host
    for host in ("fw01", "pan1", "PA-edge-01", "gx-dc-fw01"):
        assert not _GENERIC_HOSTNAME.match(host), host


def test_unmatched_serial_does_not_fall_back_to_hostname(client):
    tsf = _upload(client, "sample_techsupport.tgz")                   # has a serial
    host = tsf["hostname"]
    cfg = _upload(client, "sample_config.xml")
    from app import db
    with db.engine.begin() as conn:   # an earlier, different firewall with the same hostname
        conn.execute(text("UPDATE assessment SET hostname = :h, client_name = 'Globex' WHERE id = :id"),
                     {"h": host, "id": cfg["id"]})
    client.delete(f"/api/assessments/{tsf['id']}")
    again = _upload(client, "sample_techsupport.tgz")                 # serial matches nothing
    assert again["client_name"] is None


def test_startup_backfills_serial_column_from_parsed_data(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'old2.db'}"
    old = create_engine(url)
    with old.begin() as conn:
        conn.execute(text(
            "CREATE TABLE assessment (id INTEGER PRIMARY KEY, filename VARCHAR, hostname VARCHAR, "
            "source VARCHAR, uploaded_at DATETIME, parsed_data JSON)"
        ))
        conn.execute(text(
            "INSERT INTO assessment VALUES (1, 'old.tgz', 'fw1', 'tsf_upload', '2026-01-01 00:00:00', "
            "'{\"system_info\": {\"serial\": \"0001\"}}'), "
            "(2, 'old.xml', 'fw2', 'file_upload', '2026-01-01 00:00:00', '{\"system_info\": {\"serial\": \"N/A\"}}')"
        ))
    old.dispose()
    monkeypatch.setenv("DATABASE_URL", url)
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app):
        pass
    with db.engine.connect() as conn:
        rows = dict(conn.execute(text("SELECT id, serial FROM assessment ORDER BY id")).all())
    assert rows == {1: "0001", 2: None}

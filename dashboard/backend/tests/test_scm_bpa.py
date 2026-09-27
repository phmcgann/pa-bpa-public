import gzip
import json
import os

import httpx
import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    import importlib

    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        c.main = main
        yield c


@pytest.fixture
def scm_result():
    return json.loads(_fixture("scm_bpa_result.json"))


def _upload(client, name="network_decryption_settings.xml") -> int:
    resp = client.post("/api/assessments/upload", files={"file": (name, _fixture(name), "text/xml")})
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


def _run_scm(client, monkeypatch, assessment_id, result, sent=None):
    monkeypatch.setenv("SCM_AUTH", "proxy")

    def fake_run_bpa(config_xml):
        if sent is not None:
            sent.append(config_xml)
        return {**result, "_task_id": "task-1"}

    monkeypatch.setattr(client.main.scm_client, "run_bpa", fake_run_bpa)
    return client.post(f"/api/assessments/{assessment_id}/scm-bpa")


# ── Core rule labelling ────────────────────────────────────────────────────

def test_core_rules_are_labelled_and_linked_to_scm_checks(client):
    rules = {r["id"]: r for r in client.get("/api/rules").json()}
    assert all(r["program"] == "core" for r in rules.values())
    assert rules["security_rule_no_description"]["source_type"] == "pan_docs"
    assert rules["security_rule_no_description"]["scm_check_ids"] == [3]
    assert rules["security_rule_temp_test_name"]["scm_check_ids"] == []


def test_every_linked_scm_check_is_in_the_catalogue(client):
    catalog = {c["id"]: c for c in client.get("/api/scm/catalog").json()["checks"]}
    assert len(catalog) >= 200
    rules = client.get("/api/rules").json()
    for r in rules:
        for cid in r["scm_check_ids"]:
            assert cid in catalog, (r["id"], cid)
    assert "security_rule_no_description" in catalog[3]["core_rules"]
    assert catalog[76]["category"] == "GlobalProtect"


# ── Running SCM BPA ──────────────────────────────────────────────────────

def test_upload_keeps_config_and_scm_run_uses_it(client, monkeypatch, scm_result):
    aid = _upload(client)
    status = client.get(f"/api/assessments/{aid}").json()["scm"]
    assert status["config_stored"] is True and status["run"] is None

    sent = []
    resp = _run_scm(client, monkeypatch, aid, scm_result, sent)
    assert resp.status_code == 200, resp.text
    assert sent == [_fixture("network_decryption_settings.xml")]
    run = resp.json()["run"]
    assert run["status"] == "completed" and run["failed"] == 7


def test_scm_findings_merge_with_core_and_duplicates_score_once(client, monkeypatch, scm_result):
    aid = _upload(client)
    before = client.get(f"/api/assessments/{aid}").json()
    _run_scm(client, monkeypatch, aid, scm_result)
    after = client.get(f"/api/assessments/{aid}").json()

    scm = {f["finding_key"]: f for f in after["findings"] if f["program"] == "scm"}
    gp = scm["scm_76:global_protect_gateway:corp-gateway"]
    assert gp["category"] == "GlobalProtect"
    assert gp["severity"] == "WARNING"  # SCM "Warning" maps straight across
    assert gp["source_ref"].startswith("Palo Alto Networks Strata Cloud Manager BPA check #76")
    assert gp["not_scored_reason"] is None

    # The core no-description rule already flagged these rules → SCM #3 isn't scored again
    dup = scm["scm_3:security_rule:local-only-rule"]
    assert dup["duplicate_of"] == ["security_rule_no_description"]
    assert dup["not_scored_reason"] == "duplicate"

    scored_scm = [f for f in scm.values() if f["not_scored_reason"] is None]
    assert after["summary"]["total"] == before["summary"]["total"] + len(scored_scm)


def test_scm_findings_can_be_left_out_of_the_score(client, monkeypatch, scm_result):
    aid = _upload(client)
    before = client.get(f"/api/assessments/{aid}").json()["summary"]["total"]
    _run_scm(client, monkeypatch, aid, scm_result)
    assert client.patch("/api/scm/settings", json={"include_in_score": False}).json() == {"include_in_score": False}
    after = client.get(f"/api/assessments/{aid}").json()
    assert after["summary"]["total"] == before
    assert all(f["not_scored_reason"] in ("duplicate", "scm_excluded")
               for f in after["findings"] if f["program"] == "scm")


def test_scm_checks_can_be_disabled_and_recategorized(client, monkeypatch, scm_result):
    aid = _upload(client)
    _run_scm(client, monkeypatch, aid, scm_result)
    assert client.patch("/api/rules/scm_77", json={"enabled": False}).status_code == 200
    assert client.patch("/api/rules/scm_76", json={"severity_override": "CRITICAL"}).status_code == 200
    assert client.patch("/api/rules/scm_999999", json={"enabled": False}).status_code == 404
    keys = {f["finding_key"]: f for f in client.get(f"/api/assessments/{aid}").json()["findings"]}
    assert "scm_77:global_protect_gateway:corp-gateway" not in keys
    assert keys["scm_76:global_protect_gateway:corp-gateway"]["severity"] == "CRITICAL"


def test_scm_run_requires_configuration(client, monkeypatch):
    for var in ("SCM_AUTH", "SCM_CLIENT_ID", "SCM_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    aid = _upload(client)
    resp = client.post(f"/api/assessments/{aid}/scm-bpa")
    assert resp.status_code == 409 and "SCM_CLIENT_ID" in resp.json()["detail"]


def test_scm_run_needs_a_stored_config(client, monkeypatch, scm_result):
    aid = _upload(client)
    from sqlmodel import Session
    with Session(client.main.get_session.__globals__["engine"]) as s:
        s.delete(s.get(client.main.AssessmentConfig, aid))
        s.commit()
    resp = _run_scm(client, monkeypatch, aid, scm_result)
    assert resp.status_code == 409 and "re-upload" in resp.json()["detail"]


def test_failed_scm_run_is_recorded(client, monkeypatch):
    aid = _upload(client)
    monkeypatch.setenv("SCM_AUTH", "proxy")

    def boom(config_xml):
        raise client.main.scm_client.ScmError("SCM refused to start a BPA upload (HTTP 403)")

    monkeypatch.setattr(client.main.scm_client, "run_bpa", boom)
    resp = client.post(f"/api/assessments/{aid}/scm-bpa")
    assert resp.status_code == 502
    run = client.get(f"/api/assessments/{aid}").json()["scm"]["run"]
    assert run["status"] == "failed" and "403" in run["error"]


def test_delete_assessment_removes_scm_rows(client, monkeypatch, scm_result):
    aid = _upload(client)
    _run_scm(client, monkeypatch, aid, scm_result)
    assert client.delete(f"/api/assessments/{aid}").status_code == 204


# ── Client ───────────────────────────────────────────────────────────────

def test_extract_results_flattens_objects(scm_result):
    from app import scm_client
    rows = scm_client.extract_results(scm_result)
    failed = {(r["check_id"], r["object_name"]) for r in rows if not r["passed"]}
    assert (76, "corp-gateway") in failed and (3, "local-only-rule") in failed
    assert all(isinstance(r["check_id"], int) for r in rows)


def test_run_bpa_flow_with_token_polling_and_upload(monkeypatch, scm_result):
    from app import scm_client
    monkeypatch.setenv("SCM_CLIENT_ID", "cid")
    monkeypatch.setenv("SCM_CLIENT_SECRET", "secret")
    monkeypatch.setenv("SCM_TSG_ID", "1234")
    calls = []
    polls = iter(["IN_PROGRESS", "COMPLETED"])

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.method, str(req.url)))
        if str(req.url) == scm_client.TOKEN_URL:
            assert req.headers["authorization"].startswith("Basic ")
            assert b"tsg_id%3A1234" in req.content
            return httpx.Response(200, json={"access_token": "tok"})
        if req.url.host == "upload.example":
            assert gzip.decompress(req.content) == b"<config/>"
            assert req.headers["content-encoding"] == "gzip"
            return httpx.Response(200)
        if req.url.host == "result.example":
            return httpx.Response(200, json=scm_result)
        assert req.headers["authorization"] == "Bearer tok"
        assert req.headers["x-tenant-id"] == "1234"
        if req.url.path.endswith("config-file-upload"):
            assert json.loads(req.content) == {"delete_after_processing": True}
            return httpx.Response(201, json={"task_id": "t1", "upload_url": "https://upload.example/x"})
        if req.url.path.endswith("/t1/bpa-result"):
            s = next(polls)
            body = {"status": s}
            if s == "COMPLETED":
                body["result"] = {"report_url": "", "custom_check_url": "https://result.example/r.json"}
            return httpx.Response(200, json=body)
        raise AssertionError(req.url)

    with httpx.Client(transport=httpx.MockTransport(handler)) as c:
        out = scm_client.run_bpa(b"<config/>", poll_seconds=0, client=c)
    assert out["_task_id"] == "t1"
    assert "best_practices" in out
    assert [m for m, _ in calls].count("GET") >= 3


def test_run_bpa_explains_permission_errors(monkeypatch):
    from app import scm_client
    for var in ("SCM_CLIENT_ID", "SCM_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    transport = httpx.MockTransport(lambda req: httpx.Response(403, json={"msg": "Access denied"}))
    with httpx.Client(transport=transport) as c, pytest.raises(scm_client.ScmError, match="role"):
        scm_client.run_bpa(b"<config/>", client=c)


def test_scm_severities_map_onto_the_same_scale():
    from app.rules import scm_catalog
    assert scm_catalog.SEVERITY_MAP == {
        "Critical": "CRITICAL", "High": "WARNING", "Warning": "WARNING", "Informational": "INFORMATIONAL",
    }
    used = {c["severity"] for c in scm_catalog.load()["checks"]}
    assert used <= set(scm_catalog.SEVERITY_MAP)


def test_satellite_checks_74_and_79_are_off_by_default(client, monkeypatch, scm_result):
    catalog = {c["id"]: c for c in client.get("/api/scm/catalog").json()["checks"]}
    for cid in (74, 79):
        assert catalog[cid]["enabled"] is False
        assert "no satellites" in catalog[cid]["default_off_reason"]
    assert catalog[76]["enabled"] is True and catalog[76]["default_off_reason"] is None

    aid = _upload(client)
    _run_scm(client, monkeypatch, aid, scm_result)  # the fixture run fails #79 on corp-gateway
    keys = {f["finding_key"] for f in client.get(f"/api/assessments/{aid}").json()["findings"]}
    assert "scm_79:global_protect_gateway:corp-gateway" not in keys

    # Changing only the severity keeps it off; switching it on brings the finding back.
    client.patch("/api/rules/scm_79", json={"severity_override": "LOW"})
    assert {c["id"]: c for c in client.get("/api/scm/catalog").json()["checks"]}[79]["enabled"] is False
    client.patch("/api/rules/scm_79", json={"enabled": True})
    findings = {f["finding_key"]: f for f in client.get(f"/api/assessments/{aid}").json()["findings"]}
    assert findings["scm_79:global_protect_gateway:corp-gateway"]["severity"] == "LOW"


def test_failed_run_keeps_the_scm_task_id(monkeypatch):
    from app import scm_client
    monkeypatch.delenv("SCM_CLIENT_ID", raising=False)
    monkeypatch.delenv("SCM_CLIENT_SECRET", raising=False)

    def handler(req):
        if req.url.host == "upload.example":
            return httpx.Response(200)
        if req.url.path.endswith("config-file-upload"):
            return httpx.Response(201, json={"task_id": "t9", "upload_url": "https://upload.example/x"})
        return httpx.Response(200, json={"status": "FAILED", "message": "An internal error occurred"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as c, pytest.raises(scm_client.ScmError) as err:
        scm_client.run_bpa(b"<config/>", poll_seconds=0, client=c)
    assert err.value.task_id == "t9"
    assert str(err.value) == "SCM BPA failed: An internal error occurred (SCM task t9)"

"""How current the bundled Palo Alto content is, and SCM checks newer than the bundled list."""
import importlib
from datetime import date

import pytest

from app import content_info
from app.rules import scm_catalog, scm_coverage
from app.rules.engine import DEFAULT_WEIGHTS


def test_every_bundled_item_has_a_date_and_is_current_today():
    items = {i["id"]: i for i in content_info.report()["items"]}
    assert set(items) == {"pan_os_lifecycle", "scm_catalog", "builtin_profiles", "threat_intel", "advisories"}
    for i in items.values():
        if i["kind"] == "bundled":
            assert date.fromisoformat(i["as_of"]) and not i["review_due"]
    assert items["advisories"]["kind"] == "live" and items["advisories"]["status"] == "disabled"  # feed off in tests
    assert items["scm_catalog"]["as_of"] == scm_catalog.as_of()


def test_bundled_content_is_flagged_once_it_is_old():
    items = {i["id"]: i for i in content_info.report(on=date(2027, 6, 1))["items"]}
    assert items["scm_catalog"]["review_due"] and items["pan_os_lifecycle"]["review_due"]
    assert not items["advisories"]["review_due"]


def _scm(cid):
    return {"rule_id": f"scm_{cid}", "finding_key": f"scm_{cid}:x:y", "title": f"check {cid}", "category": "Device",
            "severity": "WARNING", "program": "scm", "scm_check_ids": [cid], "duplicate_of": [],
            "dismissed": False, "not_scored_reason": None}


def _row(cid):
    return {"check_id": cid, "object_type": "x", "object_name": "y", "passed": False, "excluded": False,
            "failed_fields": {"x": False}}


def test_checks_missing_from_the_bundled_list_are_new_from_palo_alto():
    known = min(scm_catalog.checks_by_id())
    unknown = 9001
    assert unknown not in scm_catalog.checks_by_id()
    cov = scm_coverage.build([_scm(known), _scm(unknown)], [_row(known), _row(unknown)], {}, DEFAULT_WEIGHTS)
    flags = {c["check_id"]: c["new_check"] for c in cov["checks"]}
    assert flags == {known: False, unknown: True}
    assert cov["new_checks"] == 1 and cov["catalog_as_of"] == scm_catalog.as_of()
    text = scm_coverage.as_text({**cov, "text": ""})
    assert "1 failed checks are new from Palo Alto" in text
    assert f"SCM {unknown} |" in text and "NEW: not in the bundled check list" in text


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


def test_content_endpoint(client):
    r = client.get("/api/content")
    assert r.status_code == 200
    body = r.json()
    assert body["review_after_days"] == 180 and len(body["items"]) == 5

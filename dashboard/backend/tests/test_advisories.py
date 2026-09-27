"""PAN-OS security advisories: version matching, the checks, and the assessment page's report."""
import os

import pytest

from app import advisories
from app.rules import checks
from app.rules.definitions import RULES_BY_ID

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def adv(id_, severity, version, affected, fixed, listed=None, date="2026-09-01T00:00:00.000Z"):
    """An advisory in the cached (slimmed) shape."""
    return {"id": id_, "title": f"PAN-OS: issue {id_}", "severity": severity, "score": 8.1, "date": date,
            "version": [f"PAN-OS {version}"], "affected": [affected], "fixed": [fixed],
            "affected_list": listed or []}


R112 = "< 11.2.4-h21, < 11.2.7-h20, < 11.2.10-h14, < 11.2.13-h2"
F112 = ">= 11.2.4-h21, >= 11.2.7-h20, >= 11.2.10-h14, >= 11.2.13-h2"


@pytest.fixture(autouse=True)
def _reset():
    yield
    advisories.set_for_tests(None)


@pytest.mark.parametrize("version,affected", [
    ("11.2.0", True), ("11.2.4-h20", True), ("11.2.4-h21", False),
    # A hotfix fix only covers its own maintenance release: 11.2.5 still needs 11.2.7-h20.
    ("11.2.5", True), ("11.2.7-h20", False), ("11.2.8", True),
    ("11.2.13-h2", False), ("11.2.14", False),
])
def test_hotfix_ranges(version, affected):
    assert advisories._range_affected(R112, advisories.parse_version(version)) is affected


def test_plain_and_inclusive_ranges():
    pv = advisories.parse_version
    assert advisories._range_affected("< 10.2.9, < 10.2.10-h5", pv("10.2.9-h1")) is False
    assert advisories._range_affected("< 10.2.9, < 10.2.10-h5", pv("10.2.10-h4")) is True
    assert advisories._range_affected("<= 10.2.3", pv("10.2.3-h4")) is True
    assert advisories._range_affected("<= 10.2.3", pv("10.2.4")) is False
    assert advisories._range_affected("All", pv("10.2.4")) is True
    assert advisories._range_affected("None", pv("10.2.4")) is False
    # Platform-qualified text isn't guessed at.
    assert advisories._range_affected("< 10.2.4 on Panorama", pv("10.2.1")) is None


def test_explicit_affected_list_wins_over_ranges():
    a = adv("CVE-1", "HIGH", "11.1", "< 11.1.5", ">= 11.1.5", listed=["PAN-OS 11.1.2", "PAN-OS 11.1.3"])
    assert advisories.match(a, "11.1.2") is not None
    assert advisories.match(a, "11.1.4") is None  # in the range, but not listed
    assert advisories.match(a, "10.2.4") is None  # another release


def test_fix_hint_is_the_next_fixed_build():
    a = adv("CVE-1", "HIGH", "11.2", R112, F112)
    assert advisories.match(a, "11.2.5")["fix"] == "Upgrade to PAN-OS 11.2.7-h20 or later"
    assert advisories.match(a, "11.2.4-h3")["fix"] == "Upgrade to PAN-OS 11.2.4-h21 or later"


def test_recommended_upgrade_clears_critical_and_high():
    feed = [adv("CVE-1", "CRITICAL", "11.2", "< 11.2.4-h10, < 11.2.7", ">= 11.2.4-h10, >= 11.2.7"),
            adv("CVE-2", "HIGH", "11.2", "< 11.2.4-h21, < 11.2.7-h20", ">= 11.2.4-h21, >= 11.2.7-h20"),
            adv("CVE-3", "MEDIUM", "11.2", "< 11.2.4-h30", ">= 11.2.4-h30")]
    assert advisories.recommended_upgrade(feed, "11.2.4-h1") == "11.2.4-h21"
    # A release that no longer appears in recent advisories gets no recommendation.
    old = [adv("CVE-9", "HIGH", "9.1", "< 9.1.17", ">= 9.1.17", date="2021-01-01T00:00:00.000Z")] + feed
    assert advisories.recommended_upgrade(old, "9.1.10") is None


def _data(version="11.2.5", feed=None):
    return {"system_info": {"available": True, "sw_version": version},
            "_advisories": feed if feed is not None else [
                adv("CVE-C", "CRITICAL", "11.2", R112, F112),
                adv("CVE-H", "HIGH", "11.2", R112, F112),
                adv("CVE-M1", "MEDIUM", "11.2", R112, F112),
                adv("CVE-M2", "MEDIUM", "11.2", R112, F112),
                adv("CVE-L", "LOW", "11.2", R112, F112),
                adv("CVE-X", "CRITICAL", "11.1", "< 11.1.9", ">= 11.1.9"),
            ]}


def _run(rule_id, data):
    return checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds)


def test_checks_split_by_severity():
    data = _data()
    assert [f["key"] for f in _run("panos_advisory_critical", data)] == ["CVE-C"]
    assert [f["key"] for f in _run("panos_advisory_high", data)] == ["CVE-H"]
    [medium] = _run("panos_advisory_medium", data)
    assert medium["message"].startswith("2 medium-severity security advisories affect the installed PAN-OS 11.2.5")
    assert "CVE-M1, CVE-M2" in medium["message"]
    assert len(_run("panos_advisory_low", data)) == 1
    crit = _run("panos_advisory_critical", data)[0]
    assert "11.2.7-h20" in crit["recommendation"] and "security.paloaltonetworks.com/CVE-C" in crit["recommendation"]


def test_checks_are_silent_without_exact_version_or_feed():
    assert _run("panos_advisory_critical", _data(version="11.2.13-h2")) == []
    no_version = {**_data(), "system_info": {"available": False}}
    assert _run("panos_advisory_critical", no_version) == []
    assert _run("panos_advisory_critical", {**_data(), "_advisories": None}) == []
    assert RULES_BY_ID["panos_advisory_low"].enabled_by_default is False


def test_report_explains_a_config_export():
    advisories.set_for_tests(_data()["_advisories"])
    r = advisories.report({"system_info": {"available": False}})
    assert r["matches"] == [] and "tech support file" in r["reason"]
    r = advisories.report({"system_info": {"available": True, "sw_version": "11.2.5"}})
    assert r["status"] == "ok" and [m["id"] for m in r["matches"]][:2] == ["CVE-C", "CVE-H"]


def test_report_when_feed_is_off():
    r = advisories.report({"system_info": {"available": True, "sw_version": "11.2.5"}})
    assert r["status"] == "disabled" and r["matches"] == []


def test_fetch_pages_until_a_page_adds_nothing():
    import httpx
    pages = {1: [{"ID": "A", "severity": "HIGH"}, {"ID": "B", "severity": "LOW"}], 2: [{"ID": "C"}], 3: []}

    def handler(request):
        return httpx.Response(200, json=pages[int(request.url.params["page"])])

    got = advisories.fetch(httpx.Client(transport=httpx.MockTransport(handler)))
    assert [a["id"] for a in got] == ["A", "B", "C"]


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


def test_tech_support_file_gets_advisory_findings(client):
    advisories.set_for_tests([adv("CVE-2024-0001", "CRITICAL", "11.1", "< 11.1.2-h3", ">= 11.1.2-h3")])
    raw = open(os.path.join(FIXTURES, "sample_techsupport.tgz"), "rb").read()  # PAN-OS 11.1.0
    r = client.post("/api/assessments/upload", files={"file": ("ts.tgz", raw, "application/gzip")})
    assert r.status_code == 200, r.text
    body = client.get(f"/api/assessments/{r.json()['id']}").json()
    assert [f["finding_key"] for f in body["findings"] if f["rule_id"] == "panos_advisory_critical"] == \
        ["panos_advisory_critical:CVE-2024-0001"]
    assert body["advisories"]["version"] == "11.1.0" and body["advisories"]["matches"][0]["id"] == "CVE-2024-0001"

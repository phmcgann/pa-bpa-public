"""Rules without a Log Forwarding profile: scored when the firewall has one to attach, informational and
unscored when it has none of its own (apart from the IoT Security default)."""
import pytest

from app import parser
from app.rules import checks
from app.rules.engine import run_rules

RULES = [{"name": "web", "action": "allow", "log_setting": None}, {"name": "dns", "action": "allow", "log_setting": "siem"}]


def _items(profiles):
    data = {"security_rules": RULES}
    if profiles is not None:
        data["log_forwarding_profiles"] = [{"name": n, "lists": []} for n in profiles]
    return checks.check_security_rule_no_log_forwarding(data, {})


@pytest.mark.parametrize("profiles", [[], ["IoT Security Default Profile"]])
def test_nothing_to_attach_is_informational_and_unscored(profiles):
    [item] = _items(profiles)
    assert item["key"] == "web" and item["severity"] == "INFORMATIONAL"
    assert item["not_scored"] == "no_log_forwarding_profile" and "none set up yet" in item["message"]


@pytest.mark.parametrize("profiles", [["siem"], ["IoT Security Default Profile", "siem"], None])
def test_a_profile_to_attach_keeps_the_rule_severity(profiles):
    # None: an upload from before profiles were parsed, so it isn't known that there are none.
    [item] = _items(profiles)
    assert "severity" not in item and "not_scored" not in item


def test_engine_carries_the_reason():
    data = parser.parse_config(CONFIG)
    assert data["log_forwarding_profiles"] == []
    [f] = [f for f in run_rules(data, {}) if f["rule_id"] == "security_rule_no_log_forwarding"]
    assert f["severity"] == "INFORMATIONAL" and f["not_scored_reason"] == "no_log_forwarding_profile"
    with_profile = {**data, "log_forwarding_profiles": [{"name": "siem", "lists": []}]}
    [f] = [f for f in run_rules(with_profile, {}) if f["rule_id"] == "security_rule_no_log_forwarding"]
    assert f["severity"] == "LOW" and f["not_scored_reason"] is None


CONFIG = b"""<config version="11.1.0"><devices><entry name="localhost.localdomain">
  <deviceconfig><system><hostname>fw-logs</hostname></system></deviceconfig>
  <vsys><entry name="vsys1"><rulebase><security><rules>
    <entry name="web"><from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <source-user><member>any</member></source-user><category><member>any</member></category>
      <application><member>web-browsing</member></application><service><member>application-default</member></service>
      <action>allow</action></entry>
  </rules></security></rulebase></entry></vsys>
</entry></devices><shared/></config>"""


def test_assessment_score_leaves_it_out(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    import importlib
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as client:
        r = client.post("/api/assessments/upload", files={"file": ("fw.xml", CONFIG, "text/xml")})
        assert r.status_code == 200, r.text
        body = client.get(f"/api/assessments/{r.json()['id']}").json()
    [f] = [f for f in body["findings"] if f["rule_id"] == "security_rule_no_log_forwarding"]
    assert f["severity"] == "INFORMATIONAL" and f["not_scored_reason"] == "no_log_forwarding_profile"
    counted = [x for x in body["findings"] if not x["dismissed"] and not x["rule_disabled"] and not x["not_scored_reason"]]
    assert body["summary"]["total"] == len(counted) and f not in counted

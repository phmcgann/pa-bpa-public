"""Core rule coverage of a stored SCM run: which failed SCM checks the core rules also caught."""
from app.rules import scm_coverage
from app.rules.engine import DEFAULT_WEIGHTS
from app.rules.scm_findings import core_rules_by_scm_check


def scm(cid, key="obj", severity="WARNING", duplicate_of=None):
    return {"rule_id": f"scm_{cid}", "finding_key": f"scm_{cid}:x:{key}", "title": f"check {cid}",
            "category": "Device Hardening", "severity": severity, "program": "scm", "scm_check_ids": [cid],
            "duplicate_of": duplicate_of or [], "dismissed": False, "not_scored_reason": "duplicate" if duplicate_of else None}


def core(rule_id):
    return {"rule_id": rule_id, "finding_key": f"{rule_id}:x", "program": "core"}


def row(cid, fields=None):
    return {"check_id": cid, "object_type": "device", "passed": False, "excluded": False, "failed_fields": fields}


LINKED = core_rules_by_scm_check()
NTP_CHECK = next(cid for cid, rules in LINKED.items() if "no_ntp" in rules)
UNLINKED = 999999


def test_statuses():
    findings = [scm(NTP_CHECK), scm(UNLINKED), scm(NTP_CHECK + 100000, duplicate_of=["x"])]
    cov = scm_coverage.build(findings, [row(NTP_CHECK, {"ntp_servers": None, "server": "10.1.1.1"})], {}, DEFAULT_WEIGHTS)
    by = {c["check_id"]: c for c in cov["checks"]}
    assert by[NTP_CHECK]["status"] == "core_missed" and by[NTP_CHECK]["points"] == 5
    assert by[UNLINKED]["status"] == "no_rule"
    assert by[NTP_CHECK + 100000]["status"] == "covered" and by[NTP_CHECK + 100000]["points"] == 0
    # Field values are kept only when they can't name anything.
    assert by[NTP_CHECK]["failed_fields"] == ["ntp_servers=None", "server"]
    assert cov["summary"]["core_missed"] == {"checks": 1, "points": 5}


def test_fired_elsewhere_and_turned_off():
    fired = scm_coverage.build([scm(NTP_CHECK), core("no_ntp")], [], {}, DEFAULT_WEIGHTS)
    assert fired["checks"][0]["status"] == "object_mismatch"
    off = scm_coverage.build([scm(NTP_CHECK)], [], {"no_ntp": {"enabled": False}}, DEFAULT_WEIGHTS)
    assert off["checks"][0]["status"] == "core_off"


def test_text_export_has_no_values_that_name_things():
    cov = scm_coverage.build([scm(NTP_CHECK, key="corp-dc1")], [row(NTP_CHECK, {"server": "10.9.9.9"})], {},
                             DEFAULT_WEIGHTS)
    text = scm_coverage.as_text(cov)
    assert f"SCM {NTP_CHECK} |" in text and "no_ntp" in text and "fields: server" in text
    assert "10.9.9.9" not in text and "corp-dc1" not in text

"""Remediation plan: findings grouped into ordered work items."""
from app import remediation
from app.rules.definitions import RULES
from app.rules.engine import DEFAULT_WEIGHTS


def f(rule_id, severity, key="x", category="Security Policy", program="core", **kw):
    return {"rule_id": rule_id, "finding_key": f"{rule_id}:{key}", "title": rule_id.replace("_", " "),
            "severity": severity, "category": category, "program": program, "dismissed": False,
            "rule_disabled": False, "not_scored_reason": None, **kw}


def test_groups_orders_and_totals():
    findings = [
        f("panos_advisory_critical", "CRITICAL", "CVE-1", "Software"),
        f("panos_advisory_high", "WARNING", "CVE-2", "Software"),
        f("security_rule_missing_profile_non_infra", "WARNING", "r1"),
        f("security_rule_missing_profile_non_infra", "WARNING", "r2"),
        f("unused_objects", "INFORMATIONAL", "addresses"),
        f("security_rule_shadowed", "LOW", "r3"),
        f("no_ntp", "LOW", "global", "Device Hardening"),
    ]
    plan = remediation.build(findings, DEFAULT_WEIGHTS, "11.1.4-h36")
    assert [i["key"] for i in plan] == ["upgrade", "attach_profiles", "cleanup", "mgmt_access"]
    up = plan[0]
    assert up["title"] == "Upgrade PAN-OS to 11.1.4-h36 or later" and up["order"] == 1
    assert (up["severity"], up["finding_count"], up["points"]) == ("CRITICAL", 2, 15)
    attach = plan[1]
    assert attach["checks"] == [{"rule_id": "security_rule_missing_profile_non_infra",
                                 "title": "security rule missing profile non infra", "severity": "WARNING",
                                 "program": "core", "count": 2}]
    assert plan[2]["points"] == 3  # LOW 2 + INFORMATIONAL 1


def test_only_scored_findings_count():
    findings = [f("no_ntp", "LOW", dismissed=True), f("security_rule_service_any", "WARNING", rule_disabled=True),
                f("zone_missing_protection_profile", "WARNING", "z", "Network Security", not_scored_reason="duplicate")]
    assert remediation.build(findings, DEFAULT_WEIGHTS) == []


def test_scm_findings_group_by_category_and_unknowns_go_to_other():
    findings = [f("scm_200", "WARNING", category="Logging", program="scm"),
                f("mystery_rule", "LOW", category="Something New")]
    plan = {i["key"]: i for i in remediation.build(findings, DEFAULT_WEIGHTS)}
    assert set(plan) == {"logging", "other"} and plan["logging"]["checks"][0]["program"] == "scm"


def test_upgrade_title_without_a_recommendation():
    [item] = remediation.build([f("eol_pan_os_version", "WARNING", category="Software")], DEFAULT_WEIGHTS)
    assert item["title"] == "Upgrade PAN-OS"


def test_every_rule_lands_in_a_named_work_item():
    for r in RULES:
        key = remediation._BY_RULE.get(r.id) or remediation._BY_CATEGORY.get(r.category)
        assert key, f"{r.id} ({r.category}) has no work item"


def test_rule_logging_goes_to_logging_not_policy():
    [item] = remediation.build([f("security_rule_no_logging_allow", "LOW", "r1")], DEFAULT_WEIGHTS)
    assert item["key"] == "logging"


def test_every_work_item_has_a_plain_language_risk():
    for key, *_ in remediation.ITEMS:
        assert remediation.RISKS[key]
    [item] = remediation.build([f("no_ntp", "LOW", category="Device Hardening")], DEFAULT_WEIGHTS)
    assert item["risk"] == remediation.RISKS["mgmt_access"]

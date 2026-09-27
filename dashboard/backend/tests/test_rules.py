import os

import pytest

from app import parser
from app.rules.engine import highest_active_severity, risk_label, run_rules, summarize

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_config.xml")


@pytest.fixture
def data():
    with open(FIXTURE, "rb") as f:
        return parser.parse_config(f.read())


@pytest.fixture
def keys(data):
    findings = run_rules(data, {})
    return {f["finding_key"] for f in findings}


def test_any_any_any_flagged(keys):
    assert "security_rule_any_any_any:allow-any-any-any" in keys


def test_missing_profile_non_infra(keys):
    assert "security_rule_missing_profile_non_infra:allow-any-any-any" in keys
    assert "security_rule_missing_profile_non_infra:temp-debug-rule" in keys


def test_missing_profile_infra_lower_severity_bucket(keys):
    assert "security_rule_missing_profile_infra:bgp-peering" in keys
    # bgp-peering should NOT also land in the non-infra bucket
    assert "security_rule_missing_profile_non_infra:bgp-peering" not in keys


def test_inbound_untrust_any_source(keys):
    assert "security_rule_inbound_untrust_any_source:web-servers-inbound" in keys


def test_app_any_service_any(keys):
    assert "security_rule_app_any_service_any:temp-debug-rule" in keys


def test_service_any(keys):
    assert "security_rule_service_any:ftp-legacy-transfer" in keys


def test_temp_test_name(keys):
    assert "security_rule_temp_test_name:temp-debug-rule" in keys


def test_no_logging_allow(keys):
    assert "security_rule_no_logging_allow:temp-debug-rule" in keys


def test_deny_no_logging(keys):
    assert "security_rule_deny_no_logging:deny-suspicious" in keys


def test_deny_remaining_disabled_variant(keys):
    assert "security_policy_no_deny_remaining:global" in keys


def test_zone_missing_protection_profile(keys):
    assert "zone_missing_protection_profile:trust" in keys
    assert "zone_missing_protection_profile:untrust" not in keys


def test_default_admin_and_no_mfa(keys):
    assert "default_admin_account:admin" in keys
    assert "admin_local_auth_no_mfa:admin" in keys
    assert "admin_local_auth_no_mfa:jsmith" not in keys
    assert "default_admin_account:jsmith" not in keys


def test_threat_profile_gaps(keys):
    assert "threat_profile_missing_antivirus:global" not in keys  # 1 AV profile defined
    assert "threat_profile_missing_vulnerability:global" in keys
    assert "threat_profile_missing_spyware:global" in keys
    assert "threat_profile_missing_url_filtering:global" in keys
    assert "threat_profile_missing_file_blocking:global" in keys
    assert "wildfire_profile_missing:global" in keys


def test_logging_and_hardening_gaps(keys):
    assert "no_syslog_profile:global" not in keys  # a syslog server profile is configured
    assert "mgmt_no_acl:global" in keys
    assert "no_login_banner:global" in keys
    assert "no_ntp:global" not in keys  # primary NTP server is configured


def test_offline_only_checks_are_silent(keys):
    assert not any(k.startswith("eol_pan_os_version:") for k in keys)
    assert not any(k.startswith("license_") for k in keys)
    assert not any(k.startswith("ha_not_synced:") for k in keys)


def test_disabling_a_rule_removes_its_findings(data):
    findings = run_rules(data, {"security_rule_any_any_any": {"enabled": False, "threshold_overrides": None}})
    keys = {f["finding_key"] for f in findings}
    assert "security_rule_any_any_any:allow-any-any-any" not in keys
    # other rules still run
    assert "zone_missing_protection_profile:trust" in keys


def test_every_finding_has_a_valid_source(data):
    findings = run_rules(data, {})
    for f in findings:
        assert f["source_type"] in ("cis", "pan_docs", "custom")
        if f["source_type"] in ("cis", "pan_docs"):
            assert f["source_ref"]
        else:
            assert f["source_ref"] is None


def test_severity_override_changes_finding_severity(data):
    findings = run_rules(data, {
        "security_rule_no_description": {
            "enabled": True, "threshold_overrides": None, "severity_override": "WARNING",
        }
    })
    matches = [f for f in findings if f["rule_id"] == "security_rule_no_description"]
    assert matches
    for f in matches:
        assert f["severity"] == "WARNING"
        assert f["default_severity"] == "INFORMATIONAL"
        assert f["severity_overridden"] is True

    other = [f for f in findings if f["rule_id"] == "default_admin_account"][0]
    assert other["severity_overridden"] is False
    assert other["severity"] == other["default_severity"]


def test_risk_label_uses_configurable_thresholds():
    counts = {"CRITICAL": 0, "WARNING": 0, "LOW": 3, "INFORMATIONAL": 0}
    default_thresholds = {"informational_max": 0, "low_max": 15, "warning_max": 40}
    assert risk_label(6, default_thresholds) == "LOW"  # 3 * weight 2 = 6

    tighter_thresholds = {"informational_max": 0, "low_max": 4, "warning_max": 40}
    assert risk_label(6, tighter_thresholds) == "WARNING"


def test_finding_on_disabled_rule_is_flagged_but_not_active(data):
    findings = run_rules(data, {})
    disabled_findings = [f for f in findings if f["finding_key"].endswith(":deny-suspicious")]
    assert disabled_findings
    for f in disabled_findings:
        assert f["rule_disabled"] is True

    enabled_findings = [f for f in findings if f["finding_key"].endswith(":allow-any-any-any")]
    assert enabled_findings
    for f in enabled_findings:
        assert f["rule_disabled"] is False

    # Global (non-per-rule) checks are never marked rule_disabled, even if their
    # own logic references a disabled rule by name internally.
    global_findings = [f for f in findings if f["finding_key"] == "security_policy_no_deny_remaining:global"]
    assert global_findings
    assert global_findings[0]["rule_disabled"] is False

    # "dismissed" is layered on top by main.py's compute_findings (DB-backed), not
    # part of run_rules' output — only rule_disabled is checked at this layer.
    active = [f for f in findings if not f["rule_disabled"]]
    assert not any(f["finding_key"].endswith(":deny-suspicious") for f in active)
    summary = summarize(active)
    # deny-suspicious's own finding (LOW) is excluded from the score
    assert summary["total"] == len(findings) - len(disabled_findings)


def test_risk_label_floor_guarantees_at_least_the_worst_active_severity():
    default_thresholds = {"informational_max": 0, "low_max": 15, "warning_max": 40}

    # One CRITICAL finding (10 pts) alone would only score LOW by points,
    # but must never report lower than CRITICAL — the exact scenario reported:
    # a lone critical shouldn't be able to read as INFORMATIONAL/LOW just because the
    # thresholds were tuned to need more points to reach that bucket.
    assert risk_label(10, default_thresholds, floor="CRITICAL") == "CRITICAL"

    # Same idea for WARNING: a couple of WARNING findings (10 pts) shouldn't be able
    # to read as LOW by points alone.
    assert risk_label(10, default_thresholds, floor="WARNING") == "WARNING"

    # The floor never pulls the label DOWN — if points alone already clear a
    # higher bucket than the floor, points win.
    assert risk_label(50, default_thresholds, floor="INFORMATIONAL") == "CRITICAL"

    # No active findings at all -> no floor to apply.
    assert risk_label(0, default_thresholds, floor=None) == "INFORMATIONAL"


def test_highest_active_severity():
    assert highest_active_severity({"CRITICAL": 0, "WARNING": 0, "LOW": 0, "INFORMATIONAL": 0}) is None
    assert highest_active_severity({"CRITICAL": 0, "WARNING": 0, "LOW": 1, "INFORMATIONAL": 3}) == "LOW"
    assert highest_active_severity({"CRITICAL": 1, "WARNING": 5, "LOW": 0, "INFORMATIONAL": 0}) == "CRITICAL"


def test_summarize_applies_floor_to_a_single_critical_finding():
    # Tight thresholds mean a single CRITICAL finding's 10 points alone
    # wouldn't reach the CRITICAL bucket by points, but the overall label
    # must still be CRITICAL because that's genuinely the worst open issue.
    finding = {"severity": "CRITICAL"}
    thresholds = {"informational_max": 0, "low_max": 15, "warning_max": 40}
    summary = summarize([finding], thresholds=thresholds)

    assert summary["points_based_label"] == "LOW"
    assert summary["risk_label"] == "CRITICAL"
    assert summary["floor_applied"] is True


def test_summarize_no_floor_needed_when_points_already_match():
    findings = [{"severity": "CRITICAL"}] * 5  # 50 pts, already CRITICAL by points
    summary = summarize(findings)
    assert summary["points_based_label"] == "CRITICAL"
    assert summary["risk_label"] == "CRITICAL"
    assert summary["floor_applied"] is False


def test_summarize_score_breakdown_matches_weights(data):
    findings = run_rules(data, {})
    weights = {"CRITICAL": 100, "WARNING": 1, "LOW": 1, "INFORMATIONAL": 1}
    thresholds = {"informational_max": 0, "low_max": 15, "warning_max": 40}
    summary = summarize(findings, weights, thresholds)

    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    assert summary["score_breakdown"]["CRITICAL"]["count"] == critical_count
    assert summary["score_breakdown"]["CRITICAL"]["points"] == critical_count * 100
    assert summary["score"] == sum(b["points"] for b in summary["score_breakdown"].values())

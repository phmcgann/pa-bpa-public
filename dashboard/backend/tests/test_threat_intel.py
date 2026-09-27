"""Threat-intelligence blocking coverage and its core checks."""
import os

import pytest

from app import parser
from app.rules import checks, threat_intel
from app.rules.definitions import RULES_BY_ID

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _parse(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return parser.parse_config(f.read())


@pytest.fixture(scope="module")
def data():
    return _parse("threat_intel_config.xml")


def _keys(data, rule_id):
    return sorted(i["key"] for i in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def test_external_lists_are_parsed(data):
    assert data["policy_objects"]["external_lists"] == {
        "corp-known-bad": {"type": "predefined-ip", "source": "panw-known-ip-list"},
        "partner-feed": {"type": "ip", "source": "https://feeds.example.com/ips.txt"},
    }


def test_coverage_resolves_directions_wrappers_and_disabled_rules(data):
    cov = {e["id"]: e for e in threat_intel.coverage(data)["lists"]}
    known = cov["panw-known-ip-list"]
    assert (known["inbound"], known["outbound"]) == (["block-known-inbound"], ["block-known-outbound"])
    assert (cov["panw-highrisk-ip-list"]["inbound"], cov["panw-highrisk-ip-list"]["outbound"]) == (
        ["block-highrisk-inbound"], [])
    assert cov["panw-bulletproof-ip-list"]["disabled_rules"] == ["block-bulletproof-old"]
    tor = cov["panw-torexit-ip-list"]   # negated source and an allow rule don't count
    assert (tor["inbound"], tor["outbound"], tor["disabled_rules"]) == ([], [], [])
    assert threat_intel.coverage(data)["quic"]["rules"] == ["block-evasive"]  # via application group


@pytest.mark.parametrize("rule_id, expected", [
    ("edl_known_malicious_not_blocked", []),
    ("edl_high_risk_not_blocked", ["outbound"]),
    ("edl_bulletproof_not_blocked", ["inbound", "outbound"]),
    ("edl_tor_exit_not_blocked", ["inbound", "outbound"]),
    ("quic_not_blocked", []),
])
def test_checks_flag_only_the_missing_directions(data, rule_id, expected):
    assert _keys(data, rule_id) == expected


def test_disabled_rule_is_named_in_the_message(data):
    msg = checks.check_edl_bulletproof_not_blocked(data, {})[0]["message"]
    assert "'block-bulletproof-old'" in msg and "disabled" in msg


def test_config_with_no_block_rules_flags_every_list_and_quic():
    data = _parse("sample_config.xml")
    for rule_id in ("edl_known_malicious_not_blocked", "edl_high_risk_not_blocked",
                    "edl_bulletproof_not_blocked", "edl_tor_exit_not_blocked"):
        assert _keys(data, rule_id) == ["inbound", "outbound"]
    assert _keys(data, "quic_not_blocked") == ["global"]


def test_quic_message_notes_decryption_in_use():
    data = _parse("network_decryption_settings.xml")
    msg = checks.check_quic_not_blocked(data, {})[0]["message"]
    assert "SSL decryption is in use" in msg


def test_no_security_rules_means_nothing_to_judge():
    for rule_id in ("edl_known_malicious_not_blocked", "quic_not_blocked"):
        assert checks.CHECKS[rule_id]({"security_rules": []}, {}) == []


def test_rules_cite_the_internet_gateway_best_practices():
    for rid in ("edl_known_malicious_not_blocked", "edl_high_risk_not_blocked", "edl_bulletproof_not_blocked",
                "edl_tor_exit_not_blocked", "quic_not_blocked"):
        r = RULES_BY_ID[rid]
        assert r.source_type == "pan_docs" and "internet-gateway-best-practices" in r.source_ref
    assert RULES_BY_ID["edl_high_risk_not_blocked"].scm_check_ids == (263, 264)
    assert RULES_BY_ID["quic_not_blocked"].scm_check_ids == (241,)

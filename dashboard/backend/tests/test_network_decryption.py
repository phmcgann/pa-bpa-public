import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules.engine import run_rules

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

NEW_RULE_IDS = {
    "decryption_no_outbound", "decryption_profile_weak_tls", "decryption_profile_cert_checks_disabled",
    "zone_protection_no_recon", "zone_protection_flood_disabled", "mgmt_profile_cleartext",
    "security_rule_no_log_forwarding", "zone_protection_recon_alert_only", "decryption_no_decrypt_cert_checks",
}


def _load(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


@pytest.fixture
def data():
    return parser.parse_config(_load("network_decryption_settings.xml"))


@pytest.fixture
def keys(data):
    return {f["finding_key"] for f in run_rules(data, {})}


# ── Parsing ──────────────────────────────────────────────────────────────

def test_parses_decryption_rules_and_defaults(data):
    rules = {r["name"]: r for r in data["decryption"]["rules"]}
    assert rules["decrypt-outbound"]["action"] == "decrypt"
    assert rules["decrypt-outbound"]["type"] == "ssl-forward-proxy"
    assert rules["decrypt-inbound-web"]["type"] == "ssl-inbound-inspection"
    assert rules["old-decrypt"]["disabled"] == "yes"

    profiles = {p["name"]: p for p in data["decryption"]["profiles"]}
    # No <min-version> element → the schema default, TLSv1.0
    assert profiles["weak-decrypt"]["min_version"] == "tls1-0"
    assert profiles["weak-decrypt"]["min_version_explicit"] is False
    assert profiles["tls11-decrypt"]["min_version"] == "tls1-1"
    assert profiles["weak-decrypt"]["forward_proxy_block_expired"] is False
    assert profiles["weak-decrypt"]["forward_proxy_block_untrusted"] is True
    # Absent boolean stays None, never assumed
    assert profiles["tls11-decrypt"]["forward_proxy_block_untrusted"] is None


def test_parses_zone_protection_profiles(data):
    zpp = {p["name"]: p for p in data["zone_protection_profiles"]}
    assert zpp["good-zpp"]["flood"]["tcp-syn"] is True
    assert zpp["good-zpp"]["syn_action"] == "syn-cookies"
    assert zpp["weak-zpp"]["syn_action"] == "red"
    assert zpp["weak-zpp"]["flood"]["udp"] is False
    assert zpp["weak-zpp"]["flood"]["other-ip"] is None
    assert {s["id"]: s["action"] for s in zpp["good-zpp"]["scans"]} == {"8001": "block-ip", "8002": "block"}
    assert zpp["no-recon-zpp"]["scans"] == []


def test_parses_mgmt_profiles_and_attachments(data):
    mgmt = {p["name"]: p for p in data["interface_mgmt_profiles"]}
    assert mgmt["insecure-mgmt"]["services"]["telnet"] is True
    assert mgmt["insecure-mgmt"]["services"]["ssh"] is False
    # Found under both an ethernet interface's <layer3> and a subinterface unit
    assert sorted(mgmt["insecure-mgmt"]["interfaces"]) == ["ethernet1/1", "ethernet1/2.10"]
    assert mgmt["secure-mgmt"]["interfaces"] == ["loopback.1"]
    assert mgmt["secure-mgmt"]["permitted_ip"] == ["10.0.0.0/24"]
    assert mgmt["unattached-insecure"]["interfaces"] == []


def test_parses_rule_log_setting(data):
    rules = {r["name"]: r for r in data["security_rules"]}
    assert rules["forwarded-rule"]["log_setting"] == "to-panorama"
    assert rules["local-only-rule"]["log_setting"] is None


# ── Checks ───────────────────────────────────────────────────────────────

def _dec_rule(name, action="decrypt", type_="ssl-forward-proxy", disabled="no"):
    return {"name": name, "action": action, "disabled": disabled, "type": type_, "profile": None}


def _no_outbound_findings(rules):
    data = {"decryption": {"rules": rules, "profiles": []}}
    return [f for f in run_rules(data, {}) if f["rule_id"] == "decryption_no_outbound"]


def test_decryption_no_outbound_not_flagged_with_active_forward_proxy_rule(keys):
    assert "decryption_no_outbound:global" not in keys


def test_decryption_no_outbound_flagged_when_only_inbound_inspection():
    # The real-world case: decrypt rules exist, but only for inbound traffic to your own servers
    findings = _no_outbound_findings([
        _dec_rule("inbound-web", type_="ssl-inbound-inspection"),
        _dec_rule("inbound-api", type_="ssl-inbound-inspection"),
        _dec_rule("exclude-finance", action="no-decrypt"),
    ])
    assert len(findings) == 1
    assert "only covers inbound traffic" in findings[0]["message"]
    assert "2 inbound-inspection rule(s)" in findings[0]["message"]


def test_decryption_no_outbound_flagged_when_forward_proxy_disabled():
    findings = _no_outbound_findings([_dec_rule("old-outbound", disabled="yes")])
    assert len(findings) == 1
    assert "exist but are disabled" in findings[0]["message"]


def test_decryption_no_outbound_flagged_with_no_policy():
    findings = _no_outbound_findings([])
    assert "no decryption policy at all" in findings[0]["message"]


def test_decryption_no_outbound_counts_decrypt_and_forward():
    assert _no_outbound_findings([_dec_rule("broker", action="decrypt-and-forward")]) == []


def test_decryption_profile_weak_tls(keys):
    # Unset min version (defaults to TLSv1.0) and explicit TLSv1.1 are both flagged
    assert "decryption_profile_weak_tls:weak-decrypt" in keys
    assert "decryption_profile_weak_tls:tls11-decrypt" in keys
    # Used only by a disabled rule / a no-decrypt rule → not checked
    assert "decryption_profile_weak_tls:only-on-disabled-rule" not in keys
    assert "decryption_profile_weak_tls:nd-profile" not in keys


def test_decryption_profile_weak_tls_message_explains_default(data):
    msg = next(f["message"] for f in run_rules(data, {})
               if f["finding_key"] == "decryption_profile_weak_tls:weak-decrypt")
    assert "not set, which PAN-OS treats as TLSv1.0" in msg


def test_decryption_profile_cert_checks_disabled(keys):
    assert "decryption_profile_cert_checks_disabled:weak-decrypt:forward_proxy_block_expired" in keys
    # Explicitly yes → fine
    assert "decryption_profile_cert_checks_disabled:weak-decrypt:forward_proxy_block_untrusted" not in keys
    # tls11-decrypt says no, but it's only used by an inbound-inspection rule — forward-proxy settings don't apply
    assert "decryption_profile_cert_checks_disabled:tls11-decrypt:forward_proxy_block_expired" not in keys
    assert "decryption_profile_cert_checks_disabled:only-on-disabled-rule:forward_proxy_block_expired" not in keys


def test_parses_no_decryption_cert_settings(data):
    profiles = {p["name"]: p for p in data["decryption"]["profiles"]}
    assert profiles["nd-profile"]["no_proxy_block_expired"] is False
    assert profiles["nd-profile"]["no_proxy_block_untrusted"] is None
    assert profiles["weak-decrypt"]["no_proxy_block_expired"] is None


def test_decryption_no_decrypt_cert_checks(keys):
    # Profile on an enabled no-decrypt rule explicitly doesn't block expired certs
    assert "decryption_no_decrypt_cert_checks:nd-profile:no_proxy_block_expired" in keys
    # Absent setting isn't assumed either way
    assert "decryption_no_decrypt_cert_checks:nd-profile:no_proxy_block_untrusted" not in keys
    # No-decrypt rule with no profile at all
    assert "decryption_no_decrypt_cert_checks:rule:exclude-health" in keys
    assert "decryption_no_decrypt_cert_checks:rule:old-exclusion" not in keys  # disabled
    # Decrypt rules' profiles aren't judged on their no-decryption settings
    assert not any(k.startswith("decryption_no_decrypt_cert_checks:weak-decrypt") for k in keys)


def test_zone_protection_no_recon(keys):
    assert "zone_protection_no_recon:good-zpp" not in keys
    assert "zone_protection_no_recon:weak-zpp" in keys       # only scan type is set to allow
    assert "zone_protection_no_recon:no-recon-zpp" in keys   # no scan entries at all
    assert "zone_protection_no_recon:unused-zpp" not in keys  # not assigned to any zone


def test_zone_protection_recon_alert_only(data, keys):
    assert "zone_protection_recon_alert_only:alert-zpp" in keys
    assert "zone_protection_recon_alert_only:good-zpp" not in keys   # block-ip / block
    assert "zone_protection_recon_alert_only:weak-zpp" not in keys   # allow is no_recon's job
    # Unassigned profiles are graded too (as Palo Alto SCM does), and say so.
    assert "zone_protection_recon_alert_only:unused-zpp" in keys
    msg = next(f["message"] for f in run_rules(data, {})
               if f["finding_key"] == "zone_protection_recon_alert_only:alert-zpp")
    assert "host sweep (8002)" in msg and "UDP port scan (8003)" in msg
    assert "8001" not in msg  # that one blocks


def test_zone_protection_flood_disabled(data, keys):
    assert "zone_protection_flood_disabled:weak-zpp:udp" in keys
    assert "zone_protection_flood_disabled:weak-zpp:icmp" in keys
    assert "zone_protection_flood_disabled:weak-zpp:tcp-syn" not in keys
    # Absent flood setting isn't assumed to be off
    assert "zone_protection_flood_disabled:weak-zpp:other-ip" not in keys
    assert not any(k.startswith("zone_protection_flood_disabled:no-recon-zpp") for k in keys)
    assert "zone_protection_flood_disabled:unused-zpp:udp" in keys
    msg = next(f["message"] for f in run_rules(data, {})
               if f["finding_key"] == "zone_protection_flood_disabled:unused-zpp:udp")
    assert "not assigned to any zone" in msg


def test_mgmt_profile_cleartext(data, keys):
    assert "mgmt_profile_cleartext:insecure-mgmt" in keys
    assert "mgmt_profile_cleartext:unattached-insecure" not in keys
    assert "mgmt_profile_cleartext:secure-mgmt" not in keys
    msg = next(f["message"] for f in run_rules(data, {})
               if f["finding_key"] == "mgmt_profile_cleartext:insecure-mgmt")
    assert "Telnet and HTTP" in msg


def test_security_rule_no_log_forwarding(keys):
    assert "security_rule_no_log_forwarding:local-only-rule" in keys
    assert "security_rule_no_log_forwarding:forwarded-rule" not in keys


# ── Back-compat: assessments stored before these fields existed ──────────

def test_old_assessment_data_produces_no_new_findings(data):
    old = copy.deepcopy(data)
    for key in ("decryption", "zone_protection_profiles", "interface_mgmt_profiles"):
        del old[key]
    for rule in old["security_rules"]:
        del rule["log_setting"]
    fired = {f["rule_id"] for f in run_rules(old, {})}
    assert not fired & NEW_RULE_IDS


# ── Panorama export ──────────────────────────────────────────────────────

@pytest.fixture
def panorama_data():
    root = ET.fromstring(_load("panorama_network_decryption.xml"))
    return panorama_parser.build_assessment_data(root, "branch")


def test_panorama_merges_decryption_rules_in_order(panorama_data):
    rules = panorama_data["decryption"]["rules"]
    assert [(r["name"], r["rule_scope"]) for r in rules] == [
        ("dg-exclude-health", "device_group_pre"),
        ("shared-catchall-decrypt", "shared_post"),
    ]


def test_panorama_findings(panorama_data):
    keys = {f["finding_key"] for f in run_rules(panorama_data, {})}
    assert "decryption_no_outbound:global" not in keys
    # Shared profile used by a shared post-rulebase decrypt rule
    assert "decryption_profile_weak_tls:shared-weak" in keys
    assert "decryption_profile_cert_checks_disabled:shared-weak:forward_proxy_block_untrusted" in keys
    # Zone protection profile from the template, assigned to a template zone
    assert "zone_protection_flood_disabled:branch-zpp:udp" in keys
    assert "zone_protection_no_recon:branch-zpp" in keys
    # 'mgmt' is redefined without telnet in the higher-priority template → not flagged
    assert "mgmt_profile_cleartext:mgmt" not in keys
    assert "mgmt_profile_cleartext:legacy-http" in keys

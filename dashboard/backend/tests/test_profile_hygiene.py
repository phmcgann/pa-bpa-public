"""Security, decryption and Log Forwarding profile checks ported from Palo Alto SCM."""
import os
import xml.etree.ElementTree as ET

import pytest

from app import parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID, SCM_MATCHES

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "profile_hygiene.xml")
RULE_IDS = ["profile_threat_exceptions", "av_packet_capture", "url_log_container_page_only",
            "url_categories_allowed_unlogged", "url_credential_detection_not_domain",
            "url_credential_submissions_unlogged", "url_inline_categorization_off", "decryption_inbound_checks_off",
            "decryption_ssh_checks_off", "decryption_weak_hmac", "log_forwarding_profile_no_destination",
            "log_forwarding_profile_missing_types"]
P = "devices/entry/vsys/entry/profiles"
URL = f"{P}/url-filtering/entry"
LF = "shared/log-settings/profiles/entry"
LICENSED = {"available": True, "licenses": [{"feature": "Advanced URL Filtering", "expired": "no"}]}


def _root():
    return ET.parse(FIXTURE).getroot()


def _data(root, licenses=LICENSED):
    data = parser.parse_config(ET.tostring(root))
    data["licenses"] = licenses
    return data


def _keys(data, rule_id):
    return sorted(i["key"] for i in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def _findings(data):
    return {rid: _keys(data, rid) for rid in RULE_IDS if _keys(data, rid)}


def _set(root, path, text):
    root.find(path).text = text


def _sub(root, path, tag, text=None, **attrs):
    el = ET.SubElement(root.find(path), tag, **attrs)
    el.text = text
    return el


def _members(root, path, tag, *values):
    el = ET.SubElement(root.find(path), tag)
    for v in values:
        ET.SubElement(el, "member").text = v


def _remove(root, path):
    parent, _, tag = path.rpartition("/")
    root.find(parent).remove(root.find(path))


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    data = _data(_root())
    lf = data["log_forwarding_profiles"]
    assert [p["name"] for p in lf] == ["lf-all"]
    assert {m["log_type"]: m["destinations"] for m in lf[0]["lists"]}["auth"] == ["syslog:siem"]
    dp = {p["name"]: p for p in data["decryption"]["profiles"]}
    assert all(dp["dp-inbound"]["inbound_checks"].values()) and all(dp["dp-ssh"]["ssh_checks"].values())
    assert dp["dp-ssh"]["auth_algo_sha1"] is False and dp["dp-ssh"]["auth_algo_md5"] is False


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: ET.SubElement(_sub(r, f"{P}/virus/entry", "threat-exception"), "entry", name="12345"),
     {"profile_threat_exceptions": ["antivirus:av"]}),
    (lambda r: ET.SubElement(_sub(r, f"{P}/virus/entry", "application"), "entry", name="dropbox"),
     {"profile_threat_exceptions": ["antivirus:av"]}),
    (lambda r: ET.SubElement(_sub(r, f"{P}/spyware/entry", "threat-exception"), "entry", name="13579"),
     {"profile_threat_exceptions": ["spyware:as"]}),
    (lambda r: ET.SubElement(_sub(r, f"{P}/vulnerability/entry", "threat-exception"), "entry", name="30001"),
     {"profile_threat_exceptions": ["vulnerability:vp"]}),
    (lambda r: _set(r, f"{P}/virus/entry/packet-capture", "yes"), {"av_packet_capture": ["av"]}),
    (lambda r: _set(r, f"{URL}/log-container-page-only", "yes"), {"url_log_container_page_only": ["url"]}),
    (lambda r: _members(r, URL, "allow", "shopping"), {"url_categories_allowed_unlogged": ["url"]}),
    (lambda r: (_remove(r, f"{URL}/credential-enforcement/mode/domain-credentials"),
                ET.SubElement(r.find(f"{URL}/credential-enforcement/mode"), "ip-user")),
     {"url_credential_detection_not_domain": ["url"]}),
    (lambda r: _members(r, f"{URL}/credential-enforcement", "allow", "business-and-economy"),
     {"url_credential_submissions_unlogged": ["url"]}),
    (lambda r: _set(r, f"{URL}/cloud-inline-cat", "no"), {"url_inline_categorization_off": ["url"]}),
    (lambda r: _set(r, f"{P}/decryption/entry[@name='dp-inbound']/ssl-inbound-proxy/block-unsupported-cipher", "no"),
     {"decryption_inbound_checks_off": ["dp-inbound"]}),
    (lambda r: _set(r, f"{P}/decryption/entry[@name='dp-ssh']/ssh-proxy/block-ssh-errors", "no"),
     {"decryption_ssh_checks_off": ["dp-ssh"]}),
    # SHA-1 is allowed unless turned off.
    (lambda r: _remove(r, f"{P}/decryption/entry[@name='dp-ssh']/ssl-protocol-settings/auth-algo-sha1"),
     {"decryption_weak_hmac": ["dp-ssh"]}),
    (lambda r: _set(r, f"{P}/decryption/entry[@name='dp-inbound']/ssl-protocol-settings/auth-algo-md5", "yes"),
     {"decryption_weak_hmac": ["dp-inbound"]}),
    (lambda r: _remove(r, f"{LF}/match-list/entry[@name='url']"), {"log_forwarding_profile_missing_types": ["lf-all"]}),
    (lambda r: [_set(r, f"{LF}/match-list/entry[@name='{n}']/send-to-panorama", "no")
                for n in ("traffic", "threat", "wildfire", "url")] and
               _remove(r, f"{LF}/match-list/entry[@name='auth']/send-syslog"),
     {"log_forwarding_profile_no_destination": ["lf-all"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_decryption_checks_judge_every_profile_on_every_mode():
    # Palo Alto SCM grades each profile's inbound and SSH options whatever its rules decrypt, and
    # grades profiles no rule uses; so do the core rules.
    root = _root()
    _set(root, f"{P}/decryption/entry[@name='dp-ssh']/ssl-inbound-proxy/block-unsupported-version", "no")
    _set(root, f"{P}/decryption/entry[@name='dp-inbound']/ssh-proxy/block-ssh-errors", "no")
    found = _findings(_data(root))
    assert found["decryption_inbound_checks_off"] == ["dp-ssh"]
    assert found["decryption_ssh_checks_off"] == ["dp-inbound"]


def test_inline_categorization_skipped_only_without_advanced_url_license():
    root = _root()
    _set(root, f"{URL}/cloud-inline-cat", "no")
    # License unknown (config export): flagged, noting it applies if licensed.
    assert _findings(_data(root, {"available": False, "licenses": []})) == {"url_inline_categorization_off": ["url"]}
    # Known to have only plain URL Filtering: skipped.
    assert _findings(_data(root, {"available": True, "licenses": [
        {"feature": "PAN-DB URL Filtering", "expired": "no"}]})) == {}


def test_unused_log_forwarding_profile_is_ignored():
    root = _root()
    ET.SubElement(root.find("shared/log-settings/profiles"), "entry", name="lf-empty")
    assert _findings(_data(root)) == {}


def test_findings_carry_scm_objects():
    root = _root()
    _set(root, f"{URL}/log-container-page-only", "yes")
    assert checks.CHECKS["url_log_container_page_only"](_data(root), {})[0]["scm_object"] == {
        "type": "url_filtering_profile", "name": "url"}


def test_assessment_parsed_before_these_existed_is_left_alone():
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": [], "licenses": LICENSED}, RULES_BY_ID[rid].thresholds) == []


def test_rules_link_their_scm_checks():
    for rid in RULE_IDS:
        assert SCM_MATCHES[rid]
    assert 206 in SCM_MATCHES["av_decoder_below_baseline"]

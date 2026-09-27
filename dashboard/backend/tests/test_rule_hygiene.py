"""Security rule checks ported from Palo Alto SCM: parsing and checks."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID, SCM_MATCHES

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "rule_hygiene.xml")
RULE_IDS = ["security_rule_log_at_start", "security_rule_server_response_inspection_off", "default_rule_not_logged",
            "user_id_zone_disabled", "no_new_appid_rule", "advanced_profile_not_applied"]
VSYS = "devices/entry/vsys/entry"
RULE = f"{VSYS}/rulebase/security/rules/entry[@name='staff-web']"
DEFAULTS = f"{VSYS}/rulebase/default-security-rules/rules"
ADVANCED = {"available": True, "licenses": [
    {"feature": f, "expired": "no"} for f in
    ("Advanced URL Filtering", "Advanced Threat Prevention", "Advanced WildFire License")]}


def _root():
    return ET.parse(FIXTURE).getroot()


def _data(root, licenses=ADVANCED):
    data = parser.parse_config(ET.tostring(root))
    data["licenses"] = licenses
    return data


def _keys(data, rule_id):
    return sorted(i["key"] for i in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def _findings(data):
    return {rid: _keys(data, rid) for rid in RULE_IDS if _keys(data, rid)}


def _set(root, path, text):
    root.find(path).text = text


def _add(root, path, tag, text):
    ET.SubElement(root.find(path), tag).text = text


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    data = _data(_root())
    assert data["default_rule_logging"] == {"intrazone-default": True, "interzone-default": True}
    assert {z["name"]: z["user_id"] for z in data["zones"]} == {"users": True, "untrust": False}
    assert data["policy_objects"]["new_appid_filters"] == ["new-apps"]


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _add(r, RULE, "log-start", "yes"), {"security_rule_log_at_start": ["staff-web"]}),
    (lambda r: ET.SubElement(ET.SubElement(r.find(RULE), "option"), "disable-server-response-inspection").__setattr__("text", "yes"),
     {"security_rule_server_response_inspection_off": ["staff-web"]}),
    (lambda r: _set(r, f"{DEFAULTS}/entry[@name='interzone-default']/log-end", "no"),
     {"default_rule_not_logged": ["interzone-default"]}),
    # No override at all: neither predefined rule logs (what Palo Alto SCM checks #12/#13 fail).
    (lambda r: r.find(f"{VSYS}/rulebase").remove(r.find(f"{VSYS}/rulebase/default-security-rules")),
     {"default_rule_not_logged": ["interzone-default", "intrazone-default"]}),
    (lambda r: _set(r, f"{VSYS}/zone/entry[@name='users']/enable-user-identification", "no"),
     {"user_id_zone_disabled": ["users"]}),
    (lambda r: _set(r, f"{VSYS}/application-filter/entry/new-appid", "no"), {"no_new_appid_rule": ["global"]}),
    (lambda r: _set(r, f"{VSYS}/profiles/wildfire-analysis/entry/cloud-inline-analysis", "no"),
     {"advanced_profile_not_applied": ["wildfire_analysis"]}),
    (lambda r: _set(r, f"{VSYS}/profiles/url-filtering/entry/cloud-inline-cat", "no"),
     {"advanced_profile_not_applied": ["url_filtering"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_user_id_only_matters_for_rules_matching_specific_users():
    root = _root()
    _set(root, f"{VSYS}/zone/entry[@name='users']/enable-user-identification", "no")
    _set(root, f"{RULE}/source-user/member", "known-user")
    assert _findings(_data(root)) == {}


def test_advanced_services_need_their_license():
    root = _root()
    for tag, path in (("cloud-inline-cat", "url-filtering"), ("cloud-inline-analysis", "wildfire-analysis")):
        _set(root, f"{VSYS}/profiles/{path}/entry/{tag}", "no")
    assert _findings(_data(root, {"available": False, "licenses": []})) == {}
    only_wf = {"available": True, "licenses": [{"feature": "Advanced WildFire License", "expired": "no"}]}
    assert _findings(_data(root, only_wf)) == {"advanced_profile_not_applied": ["wildfire_analysis"]}


def test_disabled_rules_dont_count():
    root = _root()
    _add(root, f"{VSYS}/rulebase/security/rules/entry[@name='new-appids']", "disabled", "yes")
    assert _findings(_data(root)) == {"no_new_appid_rule": ["global"]}


def test_panorama_default_rules_from_post_rulebase():
    fw = _root()
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='branch'/></device-group></entry></devices></config>")
    dg = pano.find("devices/entry/device-group/entry")
    ET.SubElement(dg, "pre-rulebase").append(copy.deepcopy(fw.find(f"{VSYS}/rulebase/security")))
    ET.SubElement(dg, "post-rulebase").append(copy.deepcopy(fw.find(f"{VSYS}/rulebase/default-security-rules")))
    data = panorama_parser.build_assessment_data(pano, "branch")
    assert data["default_rule_logging"] == {"intrazone-default": True, "interzone-default": True}
    assert _keys(data, "default_rule_not_logged") == []


def test_assessment_parsed_before_these_existed_is_left_alone():
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": [], "zones": [], "licenses": ADVANCED},
                                  RULES_BY_ID[rid].thresholds) == []


def test_rules_link_their_scm_checks():
    for rid in RULE_IDS:
        assert SCM_MATCHES[rid]

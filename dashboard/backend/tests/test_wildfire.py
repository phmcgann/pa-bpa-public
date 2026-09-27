"""WildFire checks ported from Palo Alto SCM: parsing and checks, including license/version gating."""
import os
import xml.etree.ElementTree as ET

import pytest

from app import parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID, SCM_MATCHES

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "wildfire_hardened.xml")
RULE_IDS = ["wildfire_size_limit_below_default", "wildfire_grayware_not_reported",
            "wildfire_inline_cloud_analysis_disabled", "wildfire_realtime_hold_off"]
WF = "devices/entry/deviceconfig/setting/wildfire"
PROFILES = "devices/entry/vsys/entry/profiles"
LICENSED = {"available": True, "licenses": [
    {"feature": "Advanced WildFire License", "expired": "no", "expires": "December 31, 2027"}]}


def _data(root, licenses=LICENSED, version="11.1.4"):
    data = parser.parse_config(ET.tostring(root))
    data["licenses"] = licenses
    data["system_info"] = {**data["system_info"], "sw_version": version}
    return data


def _root():
    return ET.parse(FIXTURE).getroot()


def _keys(data, rule_id):
    return sorted(i["key"] for i in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def _findings(data):
    return {rid: _keys(data, rid) for rid in RULE_IDS if _keys(data, rid)}


def _set(root, path, text):
    root.find(path).text = text


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    data = _data(_root())
    assert data["device_settings"]["wildfire"] == {
        "size_limits": {"pe": 16, "pdf": 3072, "MacOSX": 10, "archive": 50}, "report_grayware": True}
    av = data["security_profiles"]["antivirus"][0]
    assert av["settings"]["wfrt_hold_mode"] is True
    assert data["security_profiles"]["wildfire_analysis"][0]["settings"]["inline_cloud_analysis"] is True


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _set(r, f"{WF}/file-size-limit/entry[@name='pe']/size-limit", "2"),
     {"wildfire_size_limit_below_default": ["pe"]}),
    # Case of the entry name doesn't matter; units are the file type's own (KB for pdf).
    (lambda r: (_set(r, f"{WF}/file-size-limit/entry[@name='MacOSX']/size-limit", "5"),
                _set(r, f"{WF}/file-size-limit/entry[@name='pdf']/size-limit", "1024")),
     {"wildfire_size_limit_below_default": ["macosx", "pdf"]}),
    # Raising a limit above the default is allowed.
    (lambda r: _set(r, f"{WF}/file-size-limit/entry[@name='pe']/size-limit", "50"), {}),
    (lambda r: _set(r, f"{WF}/report-grayware-file", "no"), {"wildfire_grayware_not_reported": ["global"]}),
    (lambda r: _set(r, f"{PROFILES}/wildfire-analysis/entry/cloud-inline-analysis", "no"),
     {"wildfire_inline_cloud_analysis_disabled": ["wf-all"]}),
    (lambda r: _set(r, f"{PROFILES}/virus/entry/wfrt-hold-mode", "no"), {"wildfire_realtime_hold_off": ["global"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_unset_wildfire_settings():
    """No size limits set means PAN-OS defaults apply; grayware reporting is off by default."""
    root = _root()
    root.find("devices/entry/deviceconfig/setting").remove(root.find(WF))
    assert _findings(_data(root)) == {"wildfire_grayware_not_reported": ["global"]}


@pytest.mark.parametrize("licenses, version, expected", [
    # Unknown license (plain config export): both run, as Palo Alto SCM's do, noting the license.
    ({"available": False, "licenses": []}, "11.1.4",
     {"wildfire_inline_cloud_analysis_disabled": ["wf-all"], "wildfire_realtime_hold_off": ["global"]}),
    # Plain WildFire: hold mode applies, Inline Cloud Analysis (Advanced WildFire only) doesn't.
    ({"available": True, "licenses": [{"feature": "WildFire License", "expired": "no"}]}, "11.1.4",
     {"wildfire_realtime_hold_off": ["global"]}),
    # Expired license counts as none.
    ({"available": True, "licenses": [{"feature": "Advanced WildFire License", "expired": "yes"}]}, "11.1.4", {}),
    # Hold mode doesn't exist before PAN-OS 11.0.2.
    (LICENSED, "10.2.9-h1", {"wildfire_inline_cloud_analysis_disabled": ["wf-all"]}),
    (LICENSED, "11.1.4", {"wildfire_inline_cloud_analysis_disabled": ["wf-all"], "wildfire_realtime_hold_off": ["global"]}),
])
def test_license_and_version_gating(licenses, version, expected):
    root = _root()
    _set(root, f"{PROFILES}/wildfire-analysis/entry/cloud-inline-analysis", "no")
    _set(root, f"{PROFILES}/virus/entry/wfrt-hold-mode", "no")
    assert _findings(_data(root, licenses, version)) == expected


def test_hold_mode_judged_on_unused_profiles_too():
    root = _root()
    ET.SubElement(root.find(f"{PROFILES}/virus"), "entry", name="av-unused")
    assert _findings(_data(root)) == {"wildfire_realtime_hold_off": ["global"]}


def test_unknown_license_is_noted_in_the_message():
    root = _root()
    _set(root, f"{PROFILES}/wildfire-analysis/entry/cloud-inline-analysis", "no")
    [f] = checks.CHECKS["wildfire_inline_cloud_analysis_disabled"](
        _data(root, {"available": False, "licenses": []}, "11.1.4"), {})
    assert f["message"].endswith("(if the firewall has an Advanced WildFire license)")


def test_assessment_parsed_before_these_existed_is_left_alone():
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": [], "licenses": LICENSED}, RULES_BY_ID[rid].thresholds) == []


def test_rules_link_their_scm_checks():
    assert SCM_MATCHES["wildfire_size_limit_below_default"] == (109, 110, 111, 112, 113, 114, 115, 204, 205, 251, 361)
    for rid in RULE_IDS:
        assert SCM_MATCHES[rid]

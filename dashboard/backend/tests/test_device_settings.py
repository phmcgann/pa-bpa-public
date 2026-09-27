"""Device and session settings ported from Palo Alto SCM checks: parsing and checks."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID, SCM_MATCHES

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "device_hardened.xml")
RULE_IDS = ["session_timeout_changed", "session_accelerated_aging_off", "packet_buffer_protection_global_off",
            "cert_expiration_check_off", "log_high_dp_load_off", "telemetry_disabled",
            "update_server_verification_off", "mgmt_interface_cleartext", "ha_timers_not_recommended",
            "gre_keepalive_off", "pbf_no_monitor", "app_override_rule"]
DC = "devices/entry/deviceconfig"
SESSION = f"{DC}/setting/session"
RB = "devices/entry/vsys/entry/rulebase"


def _root():
    return ET.parse(FIXTURE).getroot()


def _data(root):
    return parser.parse_config(ET.tostring(root))


def _keys(data, rule_id):
    return sorted(i["key"] for i in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def _findings(data):
    return {rid: _keys(data, rid) for rid in RULE_IDS if _keys(data, rid)}


def _set(root, path, text):
    root.find(path).text = text


def _add(root, path, tag, text=None):
    el = ET.SubElement(root.find(path), tag)
    el.text = text
    return el


def _app_override(root):
    ao = ET.SubElement(ET.SubElement(ET.SubElement(root.find(RB), "application-override"), "rules"), "entry",
                       name="override-9999")
    for tag, text in (("protocol", "tcp"), ("port", "9999"), ("application", "custom-app")):
        ET.SubElement(ao, tag).text = text


def _replace_timers(root, tag):
    timers = root.find(f"{DC}/high-availability/group/election-option/timers")
    timers.remove(timers[0])
    ET.SubElement(timers, tag)


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _set(r, f"{SESSION}/timeout-tcp", "7200"), {"session_timeout_changed": ["timeout-tcp"]}),
    (lambda r: _add(r, SESSION, "timeout-tcp-half-closed", "600"), {"session_timeout_changed": ["timeout-tcp-half-closed"]}),
    (lambda r: _set(r, f"{SESSION}/accelerated-aging-enable", "no"), {"session_accelerated_aging_off": ["global"]}),
    (lambda r: _set(r, f"{SESSION}/packet-buffer-protection-enable", "no"),
     {"packet_buffer_protection_global_off": ["global"]}),
    (lambda r: _set(r, f"{DC}/setting/management/enable-certificate-expiration-check", "no"),
     {"cert_expiration_check_off": ["global"]}),
    (lambda r: _set(r, f"{DC}/setting/management/enable-log-high-dp-load", "no"), {"log_high_dp_load_off": ["global"]}),
    (lambda r: _set(r, f"{DC}/system/device-telemetry/threat-prevention", "no"), {"telemetry_disabled": ["global"]}),
    (lambda r: _set(r, f"{DC}/system/server-verification", "no"), {"update_server_verification_off": ["global"]}),
    (lambda r: _set(r, f"{DC}/system/service/disable-telnet", "no"), {"mgmt_interface_cleartext": ["global"]}),
    (lambda r: _replace_timers(r, "aggressive"), {"ha_timers_not_recommended": ["global"]}),
    (lambda r: _set(r, "devices/entry/network/tunnel/gre/entry/keep-alive/enable", "no"), {"gre_keepalive_off": ["gre-dc"]}),
    (lambda r: r.find(f"{RB}/pbf/rules/entry/action/forward").remove(r.find(f"{RB}/pbf/rules/entry/action/forward/monitor")),
     {"pbf_no_monitor": ["isp2"]}),
    (_app_override, {"app_override_rule": ["override-9999"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_unset_settings_use_pan_os_defaults():
    """Unset: accelerated aging, PBP, server verification on; mgmt HTTP/Telnet, telemetry-off not
    assumed; HA timers Recommended. Certificate-expiration check and the high-DP-load log are off
    by default, which is what Palo Alto SCM flags too."""
    root = ET.fromstring("<config><devices><entry name='localhost.localdomain'><deviceconfig>"
                         "<high-availability><enabled>yes</enabled></high-availability>"
                         "</deviceconfig></entry></devices></config>")
    assert _findings(_data(root)) == {"cert_expiration_check_off": ["global"], "log_high_dp_load_off": ["global"]}


def test_old_misnamed_packet_buffer_element_is_ignored():
    """<packet-buffer-protection> isn't the PAN-OS element (it's packet-buffer-protection-enable);
    Palo Alto SCM passes a config that sets only the former to "no"."""
    root = _root()
    session = root.find(SESSION)
    session.remove(session.find("packet-buffer-protection-enable"))
    ET.SubElement(session, "packet-buffer-protection").text = "no"
    assert _findings(_data(root)) == {}


def test_disabled_pbf_gre_and_override_are_skipped():
    root = _root()
    _set(root, "devices/entry/network/tunnel/gre/entry/keep-alive/enable", "no")
    _add(root, "devices/entry/network/tunnel/gre/entry", "disabled", "yes")
    _app_override(root)
    _add(root, f"{RB}/application-override/rules/entry", "disabled", "yes")
    assert _findings(_data(root)) == {}


def test_findings_carry_scm_objects():
    root = _root()
    _app_override(root)
    obj = checks.CHECKS["app_override_rule"](_data(root), {})[0]["scm_object"]
    assert obj == {"type": "app_override", "name": "override-9999"}


def test_assessment_parsed_before_these_existed_is_left_alone():
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": []}, RULES_BY_ID[rid].thresholds) == []


def test_panorama_template_and_device_group():
    fw = _root()
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='branch'><reference-templates><member>stk</member></reference-templates>"
        "</entry></device-group>"
        "<template><entry name='base'/></template>"
        "<template-stack><entry name='stk'><templates><member>base</member></templates></entry></template-stack>"
        "</entry></devices></config>")
    base = ET.SubElement(pano.find("devices/entry/template/entry[@name='base']"), "config")
    base.append(copy.deepcopy(fw.find("devices")))
    dg = pano.find("devices/entry/device-group/entry[@name='branch']")
    ET.SubElement(dg, "pre-rulebase").append(copy.deepcopy(fw.find(f"{RB}/pbf")))
    data = panorama_parser.build_assessment_data(pano, "branch")
    assert [r["name"] for r in data["misc_policy"]["pbf_rules"]] == ["isp2"]
    assert _findings(data) == {}

    _set(base, f"{SESSION}/timeout-udp", "300")
    dg.find("pre-rulebase/pbf/rules/entry/action/forward").remove(dg.find("pre-rulebase/pbf/rules/entry/action/forward/monitor"))
    assert _findings(panorama_parser.build_assessment_data(pano, "branch")) == {
        "session_timeout_changed": ["timeout-udp"], "pbf_no_monitor": ["isp2"]}


def test_every_ported_rule_links_its_scm_check():
    for rid in RULE_IDS:
        assert SCM_MATCHES[rid], rid
        assert RULES_BY_ID[rid].source_type == "custom" or "docs.paloaltonetworks.com" in (RULES_BY_ID[rid].source_ref or "")
    assert SCM_MATCHES["zone_packet_buffer_protection_off"] == (212,)


def test_panorama_device_group_without_templates_parses():
    pano = ET.fromstring("<config><shared/><devices><entry name='localhost.localdomain'>"
                         "<device-group><entry name='branch'/></device-group></entry></devices></config>")
    data = panorama_parser.build_assessment_data(pano, "branch")
    assert data["device_settings"]["server_verification"] is True

"""Management-plane hardening: parsing (firewall and Panorama template paths) and checks."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "mgmt_plane_hardened.xml")
RULE_IDS = ["admin_lockout_weak", "admin_idle_timeout_long", "api_key_no_lifetime", "password_complexity_weak",
            "mgmt_tls_below_1_2", "snmp_v2c", "ldap_profile_no_tls", "radius_weak_protocol", "tacacs_pap",
            "syslog_not_tls", "system_logs_not_forwarded", "config_logs_not_forwarded",
            "content_updates_not_timely"]


def _root():
    return ET.parse(FIXTURE).getroot()


def _data(root):
    return parser.parse_config(ET.tostring(root))


def _keys(data, rule_id):
    return sorted(i["key"] for i in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def _findings(data):
    return {rid: _keys(data, rid) for rid in RULE_IDS if _keys(data, rid)}


def _set(root, path, text):
    el = root.find(path)
    el.text = text


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    mp = _data(_root())["mgmt_plane"]
    assert (mp["idle_timeout_min"], mp["failed_attempts"], mp["lockout_minutes"], mp["api_key_lifetime_min"]) == (
        10, 5, 30, 43200)
    assert mp["update_schedule"]["wildfire"]["frequency"] == "real-time"
    assert mp["radius"] == [{"name": "corp-radius", "protocol": "PEAP-MSCHAPv2"}]
    assert mp["mgmt_tls"] == {"profile": "mgmt-tls", "found": True, "min_version": "tls1-2"}
    assert mp["log_forwarding"]["config"][0]["destinations"] == ["panorama"]


MGMT = "devices/entry/deviceconfig/setting/management"


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _set(r, f"{MGMT}/admin-lockout/failed-attempts", "0"), {"admin_lockout_weak": ["failed_attempts"]}),
    (lambda r: _set(r, f"{MGMT}/admin-lockout/failed-attempts", "10"), {"admin_lockout_weak": ["failed_attempts"]}),
    (lambda r: _set(r, f"{MGMT}/admin-lockout/lockout-time", "5"), {"admin_lockout_weak": ["lockout_time"]}),
    (lambda r: _set(r, f"{MGMT}/admin-lockout/lockout-time", "0"), {}),   # 0 = until manually unlocked
    (lambda r: r.find(MGMT).remove(r.find(f"{MGMT}/idle-timeout")), {"admin_idle_timeout_long": ["global"]}),  # default 60
    (lambda r: _set(r, f"{MGMT}/idle-timeout", "0"), {"admin_idle_timeout_long": ["global"]}),
    (lambda r: _set(r, f"{MGMT}/api/key/lifetime", "0"), {"api_key_no_lifetime": ["global"]}),
    (lambda r: _set(r, "mgt-config/password-complexity/enabled", "no"), {"password_complexity_weak": ["global"]}),
    (lambda r: _set(r, "mgt-config/password-complexity/minimum-length", "8"), {"password_complexity_weak": ["global"]}),
    (lambda r: _set(r, "shared/ssl-tls-service-profile/entry/protocol-settings/min-version", "tls1-1"),
     {"mgmt_tls_below_1_2": ["global"]}),
    (lambda r: _set(r, "shared/server-profile/ldap/entry/ssl", "no"), {"ldap_profile_no_tls": ["corp-ldap"]}),
    (lambda r: _set(r, "shared/server-profile/ldap/entry/verify-server-certificate", "no"),
     {"ldap_profile_no_tls": ["corp-ldap"]}),
    (lambda r: _set(r, "shared/server-profile/tacplus/entry/protocol", "PAP"), {"tacacs_pap": ["corp-tacacs"]}),
    (lambda r: _set(r, "shared/log-settings/syslog/entry/server/entry/transport", "UDP"), {"syslog_not_tls": ["siem"]}),
    (lambda r: r.find("shared/log-settings/system/match-list/entry").remove(
        r.find("shared/log-settings/system/match-list/entry/send-syslog")), {"system_logs_not_forwarded": ["global"]}),
    (lambda r: r.find("shared/log-settings").remove(r.find("shared/log-settings/config")),
     {"config_logs_not_forwarded": ["global"]}),
    (lambda r: _set(r, "devices/entry/deviceconfig/system/update-schedule/threats/recurring/every-30-mins/action",
                    "download-only"), {"content_updates_not_timely": ["threats"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_radius_pap_and_snmp_v2c_with_default_community():
    root = _root()
    proto = root.find("shared/server-profile/radius/entry/protocol")
    proto.remove(list(proto)[0])
    ET.SubElement(proto, "PAP")
    version = root.find("devices/entry/deviceconfig/system/snmp-setting/access-setting/version")
    version.remove(list(version)[0])
    ET.SubElement(ET.SubElement(version, "v2c"), "snmp-community-string").text = "public"
    data = _data(root)
    assert _findings(data) == {"radius_weak_protocol": ["corp-radius"], "snmp_v2c": ["polling"]}
    assert "'public'" in checks.check_snmp_v2c(data, {})[0]["message"]


def test_update_schedule_frequency_floors():
    root = _root()
    sched = root.find("devices/entry/deviceconfig/system/update-schedule")
    av = sched.find("anti-virus/recurring")
    av.remove(av.find("hourly"))
    ET.SubElement(ET.SubElement(av, "daily"), "action").text = "download-and-install"
    wf = sched.find("wildfire/recurring")
    wf.remove(wf.find("real-time"))
    ET.SubElement(ET.SubElement(wf, "every-min"), "action").text = "download-and-install"   # every minute is fine
    sched.remove(sched.find("threats"))                                                       # no schedule at all
    data = _data(root)
    assert _keys(data, "content_updates_not_timely") == ["anti-virus", "threats"]


def test_assessment_parsed_before_mgmt_plane_existed_is_left_alone():
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": []}, RULES_BY_ID[rid].thresholds) == []


def test_panorama_template_stack_resolves_the_same_settings():
    fw = _root()
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='branch'><reference-templates><member>stk</member></reference-templates></entry></device-group>"
        "<template><entry name='base'/><entry name='override'/></template>"
        "<template-stack><entry name='stk'><templates><member>override</member><member>base</member></templates></entry></template-stack>"
        "</entry></devices></config>")
    base = ET.SubElement(pano.find("devices/entry/template/entry[@name='base']"), "config")
    for tag in ("mgt-config", "shared", "devices"):
        base.append(copy.deepcopy(fw.find(tag)))
    # A template listed higher in the stack overrides one setting.
    override = ET.SubElement(pano.find("devices/entry/template/entry[@name='override']"), "config")
    mgmt = ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(
        override, "devices"), "entry", name="localhost.localdomain"), "deviceconfig"), "setting"), "management")
    ET.SubElement(mgmt, "idle-timeout").text = "120"
    pdata = panorama_parser.build_assessment_data(pano, "branch")
    assert pdata["mgmt_plane"]["idle_timeout_min"] == 120
    assert _findings(pdata) == {"admin_idle_timeout_long": ["global"]}


def test_management_rules_are_cited_or_labelled_custom():
    for rid in RULE_IDS:
        r = RULES_BY_ID[rid]
        assert (r.source_type == "pan_docs") == bool(r.source_ref)
        if r.source_type == "pan_docs":
            assert "administrative-access-best-practices" in r.source_ref
        assert r.scm_check_ids or rid == "mgmt_tls_below_1_2"

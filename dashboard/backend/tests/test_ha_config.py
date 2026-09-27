"""High-availability configuration: parsing (firewall and Panorama template paths) and checks."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "ha_hardened.xml")
RULE_IDS = ["ha_config_sync_disabled", "ha_session_sync_disabled", "ha2_keepalive_disabled",
            "ha1_encryption_disabled", "ha1_no_backup", "ha_heartbeat_backup_off",
            "ha_passive_link_state_shutdown", "ha_no_monitoring", "ha_active_active_incomplete"]
HA = "devices/entry/deviceconfig/high-availability"
G = f"{HA}/group"


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


def _remove(root, path):
    parent_path, _, tag = path.rpartition("/")
    parent = root.find(parent_path)
    parent.remove(parent.find(tag))


def test_hardened_pair_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    ha = _data(_root())["ha_config"]
    assert ha["enabled"] and ha["mode"] == "active-passive"
    assert (ha["group_id"], ha["peer_ip"], ha["peer_ip_backup"]) == ("7", "10.255.0.2", "10.255.1.2")
    assert (ha["ha1_port"], ha["ha1_backup_port"], ha["ha2_port"]) == ("ha1-a", "ha1-b", "hsci")
    assert ha["timers"] == "recommended"
    assert ha["link_monitoring"]["groups"] == [
        {"name": "data-links", "interfaces": ["ethernet1/1", "ethernet1/2"], "failure_condition": "any"}]
    assert ha["path_monitoring"]["groups"] == [{"type": "virtual-router", "name": "default"}]


def test_defaults_when_only_enabled():
    root = ET.fromstring("<config><devices><entry name='localhost.localdomain'><deviceconfig>"
                         "<high-availability><enabled>yes</enabled></high-availability>"
                         "</deviceconfig></entry></devices></config>")
    data = _data(root)
    ha = data["ha_config"]
    assert ha["config_sync"] and ha["session_sync"] and not ha["ha2_keep_alive"]
    assert ha["passive_link_state"] == "shutdown" and ha["timers"] == "recommended"
    # No HA1 port known: heartbeat backup can't be judged, so it isn't flagged.
    assert _findings(data) == {
        "ha2_keepalive_disabled": ["global"], "ha1_encryption_disabled": ["global"],
        "ha1_no_backup": ["global"], "ha_passive_link_state_shutdown": ["global"],
        "ha_no_monitoring": ["global"]}


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _set(r, f"{G}/configuration-synchronization/enabled", "no"), {"ha_config_sync_disabled": ["global"]}),
    (lambda r: _set(r, f"{G}/state-synchronization/enabled", "no"), {"ha_session_sync_disabled": ["global"]}),
    (lambda r: _set(r, f"{G}/state-synchronization/ha2-keep-alive/enabled", "no"),
     {"ha2_keepalive_disabled": ["global"]}),
    (lambda r: _set(r, f"{HA}/interface/ha1/encryption/enabled", "no"), {"ha1_encryption_disabled": ["global"]}),
    (lambda r: _remove(r, f"{G}/peer-ip-backup"), {"ha1_no_backup": ["global"]}),
    (lambda r: _set(r, f"{G}/election-option/heartbeat-backup", "no"), {"ha_heartbeat_backup_off": ["global"]}),
    (lambda r: _set(r, f"{G}/mode/active-passive/passive-link-state", "shutdown"),
     {"ha_passive_link_state_shutdown": ["global"]}),
    # Timers are a deliberate choice (Aggressive/Advanced), left to SCM #142.
    (lambda r: (_remove(r, f"{G}/election-option/timers/recommended"),
                ET.SubElement(r.find(f"{G}/election-option/timers"), "aggressive")), {}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_heartbeat_backup_not_needed_when_ha1_uses_management_port():
    root = _root()
    _set(root, f"{G}/election-option/heartbeat-backup", "no")
    _set(root, f"{HA}/interface/ha1/port", "management")
    assert _findings(_data(root)) == {}


@pytest.mark.parametrize("mutate, flagged", [
    (lambda r: _remove(r, f"{G}/monitoring/path-monitoring/path-group"), False),
    (lambda r: _remove(r, f"{G}/monitoring/link-monitoring/link-group"), False),
    (lambda r: (_remove(r, f"{G}/monitoring/path-monitoring/path-group"),
                _remove(r, f"{G}/monitoring/link-monitoring/link-group")), True),
    # Groups exist but monitoring is switched off.
    (lambda r: (_set(r, f"{G}/monitoring/link-monitoring/enabled", "no"),
                _set(r, f"{G}/monitoring/path-monitoring/enabled", "no")), True),
    # A link group with no interfaces monitors nothing.
    (lambda r: (_remove(r, f"{G}/monitoring/path-monitoring/path-group"),
                _remove(r, f"{G}/monitoring/link-monitoring/link-group/entry/interface")), True),
])
def test_monitoring_needs_a_real_link_or_path_group(mutate, flagged):
    root = _root()
    mutate(root)
    assert bool(_keys(_data(root), "ha_no_monitoring")) == flagged


def test_active_active_needs_ha3_and_first_packet_ownership():
    root = _root()
    mode = root.find(f"{G}/mode")
    mode.remove(mode.find("active-passive"))
    aa = ET.SubElement(mode, "active-active")
    ET.SubElement(aa, "device-id").text = "0"
    owner = ET.SubElement(aa, "session-owner-selection")
    ET.SubElement(owner, "primary-device")
    data = _data(root)
    assert data["ha_config"]["mode"] == "active-active"
    # Passive link state only applies to active/passive.
    assert _findings(data) == {"ha_active_active_incomplete": ["ha3", "session_owner"]}

    owner.remove(owner.find("primary-device"))
    ET.SubElement(ET.SubElement(owner, "first-packet"), "session-setup")
    ET.SubElement(ET.SubElement(root.find(f"{HA}/interface"), "ha3"), "port").text = "ethernet1/8"
    assert _findings(_data(root)) == {}


def test_ha_disabled_or_missing_raises_nothing():
    root = _root()
    _set(root, f"{HA}/enabled", "no")
    _set(root, f"{G}/configuration-synchronization/enabled", "no")
    data = _data(root)
    assert data["ha_config"] == {"enabled": False}
    assert _findings(data) == {}
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": []}, RULES_BY_ID[rid].thresholds) == []


def test_panorama_template_stack_resolves_ha():
    fw = _root()
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='branch'><reference-templates><member>stk</member></reference-templates></entry></device-group>"
        "<template><entry name='base'/><entry name='override'/></template>"
        "<template-stack><entry name='stk'><templates><member>override</member><member>base</member></templates></entry></template-stack>"
        "</entry></devices></config>")
    base = ET.SubElement(pano.find("devices/entry/template/entry[@name='base']"), "config")
    base.append(copy.deepcopy(fw.find("devices")))
    pdata = panorama_parser.build_assessment_data(pano, "branch")
    assert pdata["ha_config"]["peer_ip_backup"] == "10.255.1.2"
    assert _findings(pdata) == {}

    # A template listed higher in the stack carrying its own HA section wins.
    override = ET.SubElement(pano.find("devices/entry/template/entry[@name='override']"), "config")
    ha = ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(
        override, "devices"), "entry", name="localhost.localdomain"), "deviceconfig"), "high-availability")
    ET.SubElement(ha, "enabled").text = "no"
    assert panorama_parser.build_assessment_data(pano, "branch")["ha_config"] == {"enabled": False}


def test_ha_rules_are_cited_or_labelled_custom():
    for rid in RULE_IDS:
        r = RULES_BY_ID[rid]
        assert (r.source_type == "pan_docs") == bool(r.source_ref)
        if r.source_type == "pan_docs":
            assert "configure-activepassive-ha" in r.source_ref
        assert r.scm_check_ids
        assert r.category == "High Availability"

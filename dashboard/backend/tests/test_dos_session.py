"""DoS Protection, zone packet-based/buffer protection and session settings: parsing and checks."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "dos_hardened.xml")
RULE_IDS = ["dos_no_protection", "dos_rule_not_protect", "dos_profile_flood_incomplete",
            "dos_profile_default_thresholds", "zone_protection_packet_based_off",
            "zone_packet_buffer_protection_off", "session_rematch_disabled", "tcp_forward_oo_queue"]
DEV = "devices/entry"
VSYS = f"{DEV}/vsys/entry"
PROFILE = f"{VSYS}/profiles/dos-protection/entry[@name='web-classified']"
RULE = f"{VSYS}/rulebase/dos/rules/entry[@name='protect-web']"
ZPP = f"{DEV}/network/profiles/zone-protection-profile/entry[@name='edge-zpp']"


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


def _replace_child(root, path, tag):
    el = root.find(path)
    for c in list(el):
        el.remove(c)
    ET.SubElement(el, tag)


def _set_rates(root, flood, method, alarm, activate, maximal):
    el = root.find(f"{PROFILE}/flood/{flood}/{method}")
    for tag, v in (("alarm-rate", alarm), ("activate-rate", activate), ("maximal-rate", maximal)):
        el.find(tag).text = str(v)


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    data = _data(_root())
    profile = data["dos"]["profiles"][0]
    assert profile["type"] == "classified" and all(profile["flood"].values())
    assert profile["rates"]["tcp-syn"] == {"method": "syn-cookies", "alarm": 2000, "activate": 3000,
                                            "max": 20000, "default": False}
    assert profile["session_limit"] == 50000
    assert data["dos"]["rules"] == [{"name": "protect-web", "scope": None, "action": "protect",
                                     "aggregate_profile": None, "classified_profile": "web-classified",
                                     "from": ["untrust"], "to": ["dmz"], "disabled": False}]
    assert {k: data["session_settings"][k] for k in ("rematch", "tcp_forward_oo_queue")} == {"rematch": True, "tcp_forward_oo_queue": False}
    assert all(data["zone_protection_profiles"][0]["packet_based"].values())


def _all_rates_default(r):
    _set_rates(r, "tcp-syn", "syn-cookies", 10000, 10000, 40000)
    for f in ("udp", "icmp", "icmpv6", "other-ip"):
        _set_rates(r, f, "red", 10000, 10000, 40000)


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _set(r, f"{PROFILE}/flood/icmpv6/enable", "no"), {"dos_profile_flood_incomplete": ["web-classified"]}),
    (_all_rates_default, {"dos_profile_default_thresholds": ["web-classified"]}),
    # One tuned flood type is enough to show thresholds were considered.
    (lambda r: _set_rates(r, "udp", "red", 10000, 10000, 40000), {}),
    (lambda r: _replace_child(r, f"{RULE}/action", "allow"),
     {"dos_rule_not_protect": ["protect-web"], "dos_no_protection": ["global"]}),
    (lambda r: r.find(RULE).remove(r.find(f"{RULE}/protection")),
     {"dos_rule_not_protect": ["protect-web"], "dos_no_protection": ["global"]}),
    (lambda r: ET.SubElement(r.find(RULE), "disabled").__setattr__("text", "yes"), {"dos_no_protection": ["global"]}),
    (lambda r: _set(r, f"{ZPP}/discard-tcp-split-handshake", "no"), {"zone_protection_packet_based_off": ["edge-zpp"]}),
    (lambda r: r.find(ZPP).remove(r.find(f"{ZPP}/remove-tcp-timestamp")),
     {"zone_protection_packet_based_off": ["edge-zpp"]}),
    (lambda r: _set(r, f"{VSYS}/zone/entry[@name='dmz']/network/enable-packet-buffer-protection", "no"),
     {"zone_packet_buffer_protection_off": ["dmz"]}),
    (lambda r: _set(r, f"{DEV}/deviceconfig/setting/config/rematch", "no"), {"session_rematch_disabled": ["global"]}),
    (lambda r: _set(r, f"{DEV}/deviceconfig/setting/tcp/bypass-exceed-oo-queue", "yes"),
     {"tcp_forward_oo_queue": ["global"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_unset_session_settings_use_pan_os_defaults():
    root = _root()
    root.find(f"{DEV}/deviceconfig").remove(root.find(f"{DEV}/deviceconfig/setting"))
    data = _data(root)
    assert {k: data["session_settings"][k] for k in ("rematch", "tcp_forward_oo_queue")} == {"rematch": True, "tcp_forward_oo_queue": False}
    assert _findings(data) == {}


def test_packet_based_options_judged_on_unassigned_profiles_too():
    root = _root()
    spare = copy.deepcopy(root.find(ZPP))
    spare.set("name", "spare-zpp")
    _set(spare, "discard-ip-spoof", "no")
    root.find(f"{DEV}/network/profiles/zone-protection-profile").append(spare)
    assert _findings(_data(root)) == {"zone_protection_packet_based_off": ["spare-zpp"]}


def test_findings_carry_scm_objects_for_per_object_overlap():
    root = _root()
    _set(root, f"{PROFILE}/flood/udp/enable", "no")
    _replace_child(root, f"{RULE}/action", "deny")
    data = _data(root)
    assert checks.CHECKS["dos_profile_flood_incomplete"](data, {})[0]["scm_object"] == {
        "type": "dos_protection_profile", "name": "web-classified"}
    assert checks.CHECKS["dos_rule_not_protect"](data, {})[0]["scm_object"] == {
        "type": "dos_protection_rule", "name": "protect-web"}


def test_assessment_parsed_before_dos_existed_is_left_alone():
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": [], "zones": []}, RULES_BY_ID[rid].thresholds) == []


def test_panorama_device_group_and_template_stack():
    fw = _root()
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='branch'><reference-templates><member>stk</member></reference-templates>"
        "</entry></device-group>"
        "<template><entry name='base'/></template>"
        "<template-stack><entry name='stk'><templates><member>base</member></templates></entry></template-stack>"
        "</entry></devices></config>")
    base = ET.SubElement(pano.find("devices/entry/template/entry[@name='base']"), "config")
    base_devices = ET.SubElement(base, "devices")
    tmpl_dev = copy.deepcopy(fw.find(DEV))
    tmpl_vsys = tmpl_dev.find("vsys/entry")
    tmpl_vsys.remove(tmpl_vsys.find("profiles"))
    tmpl_vsys.remove(tmpl_vsys.find("rulebase"))
    base_devices.append(tmpl_dev)
    dg = pano.find("devices/entry/device-group/entry[@name='branch']")
    dg.append(copy.deepcopy(fw.find(f"{VSYS}/profiles")))
    pre = ET.SubElement(dg, "pre-rulebase")
    pre.append(copy.deepcopy(fw.find(f"{VSYS}/rulebase/dos")))
    data = panorama_parser.build_assessment_data(pano, "branch")
    assert [r["scope"] for r in data["dos"]["rules"]] == ["device_group_pre"]
    assert {k: data["session_settings"][k] for k in ("rematch", "tcp_forward_oo_queue")} == {"rematch": True, "tcp_forward_oo_queue": False}
    assert _findings(data) == {}

    _set(base, "devices/entry/deviceconfig/setting/tcp/bypass-exceed-oo-queue", "yes")
    _set(dg, "profiles/dos-protection/entry/flood/icmp/enable", "no")
    assert _findings(panorama_parser.build_assessment_data(pano, "branch")) == {
        "dos_profile_flood_incomplete": ["web-classified"], "tcp_forward_oo_queue": ["global"]}


def test_dos_rules_are_cited_or_labelled_custom():
    for rid in RULE_IDS:
        r = RULES_BY_ID[rid]
        assert (r.source_type == "pan_docs") == bool(r.source_ref)
        if r.source_type == "pan_docs":
            assert "docs.paloaltonetworks.com" in r.source_ref

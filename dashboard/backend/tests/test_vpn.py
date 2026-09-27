"""Site-to-site VPN: parsing (firewall and Panorama template paths) and crypto/tunnel checks."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "vpn_hardened.xml")
RULE_IDS = ["vpn_weak_encryption", "vpn_weak_authentication", "vpn_weak_dh_group", "ike_aggressive_mode",
            "ike_v1_only", "vpn_manual_key", "vpn_lifetime_long", "vpn_anti_replay_disabled",
            "vpn_no_tunnel_monitor", "vpn_stale_config"]
NET = "devices/entry/network"
IKE = f"{NET}/ike/crypto-profiles/ike-crypto-profiles/entry[@name='strong-ike']"
IPSEC = f"{NET}/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='strong-ipsec']"
GW = f"{NET}/ike/gateway/entry[@name='dc-gw']"
TUN = f"{NET}/tunnel/ipsec/entry[@name='dc-tun']"


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


def _members(root, path, *values):
    el = root.find(path)
    for m in list(el):
        el.remove(m)
    for v in values:
        ET.SubElement(el, "member").text = v


def _add(root, path, tag, text=None):
    el = ET.SubElement(root.find(path), tag)
    el.text = text
    return el


def test_hardened_vpn_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    vpn = _data(_root())["vpn"]
    assert vpn["ike_profiles"] == [{"name": "strong-ike", "encryption": ["aes-256-gcm"], "hash": ["non-auth"],
                                    "dh_groups": ["group20"], "lifetime_hours": 8}]
    assert vpn["ipsec_profiles"][0]["dh_group"] == "group20"
    assert vpn["gateways"][0] | {} == {"name": "dc-gw", "version": "ikev2", "exchange_mode": "main",
                                        "ike_profiles": ["strong-ike"], "peer": "198.51.100.20",
                                        "auth": "pre-shared-key", "disabled": False}
    by_name = {t["name"]: t for t in vpn["tunnels"]}
    assert by_name["dc-tun"]["monitor"] and by_name["dc-tun"]["gateways"] == ["dc-gw"]
    assert by_name["gp-sat"]["type"] == "globalprotect-satellite"


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _members(r, f"{IKE}/encryption", "aes-256-gcm", "3des"), {"vpn_weak_encryption": ["ike:strong-ike"],
                                                                         "vpn_weak_authentication": ["ike:strong-ike"]}),
    (lambda r: _members(r, f"{IPSEC}/esp/encryption", "des"), {"vpn_weak_encryption": ["ipsec:strong-ipsec"],
                                                               "vpn_weak_authentication": ["ipsec:strong-ipsec"]}),
    (lambda r: _members(r, f"{IKE}/hash", "sha1"), {"vpn_weak_authentication": ["ike:strong-ike"]}),
    (lambda r: _members(r, f"{IPSEC}/esp/authentication", "sha256", "md5"),
     {"vpn_weak_authentication": ["ipsec:strong-ipsec"]}),
    # AES-CBC needs a real hash; "none" is only right with GCM.
    (lambda r: _members(r, f"{IPSEC}/esp/encryption", "aes-256-cbc"), {"vpn_weak_authentication": ["ipsec:strong-ipsec"]}),
    (lambda r: _members(r, f"{IKE}/dh-group", "group20", "group5"), {"vpn_weak_dh_group": ["ike:strong-ike"]}),
    (lambda r: _set(r, f"{IPSEC}/dh-group", "no-pfs"), {"vpn_weak_dh_group": ["ipsec:strong-ipsec"]}),
    (lambda r: _set(r, f"{IPSEC}/dh-group", "group2"), {"vpn_weak_dh_group": ["ipsec:strong-ipsec"]}),
    (lambda r: _set(r, f"{IPSEC}/dh-group", "group14"), {}),
    (lambda r: (_set(r, f"{GW}/protocol/version", "ikev1"), _set(r, f"{GW}/protocol/ikev1/exchange-mode", "aggressive")),
     {"ike_aggressive_mode": ["dc-gw"], "ike_v1_only": ["dc-gw"]}),
    # Aggressive mode is set but never used on an IKEv2-only gateway.
    (lambda r: _set(r, f"{GW}/protocol/ikev1/exchange-mode", "aggressive"), {}),
    (lambda r: (_set(r, f"{GW}/protocol/version", "ikev2-preferred"),
                _set(r, f"{GW}/protocol/ikev1/exchange-mode", "aggressive")), {"ike_aggressive_mode": ["dc-gw"]}),
    (lambda r: _set(r, f"{IKE}/lifetime/hours", "48"), {"vpn_lifetime_long": ["ike:strong-ike"]}),
    (lambda r: _set(r, f"{IPSEC}/lifetime/hours", "24"), {"vpn_lifetime_long": ["ipsec:strong-ipsec"]}),
    (lambda r: _add(r, TUN, "anti-replay", "no"), {"vpn_anti_replay_disabled": ["dc-tun"]}),
    (lambda r: _set(r, f"{TUN}/tunnel-monitor/enable", "no"), {"vpn_no_tunnel_monitor": ["dc-tun"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_referenced_built_in_default_profiles_are_judged():
    root = _root()
    _set(root, f"{GW}/protocol/ikev2/ike-crypto-profile", "default")
    auto_key = root.find(f"{TUN}/auto-key")
    auto_key.remove(auto_key.find("ipsec-crypto-profile"))
    data = _data(root)
    assert {p["name"]: p.get("built_in") for p in data["vpn"]["ike_profiles"]} == {"default": True, "strong-ike": None}
    assert _findings(data) == {
        "vpn_weak_encryption": ["ike:default", "ipsec:default"],
        "vpn_weak_authentication": ["ike:default", "ipsec:default"],
        "vpn_weak_dh_group": ["ike:default", "ipsec:default"],
    }


def test_weak_profiles_that_nothing_uses_are_not_flagged():
    root = _root()
    weak = copy.deepcopy(root.find(IKE))
    weak.set("name", "old-ike")
    root.find(f"{NET}/ike/crypto-profiles/ike-crypto-profiles").append(weak)
    _members(weak, "encryption", "3des")
    assert _findings(_data(root)) == {}


def test_disabled_tunnel_is_stale_not_weak():
    root = _root()
    _add(root, TUN, "disabled", "yes")
    _members(root, f"{IKE}/encryption", "3des")
    # The gateway is still referenced by the (disabled) tunnel, so only the tunnel is reported.
    assert _findings(_data(root)) == {"vpn_stale_config": ["tunnel:dc-tun"]}


def test_gateway_no_tunnel_uses_is_stale():
    root = _root()
    gw = copy.deepcopy(root.find(GW))
    gw.set("name", "old-gw")
    root.find(f"{NET}/ike/gateway").append(gw)
    assert _findings(_data(root)) == {"vpn_stale_config": ["gateway:old-gw"]}


def test_manual_key_tunnel():
    root = _root()
    tun = ET.SubElement(root.find(f"{NET}/tunnel/ipsec"), "entry", name="legacy-static")
    esp = ET.SubElement(ET.SubElement(tun, "manual-key"), "esp")
    ET.SubElement(ET.SubElement(esp, "encryption"), "algorithm").text = "3des"
    ET.SubElement(ET.SubElement(esp, "authentication"), "md5")
    data = _data(root)
    assert next(t for t in data["vpn"]["tunnels"] if t["name"] == "legacy-static")["manual"] == {
        "protocol": "esp", "encryption": "3des", "authentication": "md5"}
    assert _findings(data) == {"vpn_manual_key": ["legacy-static"]}


def test_no_vpn_raises_nothing():
    data = parser.parse_config(b"<config><devices><entry name='localhost.localdomain'/></devices></config>")
    assert data["vpn"] == {"ike_profiles": [], "ipsec_profiles": [], "gateways": [], "tunnels": []}
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": []}, RULES_BY_ID[rid].thresholds) == []


def test_panorama_template_stack_resolves_vpn():
    fw = _root()
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='branch'><reference-templates><member>stk</member></reference-templates></entry></device-group>"
        "<template><entry name='override'/><entry name='base'/></template>"
        "<template-stack><entry name='stk'><templates><member>override</member><member>base</member></templates></entry></template-stack>"
        "</entry></devices></config>")
    base = ET.SubElement(pano.find("devices/entry/template/entry[@name='base']"), "config")
    base.append(copy.deepcopy(fw.find("devices")))
    assert _findings(panorama_parser.build_assessment_data(pano, "branch")) == {}

    # The template listed higher in the stack redefines the IPSec profile.
    override = ET.SubElement(pano.find("devices/entry/template/entry[@name='override']"), "config")
    profs = ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(
        override, "devices"), "entry", name="localhost.localdomain"), "network"), "ike"), "crypto-profiles"),
        "ipsec-crypto-profiles")
    weak = ET.SubElement(profs, "entry", name="strong-ipsec")
    ET.SubElement(ET.SubElement(ET.SubElement(weak, "esp"), "encryption"), "member").text = "aes-256-gcm"
    ET.SubElement(weak, "dh-group").text = "no-pfs"
    assert _findings(panorama_parser.build_assessment_data(pano, "branch")) == {
        "vpn_weak_dh_group": ["ipsec:strong-ipsec"]}


def test_vpn_rules_are_cited_or_labelled_custom():
    for rid in RULE_IDS:
        r = RULES_BY_ID[rid]
        assert (r.source_type == "pan_docs") == bool(r.source_ref)
        if r.source_type == "pan_docs":
            assert "ipsec-vpn/administration" in r.source_ref
        assert r.category == "VPN"

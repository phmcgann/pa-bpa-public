"""Authentication, User-ID, Authentication Portal and service checks ported from Palo Alto SCM."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID, SCM_MATCHES

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "identity_hardened.xml")
RULE_IDS = ["ssl_tls_profile_weak", "admin_no_custom_roles", "auth_profile_local_only", "auth_sequence_single_profile",
            "user_id_client_probing", "user_id_timeout_disabled", "auth_portal_transparent", "auth_portal_long_session",
            "auth_portal_weak_tls", "system_logs_high_severity_only", "content_updates_gp_not_hourly",
            "ldap_single_server", "secure_client_cert_predefined"]
VSYS = "devices/entry/vsys/entry"
SYS = "devices/entry/deviceconfig/system"
CP = f"{VSYS}/captive-portal"


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
    parent, _, _tag = path.rpartition("/")
    root.find(parent).remove(root.find(path))


def _replace_child(root, path, tag):
    el = root.find(path)
    for c in list(el):
        el.remove(c)
    ET.SubElement(el, tag)


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


def test_parsed_values():
    ident = _data(_root())["identity"]
    assert [p["method"] for p in ident["auth_profiles"]] == ["ldap", "radius"]
    assert ident["captive_portal"] == {"mode": "redirect", "timer": 60, "cookie_timeout": None, "tls_profile": "strong-tls"}
    assert ident["user_id"] == {"probing": False, "mapping_timeout": True}
    assert ident["admin_roles"] == ["ops-role"]


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _set(r, "shared/ssl-tls-service-profile/entry/protocol-settings/min-version", "tls1-1"),
     {"ssl_tls_profile_weak": ["strong-tls"], "auth_portal_weak_tls": ["global"]}),
    (lambda r: _set(r, "shared/ssl-tls-service-profile/entry/protocol-settings/max-version", "tls1-2"),
     {"ssl_tls_profile_weak": ["strong-tls"]}),
    (lambda r: r.find("shared").remove(r.find("shared/admin-role")), {"admin_no_custom_roles": ["global"]}),
    (lambda r: _replace_child(r, "shared/authentication-profile/entry[@name='corp-ldap']/method", "local-database"),
     {"auth_profile_local_only": ["corp-ldap"]}),
    (lambda r: _remove(r, "shared/authentication-sequence/entry/authentication-profiles/member[2]"),
     {"auth_sequence_single_profile": ["admin-seq"]}),
    (lambda r: _set(r, f"{VSYS}/user-id-collector/setting/enable-probing", "yes"), {"user_id_client_probing": ["global"]}),
    (lambda r: _set(r, f"{VSYS}/user-id-collector/setting/enable-mapping-timeout", "no"),
     {"user_id_timeout_disabled": ["global"]}),
    (lambda r: _replace_child(r, f"{CP}/mode", "transparent"), {"auth_portal_transparent": ["global"]}),
    (lambda r: _set(r, f"{CP}/timer", "600"), {"auth_portal_long_session": ["global"]}),
    (lambda r: _remove(r, f"{CP}/ssl-tls-service-profile"), {"auth_portal_weak_tls": ["global"]}),
    (lambda r: _set(r, "shared/log-settings/system/match-list/entry/filter", "(severity geq high)"),
     {"system_logs_high_severity_only": ["global"]}),
    (lambda r: _replace_child(r, f"{SYS}/update-schedule/global-protect-datafile/recurring", "daily"),
     {"content_updates_gp_not_hourly": ["global-protect-datafile"]}),
    (lambda r: _remove(r, "shared/server-profile/ldap/entry/server/entry[@name='dc2']"), {"ldap_single_server": ["corp-ldap"]}),
    (lambda r: _remove(r, f"{SYS}/secure-conn-client"), {"secure_client_cert_predefined": ["global"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_gp_updates_only_matter_with_globalprotect():
    root = _root()
    root.find(VSYS).remove(root.find(f"{VSYS}/global-protect"))
    root.find(SYS).remove(root.find(f"{SYS}/update-schedule"))
    assert _findings(_data(root)) == {}


def test_unset_user_id_and_no_portal_are_fine():
    root = _root()
    root.find(VSYS).remove(root.find(f"{VSYS}/user-id-collector"))
    root.find(VSYS).remove(root.find(CP))
    assert _findings(_data(root)) == {}


def test_panorama_template_path():
    fw = _root()
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='branch'><reference-templates><member>t</member></reference-templates></entry></device-group>"
        "<template><entry name='t'/></template></entry></devices></config>")
    cfg = ET.SubElement(pano.find("devices/entry/template/entry"), "config")
    cfg.append(copy.deepcopy(fw.find("shared")))
    cfg.append(copy.deepcopy(fw.find("devices")))
    data = panorama_parser.build_assessment_data(pano, "branch")
    assert data["identity"]["captive_portal"]["tls_profile"] == "strong-tls"
    assert _keys(data, "auth_portal_weak_tls") == [] and _keys(data, "ssl_tls_profile_weak") == []


def test_assessment_parsed_before_these_existed_is_left_alone():
    for rid in RULE_IDS:
        assert checks.CHECKS[rid]({"security_rules": []}, RULES_BY_ID[rid].thresholds) == []


def test_rules_link_their_scm_checks():
    for rid in RULE_IDS:
        assert SCM_MATCHES[rid]

"""GlobalProtect parsing (firewall and Panorama paths) and the gp_* core checks."""
import copy
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser, parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID
from app.rules.engine import run_rules

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "globalprotect_config.xml")


@pytest.fixture(scope="module")
def data():
    with open(FIXTURE, "rb") as f:
        return parser.parse_config(f.read())


def _keys(data, rule_id):
    return sorted(item["key"] for item in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def test_portals_and_gateways_are_parsed_with_profiles_resolved(data):
    gp = data["globalprotect"]
    assert [p["name"] for p in gp["portals"]] == ["hardened-portal", "legacy-portal"]
    assert [g["name"] for g in gp["gateways"]] == ["hardened-gateway", "legacy-gateway"]
    legacy = gp["portals"][1]
    # min-version unset -> the PAN-OS default, TLS 1.0
    assert legacy["tls"] == {"name": "tls-weak", "found": True, "min_version": "tls1-0", "max_version": "max",
                             "weak_algorithms": ["3DES", "SHA-1"]}
    seq = legacy["auth_profiles"][0]["profile"]
    assert seq["sequence"] and [m["name"] for m in seq["members"]] == ["ap-ldap", "ap-local-vsys"]
    assert seq["members"][1]["method"] == "local-database"  # vsys-scoped profile resolved


def test_unset_agent_config_gets_pan_os_defaults(data):
    defaults = data["globalprotect"]["portals"][1]["agent_configs"][0]
    assert defaults["name"] == "defaults"
    assert defaults["connect_method"] == "user-logon" and not defaults["connect_method_set"]
    assert defaults["user_override"] == "allowed" and defaults["override_timeout_min"] == 0
    assert not defaults["enforce_globalprotect"] and defaults["collect_hip"]
    assert defaults["cookie_lifetime_hours"] is None


def test_cookie_lifetime_units(data):
    hardened, legacy = data["globalprotect"]["gateways"]
    assert data["globalprotect"]["portals"][0]["agent_configs"][0]["cookie_lifetime_hours"] == 8
    assert data["globalprotect"]["portals"][1]["agent_configs"][1]["cookie_lifetime_hours"] == 30 * 24
    assert legacy["client_configs"][0]["cookie_lifetime_hours"] == 24  # accept-cookie with no lifetime: default
    assert hardened["client_configs"][0]["cookie_lifetime_hours"] is None


@pytest.mark.parametrize("rule_id, expected", [
    ("gp_tls_below_1_2", ["gateway:legacy-gateway", "portal:legacy-portal"]),
    ("gp_tls_weak_ciphers", ["gateway:legacy-gateway", "portal:legacy-portal"]),
    # legacy-gateway pairs its password with a certificate profile, so it has a second factor
    ("gp_single_factor_auth", ["portal:legacy-portal"]),
    ("gp_auth_no_lockout", ["ap-ldap", "ap-local-vsys"]),
    ("gp_cert_profile_no_revocation", ["gateway:legacy-gateway"]),
    ("gp_no_trusted_root_ca", ["legacy-portal"]),
    ("gp_connect_on_demand", ["legacy-portal:contractors"]),
    ("gp_not_enforced", ["legacy-portal:defaults"]),
    ("gp_user_can_disable", ["legacy-portal:defaults"]),
    ("gp_hip_collection_disabled", ["legacy-portal:contractors"]),
    ("gp_no_internal_host_detection", ["legacy-portal:contractors"]),
    ("gp_split_tunnel", ["legacy-gateway:split"]),
    ("gp_long_cookie_lifetime", ["portal:legacy-portal:contractors"]),
    ("gp_satellite_no_root_ca", ["legacy-portal"]),
])
def test_each_check_flags_only_the_legacy_objects(data, rule_id, expected):
    assert _keys(data, rule_id) == expected


def test_cookie_threshold_is_adjustable(data):
    items = checks.check_gp_long_cookie_lifetime(data, {"max_cookie_lifetime_hours": 4})
    assert sorted(i["key"] for i in items) == [
        "gateway:legacy-gateway:split", "portal:hardened-portal:always-on", "portal:legacy-portal:contractors"]


def test_every_gp_rule_is_registered_with_a_category_and_citation_rule():
    gp_rules = [r for r in RULES_BY_ID.values() if r.id.startswith("gp_")]
    assert len(gp_rules) == 14
    for r in gp_rules:
        assert r.category == "GlobalProtect" and r.id in checks.CHECKS
        assert (r.source_type == "pan_docs") == bool(r.source_ref)
        if r.source_type == "pan_docs":
            assert "docs.paloaltonetworks.com/globalprotect/administration" in r.source_ref


def test_messages_name_the_object_and_profile(data):
    findings = {f["finding_key"]: f for f in run_rules(data, {})}
    tls = findings["gp_tls_below_1_2:portal:legacy-portal"]
    assert "Portal 'legacy-portal'" in tls["message"] and "'tls-weak'" in tls["message"] and "TLSv1.0" in tls["message"]
    mfa = findings["gp_single_factor_auth:portal:legacy-portal"]["message"]
    assert "'seq-ldap-then-local' (sequence)" in mfa


def test_assessment_without_globalprotect_data_yields_no_gp_findings():
    old = {"security_rules": [], "zones": []}  # parsed before GlobalProtect was captured
    for rule_id in (r for r in checks.CHECKS if r.startswith("gp_")):
        assert checks.CHECKS[rule_id](old, RULES_BY_ID[rule_id].thresholds) == []


def test_config_without_globalprotect_has_empty_lists():
    with open(os.path.join(os.path.dirname(__file__), "fixtures", "sample_config.xml"), "rb") as f:
        assert parser.parse_config(f.read())["globalprotect"] == {"portals": [], "gateways": []}


def _as_panorama_export(fw_root: ET.Element) -> ET.Element:
    """Wrap the firewall config in a Panorama template stack: the template carries
    GlobalProtect and its profiles, exactly where Panorama stores them."""
    pano = ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='remote-access'><devices><entry name='001122334455'/></devices>"
        "<reference-templates><member>stk-gp</member></reference-templates></entry></device-group>"
        "<template><entry name='tmpl-gp'/></template>"
        "<template-stack><entry name='stk-gp'><templates><member>tmpl-gp</member></templates></entry></template-stack>"
        "</entry></devices></config>")
    tmpl = pano.find("devices/entry/template/entry")
    cfg = ET.SubElement(tmpl, "config")
    cfg.append(copy.deepcopy(fw_root.find("shared")))
    cfg.append(copy.deepcopy(fw_root.find("devices")))
    return pano


def test_panorama_template_resolves_the_same_globalprotect(data):
    pano = _as_panorama_export(ET.parse(FIXTURE).getroot())
    pdata = panorama_parser.build_assessment_data(pano, "remote-access")
    assert pdata["globalprotect"] == data["globalprotect"]
    for rule_id in (r for r in checks.CHECKS if r.startswith("gp_")):
        assert _keys(pdata, rule_id) == _keys(data, rule_id)


# ── SCM overlap is matched per portal/gateway ─────────────────────────────

from app.rules import scm_findings  # noqa: E402


def _scm_row(check_id, object_type, name):
    return {"check_id": check_id, "passed": False, "excluded": False, "object_type": object_type,
            "object_name": name, "location": "vsys1", "failed_fields": {}}


def test_every_gp_finding_names_its_portal_or_gateway(data):
    for f in run_rules(data, {}):
        if f["rule_id"].startswith("gp_") and f["rule_id"] != "gp_auth_no_lockout":  # lockout is per auth profile
            assert f["scm_object"]["type"] in ("global_protect_portal", "global_protect_gateway"), f["finding_key"]


def test_scm_result_is_a_duplicate_only_for_the_object_core_flagged(data):
    core = run_rules(data, {})
    rows = [
        _scm_row(67, "global_protect_portal", "legacy-portal"),      # core flagged this portal -> duplicate
        _scm_row(67, "global_protect_portal", "hardened-portal"),    # core passed it -> Palo Alto's own finding
        _scm_row(77, "global_protect_gateway", "legacy-gateway"),    # core accepted its cert profile -> not covered
        _scm_row(76, "global_protect_gateway", "legacy-gateway"),    # same gateway, TLS -> duplicate
        _scm_row(76, "global_protect_gateway", "hardened-gateway"),  # different gateway -> not covered
    ]
    out = {(f["scm_check_ids"][0], f["message"].split("'")[1]): f["duplicate_of"]
           for f in scm_findings.build(rows, data, core, {})}
    assert out[(67, "legacy-portal")] == ["gp_single_factor_auth"]
    assert out[(67, "hardened-portal")] == []
    assert out[(77, "legacy-gateway")] == []
    assert out[(76, "legacy-gateway")] == ["gp_tls_below_1_2"]
    assert out[(76, "hardened-gateway")] == []


def test_core_finding_without_an_object_still_covers_the_whole_check(data):
    core = [{"rule_id": "gp_tls_below_1_2", "scm_object": None}]
    rows = [_scm_row(76, "global_protect_gateway", "any-gateway")]
    assert scm_findings.build(rows, data, core, {})[0]["duplicate_of"] == ["gp_tls_below_1_2"]

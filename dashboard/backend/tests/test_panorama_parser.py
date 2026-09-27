import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser as pp

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "panorama_export_config.xml")
STANDALONE_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_config.xml")


@pytest.fixture
def root():
    tree = ET.parse(FIXTURE)
    return tree.getroot()


def test_is_panorama_export(root):
    assert pp.is_panorama_export(root) is True


def test_standalone_config_is_not_a_panorama_export():
    tree = ET.parse(STANDALONE_FIXTURE)
    assert pp.is_panorama_export(tree.getroot()) is False


def test_list_device_groups_excludes_readonly_mirror(root):
    # The fixture's <readonly> section mirrors "test-dg" with a decoy rule —
    # a correct implementation lists it exactly once, from the real location.
    groups = pp.list_device_groups(root)
    assert len(groups) == 1
    dg = groups[0]
    assert dg["name"] == "test-dg"
    assert dg["device_serials"] == ["001122334455"]
    assert dg["reference_templates"] == ["stk-test"]


def test_readonly_decoy_rule_is_never_counted(root):
    data = pp.build_assessment_data(root, "test-dg")
    rule_names = {r["name"] for r in data["security_rules"]}
    assert "readonly-decoy-rule" not in rule_names


def test_rules_merged_from_all_four_scopes(root):
    data = pp.build_assessment_data(root, "test-dg")
    by_scope = {r["rule_scope"]: r["name"] for r in data["security_rules"]}
    assert by_scope == {
        "shared_pre": "shared-pre-block-known-bad",
        "device_group_pre": "dg-pre-allow-web",
        "device_group_post": "dg-post-deny-all",
        "shared_post": "shared-post-catch-all",
    }


def test_zones_unioned_across_stack_member_templates_and_stack_own_layer(root):
    data = pp.build_assessment_data(root, "test-dg")
    zone_names = {z["name"] for z in data["zones"]}
    # zone-a from tmplA, zone-b from tmplB (both referenced by the stack),
    # zone-c-stack-own from the stack's own config layer.
    assert zone_names == {"zone-a", "zone-b", "zone-c-stack-own"}


def test_login_banner_resolved_via_template_stack(root):
    data = pp.build_assessment_data(root, "test-dg")
    assert data["management"]["login_banner"] is True
    assert data["management"]["mgmt_acl"] is False
    assert data["management"]["ntp_primary"] is None


def test_syslog_profile_found_in_template_embedded_shared_scope(root):
    # Regression coverage: the real Panorama export had its only syslog server
    # profile inside a template's own embedded <shared>, not Panorama's
    # top-level <shared>.
    data = pp.build_assessment_data(root, "test-dg")
    assert data["syslog_profiles"] == 1


def test_security_profiles_and_groups_resolve_with_rule_counts(root):
    data = pp.build_assessment_data(root, "test-dg")
    av = data["security_profiles"]["antivirus"]
    assert len(av) == 1
    assert av[0]["name"] == "shared-av"
    assert av[0]["rule_count"] == 1  # used by dg-pre-allow-web via the profile group

    assert len(data["profile_groups"]) == 1
    group = data["profile_groups"][0]
    assert group["name"] == "secgrp_dg-strict"
    assert group["members"] == {"antivirus": ["shared-av"]}
    assert group["rule_count"] == 1


def test_unavailable_sections_marked_consistently(root):
    data = pp.build_assessment_data(root, "test-dg")
    assert data["panorama_managed"] is True
    assert data["system_info"]["available"] is False
    assert data["licenses"]["available"] is False
    assert data["ha"]["available"] is False
    assert data["admin_accounts"] == []


def test_serial_is_derived_from_device_group_devices_list(root):
    # Regression coverage: the assigned firewall's serial IS in a Panorama
    # export (device-group/entry/devices/entry's name attribute), unlike
    # PAN-OS version/uptime which are genuinely runtime-only — a user caught
    # this being incorrectly marked unavailable alongside those.
    data = pp.build_assessment_data(root, "test-dg")
    assert data["system_info"]["serial"] == "001122334455"


def test_unknown_device_group_raises(root):
    with pytest.raises(ValueError):
        pp.build_assessment_data(root, "does-not-exist")


def _stack_export(members_xml: str) -> ET.Element:
    """A device group referencing one stack; templates 'top' and 'bottom' each set NTP and a
    same-named zone, and the stack carries its own config layer."""
    def tmpl(name, ntp, zone_proto):
        return (f"<entry name='{name}'><config><devices><entry name='localhost.localdomain'>"
                f"<deviceconfig><system><ntp-servers><primary-ntp-server><ntp-server-address>{ntp}"
                f"</ntp-server-address></primary-ntp-server></ntp-servers></system></deviceconfig>"
                f"<vsys><entry name='vsys1'><zone><entry name='trust'><network><{zone_proto}/></network>"
                f"</entry></zone></entry></vsys></entry></devices></config></entry>")
    return ET.fromstring(
        "<config><shared/><devices><entry name='localhost.localdomain'>"
        "<device-group><entry name='dg'><reference-templates><member>stk</member></reference-templates>"
        "</entry></device-group>"
        f"<template>{tmpl('top', '192.0.2.1', 'layer3')}{tmpl('bottom', '192.0.2.2', 'layer2')}</template>"
        f"<template-stack><entry name='stk'><templates>{members_xml}</templates></entry></template-stack>"
        "</entry></devices></config>")


@pytest.mark.parametrize("members_xml, ntp, zone_mode", [
    ("<member>top</member><member>bottom</member>", "192.0.2.1", "layer3"),
    ("<member>bottom</member><member>top</member>", "192.0.2.2", "layer2"),
])
def test_template_listed_higher_in_the_stack_wins(members_xml, ntp, zone_mode):
    # "Panorama evaluates the templates listed in a stack configuration from top to bottom
    # with higher templates having priority."
    data = pp.build_assessment_data(_stack_export(members_xml), "dg")
    assert data["management"]["ntp_primary"] == ntp
    assert [z["mode"] for z in data["zones"] if z["name"] == "trust"] == [zone_mode]


def test_stack_own_config_overrides_its_templates():
    root = _stack_export("<member>top</member><member>bottom</member>")
    own = ET.SubElement(root.find("devices/entry/template-stack/entry"), "config")
    system = ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(
        own, "devices"), "entry", name="localhost.localdomain"), "deviceconfig"), "system")
    ET.SubElement(ET.SubElement(ET.SubElement(system, "ntp-servers"), "primary-ntp-server"),
                  "ntp-server-address").text = "192.0.2.9"
    assert pp.build_assessment_data(root, "dg")["management"]["ntp_primary"] == "192.0.2.9"

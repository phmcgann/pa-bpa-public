import os

import pytest

from app import parser

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_config.xml")
PANORAMA_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "panorama_managed_config.xml")


@pytest.fixture
def data():
    with open(FIXTURE, "rb") as f:
        return parser.parse_config(f.read())


def test_hostname_from_deviceconfig(data):
    assert data["system_info"]["hostname"] == "fw01"
    assert data["system_info"]["available"] is False


def test_panorama_management_detection(data):
    # sample_config.xml has no <panorama> element -> locally managed
    assert data["panorama_managed"] is False

    with open(PANORAMA_FIXTURE, "rb") as f:
        panorama_data = parser.parse_config(f.read())
    assert panorama_data["panorama_managed"] is True
    # Confirms the real-world symptom: a Panorama-managed firewall's own
    # export has no local zones/rules even though it "parses successfully".
    assert panorama_data["zones"] == []
    assert panorama_data["security_rules"] == []


def test_licenses_ha_unavailable_offline(data):
    assert data["licenses"]["available"] is False
    assert data["ha"]["available"] is False


def test_admin_accounts_excludes_log_query_entries(data):
    names = {a["name"] for a in data["admin_accounts"]}
    assert names == {"admin", "jsmith"}


def test_admin_auth_profiles(data):
    by_name = {a["name"]: a for a in data["admin_accounts"]}
    assert by_name["admin"]["auth_profile"] == "local"
    assert by_name["jsmith"]["auth_profile"] == "corp-radius"


def test_zones(data):
    by_name = {z["name"]: z for z in data["zones"]}
    assert by_name["trust"]["zone_protection_profile"] is None
    assert by_name["untrust"]["zone_protection_profile"] == "strict-zpp"


def test_security_rules_count(data):
    assert len(data["security_rules"]) == 6
    names = {r["name"] for r in data["security_rules"]}
    assert "allow-any-any-any" in names
    assert "deny-suspicious" in names


def test_security_profiles_lists(data):
    sp = data["security_profiles"]
    av_names = {p["name"] for p in sp["antivirus"]}
    assert av_names == {"default-av", "unused-av"}
    assert sp["vulnerability"] == []
    assert sp["spyware"] == []
    assert sp["url_filtering"] == []
    assert sp["wildfire_analysis"] == []


def test_syslog_profile_under_log_settings(data):
    # Regression test: syslog server profiles live at .//log-settings/syslog/entry,
    # not .//server-profile/syslog/entry (that container is auth server profiles —
    # LDAP/RADIUS/SAML — a real config export exposed this mismatch).
    assert data["syslog_profiles"] == 1


def test_security_profile_rule_counts_via_group(data):
    by_name = {p["name"]: p for p in data["security_profiles"]["antivirus"]}
    # used by web-servers-inbound + ftp-legacy-transfer, both via the "strict-profiles" group
    assert by_name["default-av"]["rule_count"] == 2
    assert by_name["unused-av"]["rule_count"] == 0


def test_profile_groups(data):
    # Regression test: <profile-group> is a sibling of <profiles>, not nested
    # inside it — a real config export showed this parser returning zero groups
    # despite 5 being defined and 7 rules referencing them by name.
    assert len(data["profile_groups"]) == 1
    group = data["profile_groups"][0]
    assert group["name"] == "strict-profiles"
    assert group["members"] == {"antivirus": ["default-av"]}
    assert group["rule_count"] == 2


def test_management_settings(data):
    mgmt = data["management"]
    assert mgmt["mgmt_acl"] is False
    assert mgmt["login_banner"] is False
    # Regression test: PAN-OS 11.1 uses <ntp-server-address>, not <server>, under
    # primary/secondary-ntp-server. Primary here exercises the new tag, secondary
    # exercises the older fallback tag — both must resolve.
    assert mgmt["ntp_primary"] == "0.pool.ntp.org"
    assert mgmt["ntp_secondary"] == "1.pool.ntp.org"

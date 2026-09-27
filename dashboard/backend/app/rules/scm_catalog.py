"""Palo Alto Strata Cloud Manager (SCM) BPA check catalogue (see scm_catalog.json)."""
from __future__ import annotations

import json
import os
from functools import lru_cache

_PATH = os.path.join(os.path.dirname(__file__), "scm_catalog.json")

# SCM's own severity words -> this dashboard's scale (Critical / Warning / Low / Informational).
# SCM's four words map straight across, except "High", which has no slot of its own: like the core
# BPA rules that were HIGH, it becomes Warning. SCM never uses "Low".
SEVERITY_MAP = {"Critical": "CRITICAL", "High": "WARNING", "Warning": "WARNING", "Informational": "INFORMATIONAL"}

# SCM checks that start switched off (users can turn them on in Settings), with the reason.
# Palo Alto evaluates these satellite checks on every GlobalProtect portal/gateway, so they fail
# on deployments that don't use satellites at all; the core satellite check only runs when
# satellites are configured.
DISABLED_BY_DEFAULT: dict[int, str] = {
    74: "Off by default: Palo Alto flags it on every portal, even with no satellites configured",
    79: "Off by default: Palo Alto flags it on every gateway, even with no satellites configured",
    # Checks whose results can't be trusted from one firewall config.
    90: "Off by default: whether a hostname is unique depends on the other firewalls, not this config",
    119: "Off by default: Palo Alto fails firewalls in the US that use the global (US) WildFire cloud",
    157: "Off by default: Palo Alto passes authentication profiles with no lockout at all",
    191: "Off by default: staggering update times needs both HA peers' configs; Palo Alto judges one",
    192: "Off by default: staggering update times needs both HA peers' configs; Palo Alto judges one",
    200: "Off by default: Palo Alto fails its own predefined profile, whose low/informational actions are default",
    201: "Off by default: Palo Alto fails its own predefined profile, whose low/informational actions are default",
    267: "Off by default: where the forward trust/untrust certificates are stored couldn't be confirmed",
}
_BUSINESS = "Off by default: blocking these is a business decision (matches the core rule's default)"
_PQ = "Off by default: post-quantum crypto is new and most peers can't use it yet (matches the core rule's default)"
DISABLED_BY_DEFAULT.update({cid: _BUSINESS for cid in (340, 344, 348, 351, 352, 353, 354, 357)})
DISABLED_BY_DEFAULT.update({cid: _PQ for cid in (359, 371, 375, 376)})

# SCM checks that only apply with a license: Palo Alto evaluates them on every firewall, so without
# the license they're dropped (as the matching core rules are). check id -> license feature text.
LICENSE_GATED: dict[int, str] = {cid: "advanced ip defense" for cid in (398, 399, 400, 401, 402, 404, 406, 408, 410)}


def enabled_by_default(check_id: int) -> bool:
    return check_id not in DISABLED_BY_DEFAULT


# SCM object type -> the dashboard category it's grouped under.
_CATEGORY_BY_OBJECT = {
    "security_rule": "Security Policy", "security_rulebase": "Security Policy", "app_override": "Security Policy",
    "authentication_rules": "Security Policy", "policy_based_forwarding_rule": "Security Policy",
    "tunnel_inspection": "Security Policy", "dos_protection_rule": "Network Security",
    "decryption_rule": "Decryption", "decryption_rulebase": "Decryption", "decryption_profile": "Decryption",
    "certificate": "Decryption",
    "antivirus_profile": "Security Profiles", "anti_spyware_profile": "Security Profiles",
    "vulnerability_protection_profile": "Security Profiles", "url_filtering_profile": "Security Profiles",
    "file_blocking_profile": "Security Profiles", "wildfire_analysis_profile": "Security Profiles",
    "zone": "Network Security", "zone_protection_profile": "Network Security",
    "interface_management_profile": "Access Control", "dos_protection_profile": "Network Security",
    "user_id": "Network Security",
    "global_protect_portal": "GlobalProtect", "global_protect_gateway": "GlobalProtect",
    "ike_crypto_profiles": "VPN", "ipsec_crypto_profile": "VPN", "gre_tunnel": "VPN",
    "high_availability": "High Availability",
    "log_forwarding_profile": "Logging", "log_settings_system": "Logging", "log_settings_config": "Logging",
    "syslog_server_profile": "Logging", "snmp_trap_server_profile": "Logging",
    "device_setup_logging_reporting": "Logging",
    "device_setup_management_interface": "Access Control", "device_setup_authentication": "Access Control",
    "authentication_profile": "Access Control", "authentication_sequence": "Access Control",
    "authentication_portal": "Access Control", "admin_role": "Access Control",
    "ldap_server_profile": "Access Control", "radius_server_profile": "Access Control",
    "tacplus_server_profile": "Access Control", "device_setup_minimum_password_complexity": "Access Control",
    "dynamic_updates": "Software",
}


def category_for(object_type: str) -> str:
    return _CATEGORY_BY_OBJECT.get(object_type, "Device Hardening")


def object_type_label(object_type: str) -> str:
    return object_type.replace("_", " ").replace("device setup ", "Device setup: ").capitalize()


@lru_cache(maxsize=1)
def load() -> dict:
    with open(_PATH, encoding="utf-8") as f:
        return json.load(f)


def checks_by_id() -> dict[int, dict]:
    return {c["id"]: c for c in load()["checks"]}

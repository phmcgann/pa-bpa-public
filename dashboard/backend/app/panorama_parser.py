"""
Panorama-native config export parsing.

A firewall managed by Panorama pushes its actual security policy from
Panorama's Device Group / Template hierarchy at commit time — none of that
appears in the managed firewall's own config export (see parser.py's
detect_panorama_managed). This module parses an export taken from Panorama
itself, which has a structurally different shape: multiple device-groups
(each = one or more managed firewalls), rules split across shared and
device-group pre/post-rulebases, and zones/network settings defined in
Templates or Template Stacks rather than directly on the firewall.

Every path here was traced against a real Panorama export, not guessed from
documentation — see the plan file's "Verified real structure" section for
what was checked and how. Two things worth calling out:

1. Panorama exports also include a config/readonly/devices/... section that
   mirrors the same device-group names. Every traversal here anchors from
   config_root.find("devices") (the true top-level, direct-child element),
   never ".//devices" — a loose search matches the readonly mirror too and
   silently double-counts everything.

2. Template Stack precedence: a device-group's <reference-templates> can
   list a mix of plain template names and template-stack names, in order. A
   stack itself can *also* carry its own config layer directly, on top of
   the templates it references. Within a stack, "Panorama evaluates the
   templates listed in a stack configuration from top to bottom with higher
   templates having priority" (Panorama Admin Guide, Templates and Template
   Stacks), so the first member wins and the stack's own config sits above
   all of them. Across several reference-templates entries this module
   treats list order as priority (each later entry can add to or override
   earlier ones) and unions zones by name — a reasonable, disclosed
   approximation of Panorama's actual commit-time merge, not a certified
   replica of it.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from .certificates import parse_certificates
from .object_usage import unavailable_for_panorama
from .parser import (
    PROFILE_TYPE_TAGS, attach_mgmt_profile_interfaces, compute_profile_usage, members,
    parse_decryption_profiles_from, parse_decryption_rule_entry, parse_default_rule_actions,
    parse_default_rule_logging, parse_globalprotect,
    parse_device_settings, parse_dos, parse_identity, parse_log_forwarding_profiles, parse_ha_config, parse_misc_policy, parse_mgmt_plane,
    parse_session_settings, parse_vpn,
    parse_interface_mgmt_profiles_from, parse_mgmt_interfaces, parse_policy_objects, parse_profile_settings,
    parse_nat_rule_entry, parse_rule_entry, profile_scopes, parse_zone_entry, parse_zone_protection_profiles_from, xml_text_any,
)


def is_panorama_export(config_root: ET.Element) -> bool:
    """True if this is an export taken from Panorama itself (has real device
    groups), as opposed to a standalone/managed firewall's own export."""
    devices_top = config_root.find("devices")
    if devices_top is None:
        return False
    dg_container = devices_top.find("entry/device-group")
    return dg_container is not None and len(dg_container.findall("entry")) > 0


def _dg_container(config_root: ET.Element) -> Optional[ET.Element]:
    devices_top = config_root.find("devices")
    if devices_top is None:
        return None
    return devices_top.find("entry/device-group")


def list_device_groups(config_root: ET.Element) -> list[dict]:
    """For the upload-time picker: every device-group with its assigned
    firewall serial(s) and the templates/stacks it references."""
    dg_container = _dg_container(config_root)
    if dg_container is None:
        return []

    out = []
    for entry in dg_container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        devs = entry.find("devices")
        serials = [d.get("name") for d in devs.findall("entry") if d.get("name")] if devs is not None else []
        rt = entry.find("reference-templates")
        ref_names = members(entry, "reference-templates/member") if rt is not None else []
        out.append({"name": name, "device_serials": serials, "reference_templates": ref_names})
    return out


def _resolve_reference_configs(
    template_container: Optional[ET.Element],
    stack_container: Optional[ET.Element],
    reference_names: list[str],
) -> list[ET.Element]:
    """Expand a device-group's reference-templates list into an ordered list
    of <config> elements (lowest priority first) — each template/stack's own
    top-level <config>, which itself contains both a devices/entry subtree
    (network, zones, deviceconfig) and its own embedded <shared> subtree
    (a template can define objects like syslog server profiles in its own
    shared scope, separately from Panorama's top-level shared). A stack name
    expands to [its member templates' configs, bottom of the stack first...,
    the stack's own config]: the stack's first-listed template has priority
    over the ones below it, and the stack's own settings over all of them."""
    template_by_name = {e.get("name"): e for e in template_container.findall("entry")} if template_container is not None else {}
    stack_by_name = {e.get("name"): e for e in stack_container.findall("entry")} if stack_container is not None else {}

    configs = []
    for name in reference_names:
        if name in stack_by_name:
            stack = stack_by_name[name]
            member_names = members(stack, "templates/member")
            for member_name in reversed(member_names):
                tmpl = template_by_name.get(member_name)
                cfg = tmpl.find("config") if tmpl is not None else None
                if cfg is not None:
                    configs.append(cfg)
            own_cfg = stack.find("config")
            if own_cfg is not None:
                configs.append(own_cfg)
        elif name in template_by_name:
            cfg = template_by_name[name].find("config")
            if cfg is not None:
                configs.append(cfg)
    return configs


def _merge_zones(configs: list[ET.Element]) -> list[dict]:
    zones_by_name: dict[str, dict] = {}
    for cfg in configs:
        zone_container = cfg.find("devices/entry/vsys/entry/zone")
        if zone_container is None:
            continue
        for entry in zone_container.findall("entry"):
            if entry.get("name"):
                zones_by_name[entry.get("name")] = parse_zone_entry(entry)
    return list(zones_by_name.values())


def _count_template_syslog_profiles(configs: list[ET.Element]) -> int:
    """Union of syslog server profile names across every template/stack's own
    embedded <shared> scope — verified against a real export where the only
    syslog profile ('splunk') lived here, not in Panorama's top-level shared."""
    names: set[str] = set()
    for cfg in configs:
        syslog_container = cfg.find("shared/log-settings/syslog")
        if syslog_container is None:
            continue
        names.update(e.get("name") for e in syslog_container.findall("entry") if e.get("name"))
    return len(names)


def _merge_management_settings(configs: list[ET.Element]) -> dict:
    """First non-empty value wins, scanning layers from highest priority down
    (`configs` is lowest priority first)."""
    ntp_primary = ntp_secondary = None
    login_banner = False
    mgmt_acl = False

    for cfg in reversed(configs):
        system = cfg.find("devices/entry/deviceconfig/system")
        if system is None:
            continue
        if ntp_primary is None:
            ntp_primary = xml_text_any(system, [
                "ntp-servers/primary-ntp-server/ntp-server-address",
                "ntp-servers/primary-ntp-server/server",
            ], None)
        if ntp_secondary is None:
            ntp_secondary = xml_text_any(system, [
                "ntp-servers/secondary-ntp-server/ntp-server-address",
                "ntp-servers/secondary-ntp-server/server",
            ], None)
        if not login_banner:
            banner = system.find("login-banner")
            login_banner = bool(banner is not None and banner.text)
        if not mgmt_acl:
            permit = system.find("permitted-ip")
            mgmt_acl = bool(permit is not None and len(list(permit)) > 0)

    return {
        "mgmt_acl": mgmt_acl,
        "login_banner": login_banner,
        "ntp_primary": ntp_primary,
        "ntp_secondary": ntp_secondary,
    }


def _parse_scoped_rules(container_el: Optional[ET.Element], scope_label: str) -> list[dict]:
    if container_el is None:
        return []
    rules_el = container_el.find("security/rules")
    if rules_el is None:
        return []
    return [parse_rule_entry(entry, rule_scope=scope_label) for entry in rules_el.findall("entry")]


def _parse_scoped_nat_rules(container_el: Optional[ET.Element], scope_label: str) -> list[dict]:
    if container_el is None:
        return []
    return [parse_nat_rule_entry(entry, rule_scope=scope_label) for entry in container_el.findall("nat/rules/entry")]


def _parse_scoped_decryption_rules(container_el: Optional[ET.Element], scope_label: str) -> list[dict]:
    if container_el is None:
        return []
    return [
        parse_decryption_rule_entry(entry, rule_scope=scope_label)
        for entry in container_el.findall("decryption/rules/entry")
    ]


def build_assessment_data(config_root: ET.Element, device_group_name: str) -> dict:
    """Resolve the effective policy for one device-group into the same
    AssessmentData shape parser.parse_config() returns, so the rules engine
    and every frontend component work unchanged."""
    dg_container = _dg_container(config_root)
    if dg_container is None:
        raise ValueError("Not a Panorama export (no device-group found)")

    dg = next((e for e in dg_container.findall("entry") if e.get("name") == device_group_name), None)
    if dg is None:
        raise ValueError(f"Device group '{device_group_name}' not found in this export")

    shared = config_root.find("shared")

    # ── Rules: shared-pre -> device-group-pre -> device-group-post -> shared-post
    rules: list[dict] = []
    rules += _parse_scoped_rules(shared.find("pre-rulebase") if shared is not None else None, "shared_pre")
    rules += _parse_scoped_rules(dg.find("pre-rulebase"), "device_group_pre")
    rules += _parse_scoped_rules(dg.find("post-rulebase"), "device_group_post")
    rules += _parse_scoped_rules(shared.find("post-rulebase") if shared is not None else None, "shared_post")

    # ── Security profiles + profile groups: union of shared + this device-group's own.
    # Keeps the actual <entry> element (not just the name) so settings can be read out
    # of it below — a device-group's own entry wins over shared's on a name collision,
    # same "more specific layer wins" precedence used for zones/management settings.
    profile_entries: dict[str, dict[str, ET.Element]] = {}
    for key, tag in PROFILE_TYPE_TAGS.items():
        by_name: dict[str, ET.Element] = {}
        if shared is not None:
            for e in shared.findall(f"profiles/{tag}/entry"):
                if e.get("name"):
                    by_name[e.get("name")] = e
        for e in dg.findall(f"profiles/{tag}/entry"):
            if e.get("name"):
                by_name[e.get("name")] = e
        profile_entries[key] = by_name
    profiles: dict[str, list[str]] = {key: sorted(by_name.keys()) for key, by_name in profile_entries.items()}
    scope_of = profile_scopes([("shared", shared), ("device_group", dg)])

    groups: list[dict] = []
    seen_group_names: set[str] = set()
    for container in [shared.find("profile-group") if shared is not None else None, dg.find("profile-group")]:
        if container is None:
            continue
        for entry in container.findall("entry"):
            name = entry.get("name")
            if not name or name in seen_group_names:
                continue
            seen_group_names.add(name)
            member_profiles = {}
            for key, tag in PROFILE_TYPE_TAGS.items():
                mem = members(entry, f"{tag}/member")
                if mem:
                    member_profiles[key] = mem
            groups.append({"name": name, "members": member_profiles,
                           "data_filtering": members(entry, "data-filtering/member")})

    profile_rule_counts, group_rule_counts = compute_profile_usage(rules, profiles, groups)
    security_profiles = {
        ptype: [
            {
                "name": name,
                "rule_count": profile_rule_counts[ptype][name],
                "scope": scope_of.get((ptype, name)),
                "settings": parse_profile_settings(profile_entries[ptype][name], ptype),
            }
            for name in names
        ]
        for ptype, names in profiles.items()
    }
    profile_groups = [
        {"name": g["name"], "members": g["members"], "rule_count": group_rule_counts[g["name"]],
         "data_filtering": g.get("data_filtering", [])}
        for g in groups
    ]

    # ── Zones + management settings: resolved from the device-group's reference-templates
    devices_top = config_root.find("devices")
    template_container = devices_top.find("entry/template") if devices_top is not None else None
    stack_container = devices_top.find("entry/template-stack") if devices_top is not None else None
    reference_names = members(dg, "reference-templates/member")
    resolved_configs = _resolve_reference_configs(template_container, stack_container, reference_names)
    zones = _merge_zones(resolved_configs)
    management = _merge_management_settings(resolved_configs)

    # Same order as the security rulebase; profiles are shared then the
    # device-group's own, so a device-group profile wins on a name collision.
    decryption_rules: list[dict] = []
    for container, label in [
        (shared.find("pre-rulebase") if shared is not None else None, "shared_pre"),
        (dg.find("pre-rulebase"), "device_group_pre"),
        (dg.find("post-rulebase"), "device_group_post"),
        (shared.find("post-rulebase") if shared is not None else None, "shared_post"),
    ]:
        decryption_rules += _parse_scoped_decryption_rules(container, label)
    decryption_profile_els = (shared.findall("profiles/decryption/entry") if shared is not None else []) + \
        dg.findall("profiles/decryption/entry")

    # Network profiles and interfaces live in the template layers, lowest
    # priority first — a later layer's same-named profile replaces an earlier one.
    zpp_els: list[ET.Element] = []
    mgmt_els: list[ET.Element] = []
    interface_containers: list[ET.Element] = []
    for cfg in resolved_configs:
        zpp_els += cfg.findall("devices/entry/network/profiles/zone-protection-profile/entry")
        mgmt_els += cfg.findall("devices/entry/network/profiles/interface-management-profile/entry")
        iface = cfg.find("devices/entry/network/interface")
        if iface is not None:
            interface_containers.append(iface)
    interface_mgmt_profiles = parse_interface_mgmt_profiles_from(mgmt_els)

    # GlobalProtect lives in the template layers too: each layer's embedded shared scope
    # (profiles), then its vsys (portals, gateways and vsys-scoped profiles).
    gp_scopes: list[ET.Element] = []
    gp_vsys: list[ET.Element] = []
    for cfg in resolved_configs:
        if (tmpl_shared := cfg.find("shared")) is not None:
            gp_scopes.append(tmpl_shared)
        vsys_list = cfg.findall("devices/entry/vsys/entry")
        gp_scopes += vsys_list
        gp_vsys += vsys_list
    attach_mgmt_profile_interfaces(interface_mgmt_profiles, interface_containers)

    # ── Syslog: Panorama's top-level shared, unioned with each resolved
    # template/stack's own embedded shared scope (verified real-world location)
    top_level_names: set[str] = set()
    if shared is not None:
        top_level_names.update(e.get("name") for e in shared.findall("log-settings/syslog/entry") if e.get("name"))
    syslog_count = len(top_level_names) + _count_template_syslog_profiles(resolved_configs)

    # Serial(s) of the firewall(s) assigned to this device-group ARE in the
    # export (device-group/entry/devices/entry's name attribute) — unlike
    # PAN-OS version/uptime, which are genuinely runtime-only.
    devices_el = dg.find("devices")
    serials = [d.get("name") for d in devices_el.findall("entry") if d.get("name")] if devices_el is not None else []

    post_rulebases = [rb for rb in (shared.find("post-rulebase") if shared is not None else None,
                                    dg.find("post-rulebase")) if rb is not None]

    return {
        "panorama_managed": True,
        "mgmt_interfaces": parse_mgmt_interfaces(interface_containers),
        "policy_objects": parse_policy_objects(([shared] if shared is not None else []) + [dg]),
        "default_rule_actions": parse_default_rule_actions(post_rulebases),
        "default_rule_logging": parse_default_rule_logging(post_rulebases),
        "decryption": {
            "rules": decryption_rules,
            "profiles": parse_decryption_profiles_from(decryption_profile_els),
        },
        "globalprotect": parse_globalprotect(gp_scopes, gp_vsys),
        "zone_protection_profiles": parse_zone_protection_profiles_from(zpp_els),
        "interface_mgmt_profiles": interface_mgmt_profiles,
        "system_info": {
            "available": False,
            "hostname": device_group_name,
            "serial": ", ".join(serials) if serials else None,
            "reason": f"Resolved from a Panorama export (device group '{device_group_name}') — "
                      "PAN-OS version and uptime require a live device connection.",
        },
        "licenses": {
            "available": False, "licenses": [],
            "reason": "License status requires a live device connection.",
        },
        "admin_accounts": [],
        "zones": zones,
        "device_group": device_group_name,
        "security_rules": rules,
        # Same pre/post order as the security rulebase.
        "nat_rules": [r for container, label in (
            (shared.find("pre-rulebase") if shared is not None else None, "shared_pre"),
            (dg.find("pre-rulebase"), "device_group_pre"),
            (dg.find("post-rulebase"), "device_group_post"),
            (shared.find("post-rulebase") if shared is not None else None, "shared_post"),
        ) for r in _parse_scoped_nat_rules(container, label)],
        "security_profiles": security_profiles,
        "profile_groups": profile_groups,
        "syslog_profiles": syslog_count,
        "ha": {"available": False, "reason": "HA state requires a live device connection."},
        "management": management,
        # Template layers are lowest priority first, the order parse_mgmt_plane expects.
        "mgmt_plane": parse_mgmt_plane(resolved_configs),
        "ha_config": parse_ha_config(resolved_configs),
        "vpn": parse_vpn(resolved_configs),
        "dos": parse_dos(
            ([shared] if shared is not None else []) + [dg],
            [(rb, label) for rb, label in (
                (shared.find("pre-rulebase") if shared is not None else None, "shared_pre"),
                (dg.find("pre-rulebase"), "device_group_pre"),
                (dg.find("post-rulebase"), "device_group_post"),
                (shared.find("post-rulebase") if shared is not None else None, "shared_post"),
            ) if rb is not None]),
        "session_settings": parse_session_settings(resolved_configs),
        "log_forwarding_profiles": parse_log_forwarding_profiles(([shared] if shared is not None else []) + [dg]),
        "device_settings": parse_device_settings(resolved_configs),
        "identity": parse_identity(resolved_configs),
        "certificates": parse_certificates(resolved_configs),
        "object_usage": unavailable_for_panorama(),
        "misc_policy": parse_misc_policy(
            [rb for rb in (shared.find("pre-rulebase") if shared is not None else None, dg.find("pre-rulebase"),
                           dg.find("post-rulebase"), shared.find("post-rulebase") if shared is not None else None)
             if rb is not None],
            resolved_configs),
    }

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


# ── Device-group hierarchy and a firewall's own device groups / template stack ──

def device_group_parents(config_root: ET.Element) -> tuple[dict[str, Optional[str]], bool]:
    """Each device group's parent (None: directly under Shared), and whether the file records the
    hierarchy at all. Panorama keeps it outside the device groups themselves, in the read-only
    section: readonly/devices/entry/device-group/entry/parent-dg (older releases:
    readonly/dg-meta-data/dg-info/entry/parent-dg). A group with no parent-dg sits under Shared."""
    parents: dict[str, Optional[str]] = {}
    readonly = config_root.find("readonly")
    if readonly is None:
        return parents, False
    known = False
    for container in (readonly.find("devices/entry/device-group"), readonly.find("dg-meta-data/dg-info")):
        if container is None:
            continue
        known = True
        for entry in container.findall("entry"):
            name = entry.get("name")
            parent = (entry.findtext("parent-dg") or "").strip()
            if name and parent:
                parents[name] = parent
    return parents, known


def device_group_chain(config_root: ET.Element, name: str) -> list[str]:
    """The device groups whose policy a member of `name` receives, top of the hierarchy first:
    [grandparent, parent, name]. Shared isn't listed; it always applies."""
    parents, _ = device_group_parents(config_root)
    container = _dg_container(config_root)
    existing = {e.get("name") for e in container.findall("entry")} if container is not None else set()
    chain: list[str] = []
    current: Optional[str] = name
    while current and current in existing and current not in chain:
        chain.insert(0, current)
        current = parents.get(current)
    return chain


def _template_containers(config_root: ET.Element) -> tuple[Optional[ET.Element], Optional[ET.Element]]:
    devices_top = config_root.find("devices")
    if devices_top is None:
        return None, None
    return devices_top.find("entry/template"), devices_top.find("entry/template-stack")


def device_templates(config_root: ET.Element, serial: str) -> tuple[Optional[str], list[str], list[ET.Element]]:
    """The template stack assigned to a firewall (by serial), its templates in priority order (first
    wins), and the resolved template configs, lowest priority first. Falls back to a template the
    firewall is assigned to directly (older Panorama releases)."""
    template_container, stack_container = _template_containers(config_root)
    for stack in (stack_container.findall("entry") if stack_container is not None else []):
        if any(d.get("name") == serial for d in stack.findall("devices/entry")):
            name = stack.get("name")
            return name, members(stack, "templates/member"), _resolve_reference_configs(
                template_container, stack_container, [name])
    for tmpl in (template_container.findall("entry") if template_container is not None else []):
        if any(d.get("name") == serial for d in tmpl.findall("devices/entry")):
            name = tmpl.get("name")
            return None, [name], _resolve_reference_configs(template_container, stack_container, [name])
    return None, [], []


def _template_hostname(configs: list[ET.Element]) -> Optional[str]:
    for cfg in reversed(configs):  # highest priority first
        name = (cfg.findtext("devices/entry/deviceconfig/system/hostname") or "").strip()
        if name:
            return name
    return None


def list_devices(config_root: ET.Element, hostnames: Optional[dict[str, str]] = None) -> list[dict]:
    """For the upload-time picker: every firewall Panorama manages, with the device groups (top of the
    hierarchy first) and template stack it gets its configuration from. Hostnames come from the
    template stack when it sets one, else from `hostnames` (Panorama's own device list, when the file
    has it), else they're unknown."""
    dg_container = _dg_container(config_root)
    serial_dg: dict[str, str] = {}
    for entry in (dg_container.findall("entry") if dg_container is not None else []):
        for d in entry.findall("devices/entry"):
            if d.get("name") and entry.get("name"):
                serial_dg.setdefault(d.get("name"), entry.get("name"))
    template_container, stack_container = _template_containers(config_root)
    stacked = [d.get("name") for c in (stack_container, template_container) if c is not None
               for e in c.findall("entry") for d in e.findall("devices/entry") if d.get("name")]
    out = []
    for serial in dict.fromkeys([*serial_dg, *stacked]):
        stack, templates, configs = device_templates(config_root, serial)
        dg = serial_dg.get(serial)
        out.append({
            "serial": serial,
            "hostname": _template_hostname(configs) or (hostnames or {}).get(serial),
            "device_group": dg,
            "device_groups": device_group_chain(config_root, dg) if dg else [],
            "template_stack": stack,
            "templates": templates,
        })
    return sorted(out, key=lambda d: ((d["hostname"] or "~").lower(), d["serial"]))


def build_assessment_data_for_device(config_root: ET.Element, serial: str, hostname: Optional[str] = None) -> dict:
    """The effective configuration Panorama gives one firewall: Shared plus every device group from the
    top of its hierarchy down to its own, and the template stack it's assigned. Same AssessmentData
    shape as parser.parse_config(); local settings made on the firewall itself aren't in Panorama's
    config, so they aren't included."""
    device = next((d for d in list_devices(config_root) if d["serial"] == serial), None)
    if device is None:
        raise ValueError(f"Firewall with serial {serial} isn't managed by this Panorama")
    _, _, configs = device_templates(config_root, serial)
    _, hierarchy_known = device_group_parents(config_root)
    host = hostname or device["hostname"] or serial
    return _build(config_root, device["device_groups"], configs, host=host, serials=[serial], panorama={
        "mode": "device", "serial": serial, "device_groups": device["device_groups"],
        "template_stack": device["template_stack"], "templates": device["templates"],
        "hierarchy_known": hierarchy_known,
    })


def build_assessment_data(config_root: ET.Element, device_group_name: str) -> dict:
    """The effective policy for one device group (and the device groups above it), with templates from
    its reference-templates list. Assessments made before firewalls could be picked directly use this."""
    dg_container = _dg_container(config_root)
    if dg_container is None:
        raise ValueError("Not a Panorama export (no device-group found)")
    dg = next((e for e in dg_container.findall("entry") if e.get("name") == device_group_name), None)
    if dg is None:
        raise ValueError(f"Device group '{device_group_name}' not found in this export")
    template_container, stack_container = _template_containers(config_root)
    configs = _resolve_reference_configs(template_container, stack_container, members(dg, "reference-templates/member"))
    serials = [d.get("name") for d in dg.findall("devices/entry") if d.get("name")]
    _, hierarchy_known = device_group_parents(config_root)
    chain = device_group_chain(config_root, device_group_name)
    return _build(config_root, chain, configs, host=device_group_name, serials=serials, panorama={
        "mode": "device_group", "serial": None, "device_groups": chain,
        "template_stack": None, "templates": members(dg, "reference-templates/member"),
        "hierarchy_known": hierarchy_known,
    })


def _build(config_root: ET.Element, chain: list[str], resolved_configs: list[ET.Element], *, host: str,
           serials: list[str], panorama: dict) -> dict:
    """Resolve Shared plus the device groups in `chain` (top of the hierarchy first) and the template
    layers in `resolved_configs` (lowest priority first) into the AssessmentData shape.

    Order, as PAN-OS evaluates it: pre-rules from Shared, then each device group from the top of the
    hierarchy down; post-rules from the firewall's own device group back up the hierarchy, then Shared.
    Objects and profiles: a lower device group's same-named object wins (PAN-OS's default)."""
    dg_container = _dg_container(config_root)
    by_name = {e.get("name"): e for e in (dg_container.findall("entry") if dg_container is not None else [])}
    dgs = [(name, by_name[name]) for name in chain if name in by_name]
    shared = config_root.find("shared")
    leaf = dgs[-1][0] if dgs else None

    def rb(el: Optional[ET.Element], tag: str) -> Optional[ET.Element]:
        return el.find(tag) if el is not None else None

    # (rulebase element, scope label, owning device group) in evaluation order
    ordered = ([(rb(shared, "pre-rulebase"), "shared_pre", None)]
               + [(rb(dg, "pre-rulebase"), "device_group_pre", name) for name, dg in dgs]
               + [(rb(dg, "post-rulebase"), "device_group_post", name) for name, dg in reversed(dgs)]
               + [(rb(shared, "post-rulebase"), "shared_post", None)])

    def scoped(parse):
        out = []
        for container, label, owner in ordered:
            for r in parse(container, label):
                r["scope_name"] = owner
                out.append(r)
        return out

    rules = scoped(_parse_scoped_rules)
    decryption_rules = scoped(_parse_scoped_decryption_rules)
    nat_rules = scoped(_parse_scoped_nat_rules)

    # Object scopes, lowest priority first: Shared, then the hierarchy top-down.
    layers: list[tuple[str, ET.Element, Optional[str]]] = ([("shared", shared, None)] if shared is not None else []) + \
        [("device_group", dg, name) for name, dg in dgs]
    scope_els = [el for _, el, _ in layers]

    profile_entries: dict[str, dict[str, ET.Element]] = {}
    scope_name: dict[tuple[str, str], Optional[str]] = {}
    for key, tag in PROFILE_TYPE_TAGS.items():
        found: dict[str, ET.Element] = {}
        for _, el, owner in layers:
            for e in el.findall(f"profiles/{tag}/entry"):
                if e.get("name"):
                    found[e.get("name")] = e
                    scope_name[(key, e.get("name"))] = owner
        profile_entries[key] = found
    profiles: dict[str, list[str]] = {key: sorted(found.keys()) for key, found in profile_entries.items()}
    scope_of = profile_scopes([(label, el) for label, el, _ in layers])

    groups: list[dict] = []
    seen_group_names: set[str] = set()
    for _, el, _ in reversed(layers):  # the lowest device group's same-named group wins
        container = el.find("profile-group")
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
                "scope_name": scope_name.get((ptype, name)),
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

    zones = _merge_zones(resolved_configs)
    management = _merge_management_settings(resolved_configs)
    decryption_profile_els = [e for el in scope_els for e in el.findall("profiles/decryption/entry")]

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

    post_rulebases = [el for el in ([rb(shared, "post-rulebase")] + [rb(dg, "post-rulebase") for _, dg in dgs])
                      if el is not None]
    rulebases_in_order = [(el, label) for el, label, _ in ordered if el is not None]
    where = (f"firewall {host}" if panorama["mode"] == "device" else f"device group '{host}'")

    return {
        "panorama_managed": True,
        "panorama": panorama,
        "mgmt_interfaces": parse_mgmt_interfaces(interface_containers),
        "policy_objects": parse_policy_objects(scope_els),
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
            "hostname": host,
            "serial": ", ".join(serials) if serials else None,
            "reason": f"Resolved from a Panorama export ({where}) — "
                      "PAN-OS version and uptime require a live device connection.",
        },
        "licenses": {
            "available": False, "licenses": [],
            "reason": "License status requires a live device connection.",
        },
        "admin_accounts": [],
        "zones": zones,
        "device_group": leaf,
        "security_rules": rules,
        "nat_rules": nat_rules,
        "security_profiles": security_profiles,
        "profile_groups": profile_groups,
        "syslog_profiles": syslog_count,
        "ha": {"available": False, "reason": "HA state requires a live device connection."},
        "management": management,
        # Template layers are lowest priority first, the order parse_mgmt_plane expects.
        "mgmt_plane": parse_mgmt_plane(resolved_configs),
        "ha_config": parse_ha_config(resolved_configs),
        "vpn": parse_vpn(resolved_configs),
        "dos": parse_dos(scope_els, rulebases_in_order),
        "session_settings": parse_session_settings(resolved_configs),
        "log_forwarding_profiles": parse_log_forwarding_profiles(scope_els),
        "device_settings": parse_device_settings(resolved_configs),
        "identity": parse_identity(resolved_configs),
        "certificates": parse_certificates(resolved_configs),
        "object_usage": unavailable_for_panorama(),
        "misc_policy": parse_misc_policy([el for el, _ in rulebases_in_order], resolved_configs),
    }

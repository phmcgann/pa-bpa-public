"""
Source-agnostic PAN-OS config parsing.

Ported from the original collect_data.py's collect_*() functions, but split
from analysis: these functions only extract structured data from an already
-parsed xml.etree.ElementTree root. No "is this a problem" judgement happens
here — that lives in rules/checks.py.

Unlike collect_data.py (which calls the API once per xpath, so each response
is already scoped to that subtree), a full config export is one big tree, so
paths here are written to walk into the right subtree explicitly rather than
searching by bare tag name everywhere.

Two root shapes are supported:
  - A full PAN-OS "config" export (<config>...</config>) — the primary,
    current use case (file upload).
  - A PAN-OS XML API <response><result>...</result></response> wrapper for a
    single xpath, or an <response><result><system>...</system></result></response>
    op-command result — used by live_client.py in Phase 2. Both shapes nest
    the same tag names, so the same relative-path queries work on either.
"""

from __future__ import annotations

from typing import Optional
import xml.etree.ElementTree as ET

from .certificates import parse_certificates
from .object_usage import find_unused


EXPORT_HINT = (
    "Export it from the firewall with Device → Setup → Operations → Export named configuration snapshot, "
    "or upload a tech support file (.tgz)."
)
# Top-level sections every PAN-OS config export (firewall or Panorama) has at least one of.
CONFIG_SECTIONS = ("devices", "shared", "mgt-config")


def config_rejection(root: ET.Element) -> Optional[str]:
    """Why this parsed XML isn't a PAN-OS configuration export, or None if it is one.

    Uploads go through this before parsing: the parser is deliberately tolerant of missing
    sections, so any well-formed XML would otherwise become an assessment full of
    "not configured" findings.
    """
    if root.tag == "response":
        return ("This is a PAN-OS XML API response, not a configuration export. " + EXPORT_HINT)
    if root.tag != "config":
        return (f"This XML isn't a PAN-OS configuration — it starts with <{root.tag}>, and a configuration "
                f"export starts with <config>. " + EXPORT_HINT)
    if not any(root.find(section) is not None for section in CONFIG_SECTIONS):
        return ("This <config> file has none of the sections a PAN-OS configuration has "
                "(devices, shared, mgt-config). " + EXPORT_HINT)
    return None


def xml_text(element: Optional[ET.Element], path: str, default=None):
    if element is None:
        return default
    node = element.find(path)
    return node.text.strip() if node is not None and node.text else default


def xml_text_any(element: Optional[ET.Element], paths: list[str], default=None):
    """Like xml_text, but tries several candidate relative paths in order —
    for fields whose tag name varies across PAN-OS versions."""
    for path in paths:
        value = xml_text(element, path, None)
        if value is not None:
            return value
    return default


def members(entry: Optional[ET.Element], path: str) -> list[str]:
    if entry is None:
        return []
    return [m.text.strip() for m in entry.findall(path) if m.text]


# ── System info (runtime-only; unavailable from a config export) ──────────

def parse_system_info(config_root: ET.Element, op_root: Optional[ET.Element] = None) -> dict:
    """op_root is the <show><system><info> op-command result, only present
    in live mode (Phase 2). From a config file we can still surface the
    hostname, since it's part of deviceconfig/system."""
    device_system = config_root.find(".//deviceconfig/system")
    hostname = xml_text(device_system, "hostname", None)

    if op_root is not None:
        info = op_root.find(".//system")
        if info is not None:
            return {
                "available": True,
                "hostname": xml_text(info, "hostname", hostname or "N/A"),
                "ip_address": xml_text(info, "ip-address", "N/A"),
                "model": xml_text(info, "model", "N/A"),
                "serial": xml_text(info, "serial", "N/A"),
                "sw_version": xml_text(info, "sw-version", "N/A"),
                "app_version": xml_text(info, "app-version", "N/A"),
                "av_version": xml_text(info, "av-version", "N/A"),
                "wildfire_version": xml_text(info, "wildfire-version", "N/A"),
                "threat_version": xml_text(info, "threat-version", "N/A"),
                "uptime": xml_text(info, "uptime", "N/A"),
                "operational_mode": xml_text(info, "operational-mode", "N/A"),
            }

    return {
        "available": False,
        "hostname": hostname or "N/A",
        "reason": "PAN-OS version, serial, uptime, and content versions come from "
                  "a live 'show system info' call, not the config file. Connect a "
                  "live device to populate this section.",
    }


# ── Licenses (runtime-only) ────────────────────────────────────────────────

def parse_licenses(op_root: Optional[ET.Element] = None) -> dict:
    if op_root is None:
        return {
            "available": False,
            "licenses": [],
            "reason": "License status comes from a live 'request license info' call, "
                      "not the config file. Connect a live device to populate this section.",
        }
    licenses = []
    for lic in op_root.findall(".//entry"):
        licenses.append({
            "feature": xml_text(lic, "feature", "N/A"),
            "expires": xml_text(lic, "expires", "N/A"),
            "expired": xml_text(lic, "expired", "no"),
        })
    return {"available": True, "licenses": licenses}


# ── Admin accounts ──────────────────────────────────────────────────────────

def parse_admin_accounts(config_root: ET.Element) -> list[dict]:
    admins = []
    for entry in config_root.findall(".//mgt-config/users/entry"):
        name = entry.get("name", "unknown")
        # Skip saved log query entries — they share this XML path but only
        # contain a <query> element, not <phash>/<permissions>/<authentication-profile>.
        is_real_admin = (
            entry.find("phash") is not None
            or entry.find("authentication-profile") is not None
            or entry.find("permissions") is not None
        )
        if not is_real_admin:
            continue
        admins.append({
            "name": name,
            "role": xml_text(entry, "permissions/role-based/superuser", ""),
            "auth_profile": xml_text(entry, "authentication-profile", "local"),
        })
    return admins


# ── Security zones ───────────────────────────────────────────────────────

ZONE_MEMBER_TYPES = ("layer3", "layer2", "virtual-wire", "tap")


def parse_zone_entry(entry: ET.Element) -> dict:
    """Shared by the flat-config and Panorama-template paths."""
    mode = (
        "layer3" if entry.find(".//layer3") is not None else
        "layer2" if entry.find(".//layer2") is not None else "other"
    )
    return {
        "name": entry.get("name", "unknown"),
        "mode": mode,
        "user_id": xml_text(entry, "enable-user-identification", "no") == "yes",
        # On by default since PAN-OS 10.0; only an explicit "no" turns it off.
        "packet_buffer_protection": xml_text(entry, "network/enable-packet-buffer-protection", "yes") != "no",
        "zone_protection_profile": xml_text(entry, "network/zone-protection-profile", None),
        "interfaces": [m for t in ZONE_MEMBER_TYPES for m in members(entry, f"network/{t}/member")],
    }


def parse_zones(config_root: ET.Element) -> list[dict]:
    return [parse_zone_entry(e) for e in config_root.findall(".//vsys/entry/zone/entry")]


# ── Security policy rules ──────────────────────────────────────────────────

def parse_rule_entry(entry: ET.Element, rule_scope: Optional[str] = None) -> dict:
    """Extract one security rule <entry>'s fields. Shared by the flat-rulebase
    path here and by panorama_parser.py's shared/pre-rulebase/post-rulebase
    traversal, so field handling never diverges between the two.

    rule_scope: for Panorama-resolved rules, which rulebase this came from
    ("shared_pre" | "device_group_pre" | "device_group_post" | "shared_post").
    None for a standalone firewall's own flat rulebase."""
    name = entry.get("name", "unknown")

    profiles_el = entry.find("profile-setting/profiles")
    indiv_profiles = {}
    if profiles_el is not None:
        for ptype in profiles_el:
            mem = [m.text.strip() for m in ptype.findall("member") if m.text]
            if mem:
                indiv_profiles[ptype.tag] = mem
    profile_group = xml_text(entry, "profile-setting/group/member", None)

    return {
        "name": name,
        "action": xml_text(entry, "action", "allow"),
        "disabled": xml_text(entry, "disabled", "no"),
        "log_end": xml_text(entry, "log-end", "no"),
        "log_start": xml_text(entry, "log-start", "no"),
        "disable_server_response_inspection": xml_text(entry, "option/disable-server-response-inspection", "no") == "yes",
        "description": xml_text(entry, "description", ""),
        "profile_group": (profile_group or "").strip(),
        "indiv_profiles": indiv_profiles,
        "from_zones": members(entry, "from/member"),
        "to_zones": members(entry, "to/member"),
        "sources": members(entry, "source/member"),
        "destinations": members(entry, "destination/member"),
        "applications": members(entry, "application/member"),
        "services": members(entry, "service/member"),
        "tags": members(entry, "tag/member"),
        "source_users": members(entry, "source-user/member"),
        # universal (default) | intrazone | interzone — which zone pairs the rule can match
        "rule_type": xml_text(entry, "rule-type", "universal"),
        "log_setting": xml_text(entry, "log-setting", None),
        "negate_source": xml_text(entry, "negate-source", "no"),
        "negate_destination": xml_text(entry, "negate-destination", "no"),
        # Remaining match criteria, for the rulebase (shadowing) analysis.
        "category": members(entry, "category/member"),
        "source_hip": members(entry, "source-hip/member"),
        "destination_hip": members(entry, "destination-hip/member"),
        "schedule": xml_text(entry, "schedule", None),
        # A Panorama rule targeted at particular firewalls may not apply to this one.
        "targeted": entry.find("target/devices/entry") is not None or xml_text(entry, "target/negate", "no") == "yes",
        "rule_scope": rule_scope,
    }


def parse_security_rules(config_root: ET.Element) -> list[dict]:
    """Rules in rulebase order, each tagged with its vsys (rules in different vsys never interact)."""
    return [
        {**parse_rule_entry(entry), "vsys": vsys.get("name")}
        for vsys in config_root.findall(".//vsys/entry")
        for entry in vsys.findall("rulebase/security/rules/entry")
    ]


# ── NAT policy rules ───────────────────────────────────────────────────
#
# rulebase/nat/rules/entry (pan-os-codegen policies/nat-policy spec). NAT matches on the
# pre-NAT packet: the destination zone and address are the ones the packet arrives for, so an
# inbound port forward's destination is the public address and its to-zone the outside zone.

def _nat_source_translation(entry: ET.Element) -> Optional[dict]:
    st = entry.find("source-translation")
    if st is None:
        return None
    dipp = st.find("dynamic-ip-and-port")
    if dipp is not None:
        return {"type": "dynamic-ip-and-port", "translated": members(dipp, "translated-address/member"),
                "interface": xml_text(dipp, "interface-address/interface", None), "bidirectional": False}
    dip = st.find("dynamic-ip")
    if dip is not None:
        return {"type": "dynamic-ip", "translated": members(dip, "translated-address/member"),
                "interface": None, "bidirectional": False}
    static = st.find("static-ip")
    if static is not None:
        return {"type": "static-ip", "translated": [t] if (t := xml_text(static, "translated-address", None)) else [],
                "interface": None, "bidirectional": xml_text(static, "bi-directional", "no") == "yes"}
    return None


def _nat_destination_translation(entry: ET.Element) -> Optional[dict]:
    for tag, kind in (("destination-translation", "static"), ("dynamic-destination-translation", "dynamic")):
        dt = entry.find(tag)
        if dt is not None:
            return {"type": kind, "address": xml_text(dt, "translated-address", None),
                    "port": xml_text(dt, "translated-port", None)}
    return None


def parse_nat_rule_entry(entry: ET.Element, rule_scope: Optional[str] = None) -> dict:
    return {
        "name": entry.get("name", "unknown"),
        "disabled": xml_text(entry, "disabled", "no") == "yes",
        "description": xml_text(entry, "description", ""),
        "nat_type": xml_text(entry, "nat-type", "ipv4"),
        "from_zones": members(entry, "from/member"),
        "to_zones": members(entry, "to/member"),
        "to_interface": xml_text(entry, "to-interface", "any"),
        "sources": members(entry, "source/member"),
        "destinations": members(entry, "destination/member"),
        "service": xml_text(entry, "service", "any"),
        "source_translation": _nat_source_translation(entry),
        "destination_translation": _nat_destination_translation(entry),
        "targeted": entry.find("target/devices/entry") is not None or xml_text(entry, "target/negate", "no") == "yes",
        "rule_scope": rule_scope,
    }


def parse_nat_rules(config_root: ET.Element) -> list[dict]:
    return [
        {**parse_nat_rule_entry(entry), "vsys": vsys.get("name")}
        for vsys in config_root.findall(".//vsys/entry")
        for entry in vsys.findall("rulebase/nat/rules/entry")
    ]


# ── Security profiles (individual profiles + profile groups) ────────────

# Maps our normalized profile-type keys to the PAN-OS XML tag used both for
# the profile object container (profiles/<tag>/entry) and for a profile
# group's per-type member list (profile-group entry's <tag><member>...).
PROFILE_TYPE_TAGS = {
    "antivirus": "virus",
    "vulnerability": "vulnerability",
    "spyware": "spyware",
    "url_filtering": "url-filtering",
    "wildfire_analysis": "wildfire-analysis",
    "file_blocking": "file-blocking",
}


def parse_security_profile_entries(config_root: ET.Element) -> dict[str, dict[str, ET.Element]]:
    """Same profile discovery as parse_security_profiles, but keyed by name to
    the raw <entry> element instead of just the name — needed to read what's
    actually configured inside the profile, not just that it exists."""
    result: dict[str, dict[str, ET.Element]] = {}
    for key, tag in PROFILE_TYPE_TAGS.items():
        by_name: dict[str, ET.Element] = {}
        for e in config_root.findall(f".//profiles/{tag}/entry"):
            name = e.get("name")
            if name:
                by_name[name] = e
        result[key] = by_name
    return result


def profile_scopes(scopes: list[tuple[str, Optional[ET.Element]]]) -> dict[tuple[str, str], str]:
    """(profile type, name) → the scope that defines it: "shared", a vsys name, or on Panorama
    "device_group". `scopes` are lowest priority first; a later scope's same-named profile wins, as it
    does in the parsed settings. CLI commands need it: shared profiles live at `shared profiles …`."""
    out: dict[tuple[str, str], str] = {}
    for label, el in scopes:
        if el is None:
            continue
        for key, tag in PROFILE_TYPE_TAGS.items():
            for e in el.findall(f"profiles/{tag}/entry"):
                if e.get("name"):
                    out[(key, e.get("name"))] = label
    return out


def parse_security_profiles(config_root: ET.Element) -> dict[str, list[str]]:
    """Individual security profile objects defined in the config, by type."""
    return {key: list(by_name.keys()) for key, by_name in parse_security_profile_entries(config_root).items()}


# ── Security profile settings (what's actually configured inside a profile) ──
#
# Every value/tag name below was read directly off a real profile in a real
# PAN-OS 11.1 tech support file, not assumed — see the "Security Profile
# Audit" comparison this was built from. The one exception is Inline Cloud
# Analysis (Anti-Spyware/Vulnerability Protection): the reference firewall
# had no Advanced Threat Prevention license, so its tags come from Palo
# Alto's pan-os-codegen specs instead (anti-spyware-profile.yaml,
# vulnerability.yaml) — cloud-inline-analysis, and per-model
# mica-engine-{spyware,vulnerability}-enabled/entry/inline-policy-action,
# whose spec default is "alert".

def _single_child_tag(el: Optional[ET.Element], default: str = "default") -> str:
    """PAN-OS often encodes an enum as the tag name of <parent>'s one child,
    e.g. <action><reset-both/></action> rather than <action>reset-both</action>."""
    if el is None:
        return default
    children = list(el)
    return children[0].tag if children else default


def _parse_severity_rules(entry: ET.Element, include_host: bool = False) -> list[dict]:
    rules = []
    for r in entry.findall("rules/entry"):
        rule = {
            "name": r.get("name"),
            "severities": members(r, "severity/member"),
            "action": _single_child_tag(r.find("action")),
            "packet_capture": xml_text(r, "packet-capture", "disable"),
        }
        if include_host:
            rule["host"] = xml_text(r, "host", None)
        rules.append(rule)
    return rules


def _parse_inline_cloud_analysis(entry: ET.Element, engine_tag: str) -> dict:
    """The feature is opt-in (Palo Alto's docs have you enable it per profile),
    so an absent <cloud-inline-analysis> reads as off."""
    return {
        "enabled": xml_text(entry, "cloud-inline-analysis", "no") == "yes",
        "models": {
            m.get("name"): xml_text(m, "inline-policy-action", "alert")
            for m in entry.findall(f"{engine_tag}/entry") if m.get("name")
        },
    }


def _parse_antivirus_settings(entry: ET.Element) -> dict:
    decoders = {}
    for d in entry.findall("decoder/entry"):
        name = d.get("name")
        if not name:
            continue
        decoders[name] = {
            "action": xml_text(d, "action", "default"),
            "wildfire_action": xml_text(d, "wildfire-action", "default"),
            "mlav_action": xml_text(d, "mlav-action", "default"),
        }
    inline_ml = {}
    for m in entry.findall("mlav-engine-filebased-enabled/entry"):
        name = m.get("name")
        if name:
            inline_ml[name] = xml_text(m, "mlav-policy-action", "default")
    return {
        "decoders": decoders,
        "packet_capture": xml_text(entry, "packet-capture", "no") == "yes",
        "inline_ml": inline_ml,
        "threat_exceptions": [e.get("name") for e in entry.findall("threat-exception/entry") if e.get("name")],
        "app_exceptions": [e.get("name") for e in entry.findall("application/entry") if e.get("name")],
        # Hold for WildFire Real Time Signature Lookup (PAN-OS 11.0.2+, pan-os-codegen antivirus spec).
        "wfrt_hold_mode": xml_text(entry, "wfrt-hold-mode", "no") == "yes",
    }


def _parse_spyware_settings(entry: ET.Element) -> dict:
    dns_categories = {}
    for c in entry.findall("botnet-domains/dns-security-categories/entry"):
        name = c.get("name")
        if name:
            dns_categories[name] = {
                "action": xml_text(c, "action", "default"),
                "packet_capture": xml_text(c, "packet-capture", "disable"),
            }
    whitelist = [
        {"name": w.get("name"), "description": xml_text(w, "description", "")}
        for w in entry.findall("botnet-domains/whitelist/entry") if w.get("name")
    ]
    return {
        "severity_rules": _parse_severity_rules(entry),
        "dns_sinkhole_enabled": entry.find("botnet-domains/sinkhole") is not None,
        "dns_categories": dns_categories,
        "whitelist": whitelist,
        "threat_exceptions": [e.get("name") for e in entry.findall("threat-exception/entry") if e.get("name")],
        "inline_cloud_analysis": _parse_inline_cloud_analysis(entry, "mica-engine-spyware-enabled"),
    }


def _parse_vulnerability_settings(entry: ET.Element) -> dict:
    exceptions = []
    for e in entry.findall("threat-exception/entry"):
        eid = e.get("name")
        if not eid:
            continue
        exceptions.append({
            "id": eid,
            "action": _single_child_tag(e.find("action")),
            "exempt_ips": [x.get("name") for x in e.findall("exempt-ip/entry") if x.get("name")],
        })
    return {
        "severity_rules": _parse_severity_rules(entry, include_host=True),
        "threat_exceptions": exceptions,
        "inline_cloud_analysis": _parse_inline_cloud_analysis(entry, "mica-engine-vulnerability-enabled"),
    }


def _parse_url_filtering_settings(entry: ET.Element) -> dict:
    return {
        "block_categories": members(entry, "block/member"),
        "alert_categories": members(entry, "alert/member"),
        "allow_categories": members(entry, "allow/member"),
        "continue_categories": members(entry, "continue/member"),
        "override_categories": members(entry, "override/member"),
        "credential_alert_categories": members(entry, "credential-enforcement/alert/member"),
        "credential_continue_categories": members(entry, "credential-enforcement/continue/member"),
        "credential_allow_categories": members(entry, "credential-enforcement/allow/member"),
        "credential_enforcement_mode": _single_child_tag(entry.find("credential-enforcement/mode"), "disabled"),
        "credential_enforcement_block_categories": members(entry, "credential-enforcement/block/member"),
        "log_container_page_only": xml_text(entry, "log-container-page-only", "no") == "yes",
        "local_inline_cat": xml_text(entry, "local-inline-cat", "no") == "yes",
        "cloud_inline_cat": xml_text(entry, "cloud-inline-cat", "no") == "yes",
    }


def _parse_wildfire_settings(entry: ET.Element) -> dict:
    rules = []
    for r in entry.findall("rules/entry"):
        rules.append({
            "name": r.get("name"),
            "applications": members(r, "application/member"),
            "file_types": members(r, "file-type/member"),
            "direction": xml_text(r, "direction", "both"),
            "analysis": xml_text(r, "analysis", "public-cloud"),
        })
    return {"rules": rules,
            # Palo Alto SCM failed-field name cloud_inline_analysis (check #363); Advanced WildFire only.
            "inline_cloud_analysis": xml_text(entry, "cloud-inline-analysis", "no") == "yes"}


def _parse_file_blocking_settings(entry: ET.Element) -> dict:
    rules = []
    for r in entry.findall("rules/entry"):
        rules.append({
            "name": r.get("name"),
            "action": xml_text(r, "action", "alert"),
            "direction": xml_text(r, "direction", "both"),
            "applications": members(r, "application/member"),
            "file_types": members(r, "file-type/member"),
        })
    return {"rules": rules}


PROFILE_SETTINGS_PARSERS = {
    "antivirus": _parse_antivirus_settings,
    "spyware": _parse_spyware_settings,
    "vulnerability": _parse_vulnerability_settings,
    "url_filtering": _parse_url_filtering_settings,
    "wildfire_analysis": _parse_wildfire_settings,
    "file_blocking": _parse_file_blocking_settings,
}


def parse_profile_settings(entry: ET.Element, ptype: str) -> dict:
    parser_fn = PROFILE_SETTINGS_PARSERS.get(ptype)
    return parser_fn(entry) if parser_fn else {}


def parse_profile_groups(config_root: ET.Element) -> list[dict]:
    """Security profile groups: name + the individual profiles each one bundles.

    <profile-group> is a sibling of <profiles> (both direct children of the
    vsys/shared entry), not nested inside it — verified against a real PAN-OS
    11.1 config export. An earlier version of this parser searched
    ".//profiles/profile-group/entry", which never matches anything."""
    groups = []
    for entry in config_root.findall(".//profile-group/entry"):
        name = entry.get("name")
        if not name:
            continue
        member_profiles = {}
        for key, tag in PROFILE_TYPE_TAGS.items():
            mem = members(entry, f"{tag}/member")
            if mem:
                member_profiles[key] = mem
        groups.append({"name": name, "members": member_profiles,
                       "data_filtering": members(entry, "data-filtering/member")})
    return groups


def compute_profile_usage(security_rules: list[dict], profiles: dict[str, list[str]],
                           groups: list[dict]) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    """How many security rules reference each individual profile (directly, or
    indirectly via a profile group) and each profile group (directly)."""
    group_by_name = {g["name"]: g for g in groups}
    profile_rule_counts = {ptype: {name: 0 for name in names} for ptype, names in profiles.items()}
    group_rule_counts = {g["name"]: 0 for g in groups}

    for rule in security_rules:
        group_name = (rule.get("profile_group") or "").strip()
        if group_name and group_name in group_by_name:
            group_rule_counts[group_name] += 1
            for ptype, names in group_by_name[group_name]["members"].items():
                for name in names:
                    if name in profile_rule_counts.get(ptype, {}):
                        profile_rule_counts[ptype][name] += 1

        tag_to_type = {tag: key for key, tag in PROFILE_TYPE_TAGS.items()}
        for tag, names in rule.get("indiv_profiles", {}).items():
            ptype = tag_to_type.get(tag)
            if not ptype:
                continue
            for name in names:
                if name in profile_rule_counts.get(ptype, {}):
                    profile_rule_counts[ptype][name] += 1

    return profile_rule_counts, group_rule_counts


# ── Decryption, zone protection, interface management profiles ───────────
#
# Unlike everything above, these tag names weren't read off a real export —
# the reference firewall's config isn't available in every environment this
# gets built in. They come from Palo Alto's own schema definitions instead:
# the pan-os-codegen specs (github.com/PaloAltoNetworks/pan-os-codegen,
# specs/objects/profiles/decryption-profile.yaml, specs/policies/decryption-
# policy.yaml, specs/network/profiles/zone-protection.yaml, specs/network/
# profiles/interface-management-profile.yaml) and the pango Go structs
# generated from them. Where the spec declares no default for a boolean,
# callers only act on an explicit value, never on absence.

def parse_decryption_rule_entry(entry: ET.Element, rule_scope: Optional[str] = None) -> dict:
    type_el = entry.find("type")
    return {
        "name": entry.get("name", "unknown"),
        # Spec default is no-decrypt when <action> is absent.
        "action": xml_text(entry, "action", "no-decrypt"),
        "disabled": xml_text(entry, "disabled", "no"),
        "type": _single_child_tag(type_el, "unknown"),
        "profile": xml_text(entry, "profile", None),
        "rule_scope": rule_scope,
    }


def parse_decryption_rules(config_root: ET.Element) -> list[dict]:
    return [
        parse_decryption_rule_entry(entry)
        for entry in config_root.findall(".//vsys/entry/rulebase/decryption/rules/entry")
    ]


def _yes_no(el: Optional[ET.Element], path: str) -> Optional[bool]:
    """True/False for an explicit yes/no, None when the element is absent."""
    value = xml_text(el, path, None)
    if value is None:
        return None
    return value == "yes"


NON_QUANTUM_SAFE_CIPHERS = ("3des", "rc4", "aes-128-cbc", "aes-256-cbc", "aes-128-gcm")
INBOUND_CHECKS = ("block-unsupported-version", "block-unsupported-cipher", "block-if-no-resource",
                  "block-if-hsm-unavailable", "block-tls13-downgrade-no-resource")
SSH_CHECKS = ("block-unsupported-version", "block-unsupported-alg", "block-ssh-errors", "block-if-no-resource")


def parse_decryption_profile_entry(entry: ET.Element) -> dict:
    return {
        "name": entry.get("name"),
        # Spec default is tls1-0 when <min-version> is absent.
        "min_version": xml_text(entry, "ssl-protocol-settings/min-version", "tls1-0"),
        "min_version_explicit": entry.find("ssl-protocol-settings/min-version") is not None,
        "forward_proxy_block_expired": _yes_no(entry, "ssl-forward-proxy/block-expired-certificate"),
        "forward_proxy_block_untrusted": _yes_no(entry, "ssl-forward-proxy/block-untrusted-issuer"),
        # Server-certificate checks applied to traffic a no-decrypt rule leaves encrypted.
        "no_proxy_block_expired": _yes_no(entry, "ssl-no-proxy/block-expired-certificate"),
        "no_proxy_block_untrusted": _yes_no(entry, "ssl-no-proxy/block-untrusted-issuer"),
        # SSL Inbound Inspection and SSH Proxy unsupported-mode/failure checks (pan-os-codegen
        # decryption-profile spec; Palo Alto SCM checks #56 and #59), all off unless set.
        "inbound_checks": {opt: xml_text(entry, f"ssl-inbound-proxy/{opt}", "no") == "yes" for opt in INBOUND_CHECKS},
        "ssh_checks": {opt: xml_text(entry, f"ssh-proxy/{opt}", "no") == "yes" for opt in SSH_CHECKS},
        # HMAC algorithms allowed for decrypted sessions. SHA-1 is allowed unless turned off; Palo Alto
        # SCM check #372 fails the predefined default profile on SHA-1 but not MD5.
        "auth_algo_sha1": xml_text(entry, "ssl-protocol-settings/auth-algo-sha1", "yes") != "no",
        "auth_algo_md5": xml_text(entry, "ssl-protocol-settings/auth-algo-md5", "no") == "yes",
        # Encryption algorithms still allowed (each is on unless turned off; Palo Alto SCM check #371
        # fails the predefined default profile on all of these), and PQC key exchange (#375, off).
        "legacy_ciphers": [a for a in NON_QUANTUM_SAFE_CIPHERS
                           if xml_text(entry, f"ssl-protocol-settings/enc-algo-{a}", "yes") != "no"],
        "pqc_key_exchange": any(xml_text(entry, f"ssl-protocol-settings/keyxchg-algo-{k}", "no") == "yes"
                                for k in ("pqc-standardized", "pqc-non-standardized")),
    }


def parse_decryption_profiles_from(elements: list[ET.Element]) -> list[dict]:
    by_name: dict[str, dict] = {}
    for e in elements:
        if e.get("name"):
            by_name[e.get("name")] = parse_decryption_profile_entry(e)
    return list(by_name.values())


def parse_decryption(config_root: ET.Element) -> dict:
    return {
        "rules": parse_decryption_rules(config_root),
        "profiles": parse_decryption_profiles_from(config_root.findall(".//profiles/decryption/entry")),
    }


FLOOD_TYPES = ["tcp-syn", "udp", "icmp", "icmpv6", "other-ip"]
# Packet-based attack protection options Palo Alto's DoS and Zone Protection best practices say to
# turn on (IP Drop and TCP Drop), as element names in the pan-os-codegen zone-protection spec.
PACKET_BASED_OPTIONS = ("discard-ip-spoof", "discard-strict-source-routing", "discard-loose-source-routing",
                        "discard-malformed-option", "discard-unknown-option",
                        "discard-overlapping-tcp-segment-mismatch", "discard-tcp-split-handshake",
                        "remove-tcp-timestamp")


def parse_zone_protection_profile_entry(entry: ET.Element) -> dict:
    flood = {ftype: _yes_no(entry, f"flood/{ftype}/enable") for ftype in FLOOD_TYPES}
    syn = entry.find("flood/tcp-syn")
    syn_action = None
    if syn is not None:
        syn_action = "syn-cookies" if syn.find("syn-cookies") is not None else (
            "red" if syn.find("red") is not None else None)
    # A <scan><entry> only exists for a reconnaissance type that's been enabled.
    scans = [
        {"id": s.get("name"), "action": _single_child_tag(s.find("action"), "unknown")}
        for s in entry.findall("scan/entry") if s.get("name")
    ]
    return {
        "name": entry.get("name"),
        "flood": flood,
        "syn_action": syn_action,
        "scans": scans,
        "packet_based": {opt: xml_text(entry, opt, "no") == "yes" for opt in PACKET_BASED_OPTIONS},
    }


def parse_zone_protection_profiles_from(elements: list[ET.Element]) -> list[dict]:
    by_name: dict[str, dict] = {}
    for e in elements:
        if e.get("name"):
            by_name[e.get("name")] = parse_zone_protection_profile_entry(e)
    return list(by_name.values())


def parse_interface_mgmt_profiles_from(elements: list[ET.Element]) -> list[dict]:
    by_name: dict[str, dict] = {}
    for e in elements:
        name = e.get("name")
        if not name:
            continue
        by_name[name] = {
            "name": name,
            "services": {
                svc: xml_text(e, svc, None) == "yes"
                for svc in ("https", "ssh", "ping", "snmp", "http", "http-ocsp", "telnet")
            },
            "permitted_ip": [p.get("name") for p in e.findall("permitted-ip/entry") if p.get("name")],
            "interfaces": [],
        }
    return list(by_name.values())


def attach_mgmt_profile_interfaces(profiles: list[dict], interface_containers: list[ET.Element]) -> None:
    """Record which interfaces reference each profile. The reference lives on
    the interface entry itself (loopback/tunnel/vlan/subinterface units) or
    under its <layer3> (ethernet/aggregate), depending on interface type."""
    by_name = {p["name"]: p for p in profiles}
    for container in interface_containers:
        for iface in container.iter("entry"):
            ref = xml_text(iface, "interface-management-profile", None) or \
                xml_text(iface, "layer3/interface-management-profile", None)
            if ref and ref in by_name and iface.get("name") not in by_name[ref]["interfaces"]:
                by_name[ref]["interfaces"].append(iface.get("name"))


def parse_network_profiles(config_root: ET.Element) -> tuple[list[dict], list[dict]]:
    zpp = parse_zone_protection_profiles_from(
        config_root.findall(".//network/profiles/zone-protection-profile/entry"))
    mgmt = parse_interface_mgmt_profiles_from(
        config_root.findall(".//network/profiles/interface-management-profile/entry"))
    attach_mgmt_profile_interfaces(mgmt, config_root.findall(".//network/interface"))
    return zpp, mgmt


# ── Inputs for management-access reachability ────────────────────────────
#
# Shapes from the pan-os-codegen specs: interface ip/entry sits beside the
# interface-management-profile reference (network/interface/{ethernet,
# loopback,vlan}.yaml); address/{ip-netmask,ip-range,ip-wildcard,fqdn},
# address-group/{static,dynamic}, service/protocol/{tcp,udp}/port,
# {service,application}-group/members (objects/*.yaml); default rule
# overrides at <rulebase>/default-security-rules/rules/entry/action
# (policies/default-security-policy-rule.yaml).

def parse_mgmt_interfaces(interface_containers: list[ET.Element]) -> list[dict]:
    """Every interface with a management profile, with its static IPs. A later
    container's interface of the same name wins (Panorama template priority)."""
    by_name: dict[str, dict] = {}
    for container in interface_containers:
        for iface in container.iter("entry"):
            ctx = iface if iface.find("interface-management-profile") is not None else iface.find("layer3")
            profile = xml_text(ctx, "interface-management-profile", None) if ctx is not None else None
            if not profile or not iface.get("name"):
                continue
            by_name[iface.get("name")] = {
                "name": iface.get("name"),
                "mgmt_profile": profile,
                # A name here is a CIDR literal or an address object name.
                "ips": [e.get("name") for e in ctx.findall("ip/entry") if e.get("name")],
                "dhcp": ctx.find("dhcp-client") is not None,
            }
    return list(by_name.values())


ADDRESS_TYPES = ("ip-netmask", "ip-range", "ip-wildcard", "fqdn")


def parse_policy_objects(scopes: list[ET.Element]) -> dict:
    """Address/service/application objects and groups. Scopes are lowest
    priority first (shared, then vsys or device-group); a later scope's object
    replaces a same-named one."""
    objs: dict = {"addresses": {}, "address_groups": {}, "services": {}, "service_groups": {},
                  "application_groups": {}, "application_filters": [], "new_appid_filters": [],
                  "external_lists": {}}
    for scope in scopes:
        for e in scope.findall("address/entry"):
            for t in ADDRESS_TYPES:
                value = xml_text(e, t, None)
                if value and e.get("name"):
                    objs["addresses"][e.get("name")] = {"type": t, "value": value}
                    break
        for e in scope.findall("address-group/entry"):
            if e.get("name"):
                dynamic = e.find("dynamic") is not None
                objs["address_groups"][e.get("name")] = {
                    "dynamic": dynamic, "members": [] if dynamic else members(e, "static/member")}
        for e in scope.findall("service/entry"):
            if e.get("name"):
                objs["services"][e.get("name")] = {
                    "tcp": xml_text(e, "protocol/tcp/port", None),
                    "udp": xml_text(e, "protocol/udp/port", None),
                    "sctp": xml_text(e, "protocol/sctp/port", None),
                    "source_port": xml_text_any(e, ["protocol/tcp/source-port", "protocol/udp/source-port",
                                                    "protocol/sctp/source-port"], None),
                }
        for e in scope.findall("service-group/entry"):
            if e.get("name"):
                objs["service_groups"][e.get("name")] = members(e, "members/member")
        for e in scope.findall("application-group/entry"):
            if e.get("name"):
                objs["application_groups"][e.get("name")] = members(e, "members/member")
        # External dynamic lists (objects/external-dynamic-list.yaml): type/<kind>/url. A
        # predefined-ip list's url is the built-in list it wraps, e.g. panw-known-ip-list.
        for e in scope.findall("external-list/entry"):
            kind = _single_child_tag(e.find("type"), "unknown")
            if e.get("name"):
                objs["external_lists"][e.get("name")] = {
                    "type": kind,
                    "source": xml_text(e, f"type/{kind}/url", None),
                }
        # Application filters with "New App-ID" set (SCM API field new_appid) match App-IDs added by
        # recent content updates.
        objs["new_appid_filters"] += [e.get("name") for e in scope.findall("application-filter/entry")
                                      if e.get("name") and xml_text(e, "new-appid", "no") == "yes"
                                      and e.get("name") not in objs["new_appid_filters"]]
        objs["application_filters"] += [e.get("name") for e in scope.findall("application-filter/entry")
                                        if e.get("name") and e.get("name") not in objs["application_filters"]]
    return objs


def parse_default_rule_logging(rulebases: list[ET.Element]) -> dict[str, bool]:
    """Whether intrazone-default and interzone-default log at session end. Neither does unless
    overridden (Palo Alto SCM checks #12 and #13 fail a rulebase with no override)."""
    logging = {"intrazone-default": False, "interzone-default": False}
    for rb in rulebases:
        for e in rb.findall("default-security-rules/rules/entry"):
            if e.get("name") in logging and e.find("log-end") is not None:
                logging[e.get("name")] = xml_text(e, "log-end", "no") == "yes"
    return logging


def parse_default_rule_actions(rulebases: list[ET.Element]) -> dict[str, str]:
    """Overridden actions for intrazone-default / interzone-default, lowest
    priority first. Absent keys mean the rule isn't overridden."""
    actions: dict[str, str] = {}
    for rb in rulebases:
        for e in rb.findall("default-security-rules/rules/entry"):
            action = xml_text(e, "action", None)
            if e.get("name") in ("intrazone-default", "interzone-default") and action:
                actions[e.get("name")] = action
    return actions


# ── Log forwarding ───────────────────────────────────────────────────────

# ── GlobalProtect ────────────────────────────────────────────────────────
#
# Shapes from the pan-os-codegen specs (network/globalprotect-portal.yaml,
# device/globalprotect-gateway.yaml, objects/profiles/ssl-tls-service.yaml,
# device/authentication-profile.yaml, objects/profiles/certificate.yaml).
# Portals and gateways live in a vsys; the SSL/TLS service, certificate and
# authentication profiles they reference by name live in shared or a vsys.

TLS_RANK = {"sslv3": 0, "tls1-0": 1, "tls1-1": 2, "tls1-2": 3, "tls1-3": 4, "max": 9}
WEAK_TLS_ALGOS = {"enc-algo-3des": "3DES", "enc-algo-rc4": "RC4", "auth-algo-sha1": "SHA-1"}
AUTH_METHODS = ("local-database", "ldap", "radius", "tacplus", "saml-idp", "kerberos", "cloud")


def _by_name(scopes: list[ET.Element], path: str) -> dict[str, ET.Element]:
    """Entries at `path` across scopes; a later scope's same-named entry wins."""
    out: dict[str, ET.Element] = {}
    for scope in scopes:
        for e in scope.findall(path):
            if e.get("name"):
                out[e.get("name")] = e
    return out


def _tls_profile(name: Optional[str], tls: dict[str, ET.Element]) -> Optional[dict]:
    if not name:
        return None
    e = tls.get(name)
    if e is None:
        return {"name": name, "found": False}
    return {
        "name": name,
        "found": True,
        "min_version": xml_text(e, "protocol-settings/min-version", "tls1-0"),  # PAN-OS default
        "max_version": xml_text(e, "protocol-settings/max-version", "max"),
        "weak_algorithms": [label for tag, label in WEAK_TLS_ALGOS.items()
                            if xml_text(e, f"protocol-settings/{tag}", None) == "yes"],
    }


def _auth_profile(name: Optional[str], auth: dict[str, ET.Element], seqs: dict[str, ET.Element]) -> Optional[dict]:
    if not name:
        return None
    if name in seqs:
        members_ = members(seqs[name], "authentication-profiles/member")
        resolved = [_auth_profile(m, auth, {}) for m in members_]
        return {"name": name, "found": True, "sequence": True, "method": "sequence",
                "mfa": all(r and r.get("mfa") for r in resolved) if resolved else False,
                "members": [r for r in resolved if r]}
    e = auth.get(name)
    if e is None:
        return {"name": name, "found": False}
    method = next((m for m in AUTH_METHODS if e.find(f"method/{m}") is not None), "none")
    failed = xml_text(e, "lockout/failed-attempts", None)
    return {
        "name": name,
        "found": True,
        "sequence": False,
        "method": method,
        # A factor beyond the first: the profile's own MFA, or an IdP/RADIUS server that can
        # enforce one (the firewall can't see whether it does).
        "mfa": xml_text(e, "multi-factor-auth/mfa-enable", "no") == "yes",
        "external_mfa_capable": method in ("saml-idp", "radius", "cloud"),
        "lockout_attempts": int(failed) if failed and failed.isdigit() else 0,
    }


def _cert_profile(name: Optional[str], certs: dict[str, ET.Element]) -> Optional[dict]:
    if not name:
        return None
    e = certs.get(name)
    if e is None:
        return {"name": name, "found": False}
    return {
        "name": name,
        "found": True,
        "use_crl": xml_text(e, "use-crl", "no") == "yes",
        "use_ocsp": xml_text(e, "use-ocsp", "no") == "yes",
        "block_expired": xml_text(e, "block-expired-cert", "no") == "yes",
    }


def _cookie_lifetime_hours(el: Optional[ET.Element]) -> Optional[float]:
    """Accept-cookie lifetime in hours, or None if cookies aren't accepted."""
    if el is None or el.find("accept-cookie") is None:
        return None
    life = el.find("accept-cookie/cookie-lifetime")
    for tag, per_hour in (("lifetime-in-days", 24), ("lifetime-in-hours", 1), ("lifetime-in-minutes", 1 / 60)):
        v = xml_text(life, tag, None) if life is not None else None
        if v and v.isdigit():
            return int(v) * per_hour
    return 24.0  # PAN-OS default: 24 hours


def _client_auth(entry: ET.Element, auth, seqs, certs, tls) -> dict:
    return {
        "tls": _tls_profile(xml_text(entry, "ssl-tls-service-profile", None), tls),
        "auth_profiles": [
            {"name": a.get("name"), "os": xml_text(a, "os", "Any"),
             "profile": _auth_profile(xml_text(a, "authentication-profile", None), auth, seqs)}
            for a in entry.findall("client-auth/entry")
        ],
        "certificate_profile": _cert_profile(xml_text(entry, "certificate-profile", None), certs),
    }


def _app_config(cfg: ET.Element) -> dict[str, str]:
    """The portal agent config's App settings (gp-app-config name/value pairs)."""
    return {e.get("name"): (members(e, "value/member") or [""])[0]
            for e in cfg.findall("gp-app-config/config/entry") if e.get("name")}


def _agent_config(cfg: ET.Element) -> dict:
    app = _app_config(cfg)
    # Older configs keep a few of these outside gp-app-config.
    connect = app.get("connect-method") or xml_text(cfg, "agent-config/connect-method", None)
    override = app.get("agent-user-override") or xml_text(cfg, "agent-ui/agent-user-override", None)
    timeout = xml_text(cfg, "agent-ui/agent-user-override-timeout", None) or app.get("agent-user-override-timeout")
    collect_hip = xml_text(cfg, "hip-collection/collect-hip-data", None)
    return {
        "name": cfg.get("name"),
        # Defaults are the PAN-OS ones: User-logon (Always On), Allow (user may disable),
        # no disable timeout, enforcement off, HIP collection on, credentials saved.
        "connect_method": connect or "user-logon",
        "connect_method_set": connect is not None,
        "enforce_globalprotect": (app.get("enforce-globalprotect") or "no") == "yes",
        "user_override": override or "allowed",
        "override_timeout_min": int(timeout) if timeout and timeout.isdigit() else 0,
        "collect_hip": collect_hip != "no",
        "internal_gateways": len(cfg.findall("gateways/internal/list/entry")),
        "external_gateways": len(cfg.findall("gateways/external/list/entry")),
        "internal_host_detection": cfg.find("internal-host-detection") is not None
            or cfg.find("internal-host-detection-v6") is not None,
        "save_credentials": xml_text(cfg, "save-user-credentials", "1"),
        "cookie_lifetime_hours": _cookie_lifetime_hours(cfg.find("authentication-override")),
    }


def parse_globalprotect(profile_scopes: list[ET.Element], vsys_entries: list[ET.Element]) -> dict:
    """GlobalProtect portals and gateways with the profiles they reference resolved.
    `profile_scopes` is lowest priority first (shared, then vsys)."""
    tls = _by_name(profile_scopes, "ssl-tls-service-profile/entry")
    certs = _by_name(profile_scopes, "certificate-profile/entry")
    auth = _by_name(profile_scopes, "authentication-profile/entry")
    seqs = _by_name(profile_scopes, "authentication-sequence/entry")

    portals: dict[str, dict] = {}
    gateways: dict[str, dict] = {}
    for vsys in vsys_entries:
        location = vsys.get("name") or "vsys1"
        for p in vsys.findall("global-protect/global-protect-portal/entry"):
            pc = p.find("portal-config")
            sat = p.find("satellite-config")
            portals[p.get("name")] = {
                "name": p.get("name"),
                "location": location,
                "interface": xml_text(pc, "local-address/interface", None) if pc is not None else None,
                **(_client_auth(pc, auth, seqs, certs, tls) if pc is not None
                   else {"tls": None, "auth_profiles": [], "certificate_profile": None}),
                "root_ca": [e.get("name") for e in p.findall("client-config/root-ca/entry") if e.get("name")],
                "agent_configs": [_agent_config(c) for c in p.findall("client-config/configs/entry")],
                "satellite": {
                    "configured": sat is not None and len(sat.findall("configs/entry")) > 0,
                    "root_ca": [e.get("name") for e in p.findall("satellite-config/root-ca/entry") if e.get("name")],
                },
            }
        for g in vsys.findall("global-protect/global-protect-gateway/entry"):
            gateways[g.get("name")] = {
                "name": g.get("name"),
                "location": location,
                "interface": xml_text(g, "local-address/interface", None),
                **_client_auth(g, auth, seqs, certs, tls),
                "tunnel_mode": xml_text(g, "tunnel-mode", "no") == "yes",
                "client_configs": [
                    {
                        "name": c.get("name"),
                        "access_routes": members(c, "split-tunneling/access-route/member"),
                        "exclude_routes": members(c, "split-tunneling/exclude-access-route/member"),
                        "ip_pool": members(c, "ip-pool/member"),
                        "cookie_lifetime_hours": _cookie_lifetime_hours(c.find("authentication-override")),
                    }
                    for c in g.findall("remote-user-tunnel-configs/entry")
                ],
            }
    return {"portals": list(portals.values()), "gateways": list(gateways.values())}


def parse_syslog_profiles(config_root: ET.Element) -> int:
    """Syslog server profile objects live under <log-settings><syslog>, not
    under <server-profile> (that container holds LDAP/RADIUS/SAML auth server
    profiles instead) — verified against a real PAN-OS 11.1 config export."""
    return len(config_root.findall(".//log-settings/syslog/entry"))


# ── High availability (runtime-only) ───────────────────────────────────────

def parse_ha(op_root: Optional[ET.Element] = None) -> dict:
    if op_root is None:
        return {
            "available": False,
            "reason": "HA sync state comes from a live 'show high-availability state' "
                      "call, not the config file. Connect a live device to populate this section.",
        }
    enabled_el = op_root.find(".//enabled")
    ha_enabled = enabled_el is not None and enabled_el.text == "yes"
    result = {"available": True, "enabled": ha_enabled}
    if ha_enabled:
        result["local_state"] = xml_text(op_root, ".//group/local-info/state", "unknown")
        result["peer_state"] = xml_text(op_root, ".//group/peer-info/state", "unknown")
        result["sync_status"] = xml_text(op_root, ".//group/running-sync", "unknown")
    return result


# ── High-availability configuration ──────────────────────────────────────
#
# deviceconfig/high-availability, with element names confirmed against Palo Alto SCM BPA
# failed-field names for the HA checks (group.peer_ip_backup, interface.ha1.encryption.enabled,
# group.state_synchronization.ha2_keep_alive.enabled, group.mode.active_passive.passive_link_state,
# group.election_option.timers, group.monitoring.{link,path}_monitoring.*). Defaults are the
# ones Palo Alto's "Configure Active/Passive HA" guide states: config and session sync on,
# passive link state shutdown, HA timers Recommended; HA2 keep-alive, HA1 encryption and
# heartbeat backup are off unless selected.

PATH_GROUP_TYPES = ("virtual-wire", "vlan", "virtual-router", "logical-router")


def parse_ha_config(layers: list[ET.Element]) -> dict:
    """HA settings from the config. `layers` are <config>-shaped roots, lowest priority first;
    the highest-priority layer that has a high-availability section is used."""
    ha = None
    for layer in layers:
        el = layer.find("devices/entry/deviceconfig/high-availability")
        if el is not None:
            ha = el
    if ha is None or xml_text(ha, "enabled", "no") != "yes":
        return {"enabled": False}
    g = ha.find("group")
    mode_el = g.find("mode") if g is not None else None
    mode = _single_child_tag(mode_el, "active-passive") if mode_el is not None else "active-passive"
    link_groups = [
        {"name": e.get("name"), "interfaces": members(e, "interface/member"),
         "failure_condition": xml_text(e, "failure-condition", "any")}
        for e in (g.findall("monitoring/link-monitoring/link-group/entry") if g is not None else [])
    ]
    path_groups = [
        {"type": t, "name": e.get("name")}
        for t in PATH_GROUP_TYPES
        for e in (g.findall(f"monitoring/path-monitoring/path-group/{t}/entry") if g is not None else [])
    ]
    return {
        "enabled": True,
        "mode": mode,
        "group_id": xml_text(g, "group-id", None) if g is not None else None,
        "peer_ip": xml_text(g, "peer-ip", None) if g is not None else None,
        "peer_ip_backup": xml_text(g, "peer-ip-backup", None) if g is not None else None,
        "config_sync": xml_text(g, "configuration-synchronization/enabled", "yes") != "no",
        "session_sync": xml_text(g, "state-synchronization/enabled", "yes") != "no",
        "ha2_keep_alive": xml_text(g, "state-synchronization/ha2-keep-alive/enabled", "no") == "yes",
        "heartbeat_backup": xml_text(g, "election-option/heartbeat-backup", "no") == "yes",
        "preemptive": xml_text(g, "election-option/preemptive", "no") == "yes",
        "timers": _single_child_tag(g.find("election-option/timers"), "recommended") if g is not None else "recommended",
        "passive_link_state": xml_text(g, "mode/active-passive/passive-link-state", "shutdown") if g is not None else "shutdown",
        "session_owner": _single_child_tag(g.find("mode/active-active/session-owner-selection"), None)
                         if g is not None else None,
        "ha1_port": xml_text(ha, "interface/ha1/port", None),
        "ha1_encryption": xml_text(ha, "interface/ha1/encryption/enabled", "no") == "yes",
        "ha1_backup_port": xml_text(ha, "interface/ha1-backup/port", None),
        "ha2_port": xml_text(ha, "interface/ha2/port", None),
        "ha3_port": xml_text(ha, "interface/ha3/port", None),
        "link_monitoring": {
            "enabled": (xml_text(g, "monitoring/link-monitoring/enabled", "yes") if g is not None else "yes") != "no",
            "groups": link_groups,
        },
        "path_monitoring": {
            "enabled": (xml_text(g, "monitoring/path-monitoring/enabled", "yes") if g is not None else "yes") != "no",
            "groups": path_groups,
        },
    }


# ── DoS protection & session settings ──────────────────────────────────
#
# DoS Protection profiles (profiles/dos-protection, pan-os-codegen spec device/profiles/
# dos-protection) and DoS policy rules (rulebase/dos/rules). Flood rates not in the config are the
# PAN-OS defaults from that spec. Session settings: deviceconfig/setting/config/rematch and
# deviceconfig/setting/tcp/bypass-exceed-oo-queue, confirmed against Palo Alto SCM failed-field
# names (config.rematch, tcp.bypass_exceed_oo_queue).

DOS_FLOOD_TYPES = ("tcp-syn", "udp", "icmp", "icmpv6", "other-ip")
DOS_DEFAULT_RATES = {"red": (10000, 10000, 40000), "syn-cookies": (10000, 0, 1000000)}


def _dos_rates(flood: Optional[ET.Element]) -> Optional[dict]:
    if flood is None:
        return None
    method = "syn-cookies" if flood.find("syn-cookies") is not None else "red"
    el = flood.find(method)
    default = DOS_DEFAULT_RATES[method]
    alarm, activate, maximal = (int(v) if (v := xml_text(el, tag, None)) and v.isdigit() else d
                                for tag, d in zip(("alarm-rate", "activate-rate", "maximal-rate"), default))
    # The web interface pre-fills 10000/10000/40000 for every flood type, so those count as
    # untuned too (Palo Alto SCM check #50 flags the same values).
    return {"method": method, "alarm": alarm, "activate": activate, "max": maximal,
            "default": (alarm, activate, maximal) in (default, DOS_DEFAULT_RATES["red"])}


def _dos_profile(e: ET.Element) -> dict:
    flood = {t: xml_text(e, f"flood/{t}/enable", "no") == "yes" for t in DOS_FLOOD_TYPES}
    return {
        "name": e.get("name"),
        "type": xml_text(e, "type", "aggregate"),
        "flood": flood,
        "rates": {t: _dos_rates(e.find(f"flood/{t}")) for t in DOS_FLOOD_TYPES if flood[t]},
        "session_limit": (int(v) if (v := xml_text(e, "resource/sessions/max-concurrent-limit", None)) and v.isdigit()
                          else 32768) if xml_text(e, "resource/sessions/enabled", "no") == "yes" else None,
    }


def _dos_rule(e: ET.Element, scope: Optional[str]) -> dict:
    return {
        "name": e.get("name"),
        "scope": scope,
        "action": _single_child_tag(e.find("action"), "deny"),
        "aggregate_profile": xml_text(e, "protection/aggregate/profile", None),
        "classified_profile": xml_text(e, "protection/classified/profile", None),
        "from": members(e, "from/zone/member") or members(e, "from/interface/member"),
        "to": members(e, "to/zone/member") or members(e, "to/interface/member"),
        "disabled": xml_text(e, "disabled", "no") == "yes",
    }


def parse_dos(profile_scopes: list[ET.Element], rulebases: list[tuple[ET.Element, Optional[str]]]) -> dict:
    """DoS Protection profiles from each scope (a later scope's same-named profile wins) and
    DoS policy rules from each rulebase, in evaluation order."""
    profiles: dict[str, dict] = {}
    for scope in profile_scopes:
        for e in scope.findall("profiles/dos-protection/entry"):
            if e.get("name"):
                profiles[e.get("name")] = _dos_profile(e)
    rules = [_dos_rule(e, label) for rb, label in rulebases for e in rb.findall("dos/rules/entry") if e.get("name")]
    return {"profiles": [profiles[n] for n in sorted(profiles)], "rules": rules}


# PAN-OS session timeout defaults (seconds), from Palo Alto's SCM device-settings API spec
# (session-timeouts), whose field names mirror the XML elements under deviceconfig/setting/session.
SESSION_TIMEOUT_DEFAULTS = {
    "timeout-default": 30, "timeout-discard-default": 60, "timeout-discard-tcp": 90,
    "timeout-discard-udp": 60, "timeout-icmp": 6, "timeout-scan": 10, "timeout-tcp": 3600,
    "timeout-tcphandshake": 10, "timeout-tcpinit": 5, "timeout-tcp-half-closed": 120,
    "timeout-tcp-time-wait": 15, "timeout-tcp-unverified-rst": 30, "timeout-udp": 30,
}


def parse_session_settings(layers: list[ET.Element]) -> dict:
    """Global session/TCP settings. `layers` are <config>-shaped roots, lowest priority first.
    Unset values are PAN-OS defaults: rematch, accelerated aging and global Packet Buffer
    Protection on; forwarding past the out-of-order queue off. `timeouts` holds only the session
    timeouts the config sets."""
    rematch = bypass = aging = pbp = None
    timeouts: dict[str, int] = {}
    for layer in layers:
        setting = layer.find("devices/entry/deviceconfig/setting")
        rematch = xml_text(setting, "config/rematch", rematch)
        bypass = xml_text(setting, "tcp/bypass-exceed-oo-queue", bypass)
        aging = xml_text(setting, "session/accelerated-aging-enable", aging)
        pbp = xml_text(setting, "session/packet-buffer-protection-enable", pbp)
        for tag in SESSION_TIMEOUT_DEFAULTS:
            v = xml_text(setting, f"session/{tag}", None)
            if v is not None and v.isdigit():
                timeouts[tag] = int(v)
    return {"rematch": rematch != "no", "tcp_forward_oo_queue": bypass == "yes",
            "accelerated_aging": aging != "no", "packet_buffer_protection": pbp != "no",
            "timeouts": timeouts}


def parse_device_settings(layers: list[ET.Element]) -> dict:
    """Device > Setup settings behind Palo Alto SCM checks #89, #97, #102, #104 and #197, with
    element names from SCM's failed-field names and device-settings API spec. `layers` are
    <config>-shaped roots, lowest priority first; a later layer's value wins."""
    paths = {
        "cert_expiration_check": "setting/management/enable-certificate-expiration-check",
        "log_high_dp_load": "setting/management/enable-log-high-dp-load",
        "server_verification": "system/server-verification",
        "disable_http": "system/service/disable-http",
        "disable_telnet": "system/service/disable-telnet",
        "secure_conn_cert_type": "system/secure-conn-client/certificate-type",
        "telemetry_health": "system/device-telemetry/device-health-performance",
        "telemetry_usage": "system/device-telemetry/product-usage",
        "telemetry_threat": "system/device-telemetry/threat-prevention",
    }
    values: dict[str, Optional[str]] = dict.fromkeys(paths)
    cert_type = None
    for layer in layers:
        dc = layer.find("devices/entry/deviceconfig")
        for key, path in paths.items():
            values[key] = xml_text(dc, path, values.get(key))
        ct = dc.find(paths["secure_conn_cert_type"]) if dc is not None else None
        if ct is not None:
            cert_type = _single_child_tag(ct, "none")
    size_limits: dict[str, int] = {}
    grayware = None
    for layer in layers:
        wf = layer.find("devices/entry/deviceconfig/setting/wildfire")
        if wf is None:
            continue
        grayware = xml_text(wf, "report-grayware-file", grayware)
        for e in wf.findall("file-size-limit/entry"):
            v = xml_text(e, "size-limit", None)
            if e.get("name") and v and v.isdigit():
                size_limits[e.get("name")] = int(v)
    return {
        # Device > Setup > WildFire: per-file-type forwarding limits the config sets (in the file
        # type's own unit, MB or KB), and Report Grayware Files (off by default).
        "wildfire": {"size_limits": size_limits, "report_grayware": grayware == "yes"},
        # Off unless turned on.
        "cert_expiration_check": values["cert_expiration_check"] == "yes",
        "log_high_dp_load": values["log_high_dp_load"] == "yes",
        # On unless explicitly turned off.
        "server_verification": values["server_verification"] != "no",
        # The management interface's HTTP/Telnet count as enabled only when the config says so.
        "mgmt_http": values["disable_http"] == "no",
        "mgmt_telnet": values["disable_telnet"] == "no",
        # Secure Client Communication certificate: predefined unless a local or SCEP certificate is set
        # (Palo Alto SCM check #223 fields secure_conn_client.certificate_type.{local,scep}).
        "secure_conn_cert_type": cert_type or "none",
        "telemetry_off": [name for key, name in (("telemetry_health", "device health and performance"),
                                                 ("telemetry_usage", "product usage"),
                                                 ("telemetry_threat", "threat prevention"))
                          if values[key] == "no"],
    }


def parse_misc_policy(rulebases: list[ET.Element], layers: list[ET.Element]) -> dict:
    """Policy-based forwarding and Application Override rules from each rulebase, and GRE tunnels
    from the network layers (a later layer's same-named tunnel wins)."""
    gre: dict[str, dict] = {}
    for layer in layers:
        for e in layer.findall("devices/entry/network/tunnel/gre/entry"):
            if e.get("name"):
                gre[e.get("name")] = {"name": e.get("name"),
                                      "keep_alive": xml_text(e, "keep-alive/enable", "no") == "yes",
                                      "disabled": xml_text(e, "disabled", "no") == "yes"}
    pbf, app_override = [], []
    for rb in rulebases:
        for e in rb.findall("pbf/rules/entry"):
            pbf.append({"name": e.get("name"), "action": _single_child_tag(e.find("action"), "forward"),
                        "monitor_profile": xml_text(e, "action/forward/monitor/profile", None),
                        "disabled": xml_text(e, "disabled", "no") == "yes"})
        for e in rb.findall("application-override/rules/entry"):
            app_override.append({"name": e.get("name"), "application": xml_text(e, "application", None),
                                 "port": xml_text(e, "port", None), "protocol": xml_text(e, "protocol", None),
                                 "disabled": xml_text(e, "disabled", "no") == "yes"})
    return {"gre_tunnels": [gre[n] for n in sorted(gre)], "pbf_rules": pbf, "app_override_rules": app_override}


# ── Authentication, User-ID and certificate settings ───────────────────
#
# Authentication profiles and sequences, admin roles and SSL/TLS service profiles (shared or vsys;
# pan-os-codegen device/authentication-profile, device/adminrole and objects/profiles/ssl-tls-service
# specs), the vsys Authentication Portal (captive-portal) and User-ID collector settings. Portal and
# User-ID element names follow Palo Alto SCM's API fields for those objects.

def parse_identity(layers: list[ET.Element]) -> dict:
    """`layers` are <config>-shaped roots, lowest priority first; a later layer's same-named object wins."""
    auth: dict[str, dict] = {}
    seqs: dict[str, dict] = {}
    tls: dict[str, dict] = {}
    roles: set[str] = set()
    portal = None
    probing = mapping_timeout = None
    for layer in layers:
        scopes = [x for x in [layer.find("shared")] if x is not None] + layer.findall("devices/entry/vsys/entry")
        for scope in scopes:
            for e in scope.findall("authentication-profile/entry"):
                if e.get("name"):
                    fa = xml_text(e, "lockout/failed-attempts", None)
                    auth[e.get("name")] = {"name": e.get("name"),
                                           "method": _single_child_tag(e.find("method"), "none"),
                                           "failed_attempts": int(fa) if fa and fa.isdigit() else None,
                                           "allow_list": members(e, "allow-list/member")}
            for e in scope.findall("authentication-sequence/entry"):
                if e.get("name"):
                    seqs[e.get("name")] = {"name": e.get("name"),
                                           "profiles": members(e, "authentication-profiles/member")}
            for e in scope.findall("ssl-tls-service-profile/entry"):
                if e.get("name"):
                    tls[e.get("name")] = {"name": e.get("name"),
                                          "min_version": xml_text(e, "protocol-settings/min-version", "tls1-0"),
                                          "max_version": xml_text(e, "protocol-settings/max-version", "max")}
            roles.update(e.get("name") for e in scope.findall("admin-role/entry") if e.get("name"))
        for v in layer.findall("devices/entry/vsys/entry"):
            cp = v.find("captive-portal")
            if cp is not None:
                cookie = xml_text(cp, "mode/redirect/session-cookie/timeout", None)
                portal = {"mode": _single_child_tag(cp.find("mode"), "transparent"),
                          "timer": int(t) if (t := xml_text(cp, "timer", None)) and t.isdigit() else None,
                          "cookie_timeout": int(cookie) if cookie and cookie.isdigit() else None,
                          "tls_profile": xml_text(cp, "ssl-tls-service-profile", None)}
            uid = v.find("user-id-collector/setting")
            if uid is not None:
                probing = xml_text(uid, "enable-probing", probing)
                mapping_timeout = xml_text(uid, "enable-mapping-timeout", mapping_timeout)
    return {
        "auth_profiles": [auth[n] for n in sorted(auth)],
        "auth_sequences": [seqs[n] for n in sorted(seqs)],
        "tls_profiles": [tls[n] for n in sorted(tls)],
        "admin_roles": sorted(roles),
        "captive_portal": portal,
        # PAN-OS defaults: client probing off, User-ID mapping timeout on. Only explicit values change them.
        "user_id": {"probing": probing == "yes", "mapping_timeout": mapping_timeout != "no"},
    }


# ── Site-to-site VPN ─────────────────────────────────────────────────────
#
# network/ike/crypto-profiles/{ike,ipsec}-crypto-profiles, network/ike/gateway and
# network/tunnel/ipsec, with element names from the pan-os-codegen specs (ike-crypto-profile,
# ipsec-crypto-profile, ike-gateway, tunnels/ipsec). A profile a gateway or tunnel names but the
# config doesn't define is one of PAN-OS's predefined profiles, filled in from BUILT_IN_*.

def _lifetime_hours(el: Optional[ET.Element], default: float) -> float:
    if el is None:
        return default
    for unit, per_hour in (("days", 1 / 24), ("hours", 1), ("minutes", 60), ("seconds", 3600)):
        v = xml_text(el, unit, None)
        if v is not None and v.isdigit():
            return int(v) / per_hour
    return default


BUILT_IN_IKE_PROFILES = {
    "default": {"encryption": ["aes-128-cbc", "3des"], "hash": ["sha1"], "dh_groups": ["group2"], "lifetime_hours": 8},
    "Suite-B-GCM-128": {"encryption": ["aes-128-cbc"], "hash": ["sha256"], "dh_groups": ["group19"], "lifetime_hours": 8},
    "Suite-B-GCM-256": {"encryption": ["aes-256-cbc"], "hash": ["sha384"], "dh_groups": ["group20"], "lifetime_hours": 8},
}
BUILT_IN_IPSEC_PROFILES = {
    "default": {"protocol": "esp", "encryption": ["aes-128-cbc", "3des"], "authentication": ["sha1"],
                "dh_group": "group2", "lifetime_hours": 1},
    "Suite-B-GCM-128": {"protocol": "esp", "encryption": ["aes-128-gcm"], "authentication": ["none"],
                        "dh_group": "group19", "lifetime_hours": 1},
    "Suite-B-GCM-256": {"protocol": "esp", "encryption": ["aes-256-gcm"], "authentication": ["none"],
                        "dh_group": "group20", "lifetime_hours": 1},
}


def _ike_profile(e: ET.Element) -> dict:
    return {
        "encryption": members(e, "encryption/member"),
        "hash": members(e, "hash/member"),
        "dh_groups": members(e, "dh-group/member"),
        "lifetime_hours": _lifetime_hours(e.find("lifetime"), 8),
    }


def _ipsec_profile(e: ET.Element) -> dict:
    ah = e.find("ah")
    return {
        "protocol": "ah" if ah is not None else "esp",
        "encryption": [] if ah is not None else members(e, "esp/encryption/member"),
        "authentication": members(e, "ah/authentication/member") if ah is not None
                          else members(e, "esp/authentication/member"),
        "dh_group": xml_text(e, "dh-group", "group2"),
        "lifetime_hours": _lifetime_hours(e.find("lifetime"), 1),
    }


def _ike_gateway(e: ET.Element) -> dict:
    version = xml_text(e, "protocol/version", "ikev1")
    v1 = xml_text(e, "protocol/ikev1/ike-crypto-profile", "default")
    v2 = xml_text(e, "protocol/ikev2/ike-crypto-profile", "default")
    peer = e.find("peer-address")
    return {
        "name": e.get("name"),
        "version": version,
        "exchange_mode": xml_text(e, "protocol/ikev1/exchange-mode", "auto"),
        "ike_profiles": [v1] if version == "ikev1" else [v2] if version == "ikev2" else list(dict.fromkeys([v2, v1])),
        "peer": (xml_text(peer, "ip", None) or xml_text(peer, "fqdn", None)
                 or ("dynamic" if peer is not None and peer.find("dynamic") is not None else None)),
        "auth": "certificate" if e.find("authentication/certificate") is not None else "pre-shared-key",
        "disabled": xml_text(e, "disabled", "no") == "yes",
    }


def _ipsec_tunnel(e: ET.Element) -> dict:
    manual = e.find("manual-key")
    kind = ("manual-key" if manual is not None else
            "globalprotect-satellite" if e.find("global-protect-satellite") is not None else "auto-key")
    t = {
        "name": e.get("name"),
        "type": kind,
        "tunnel_interface": xml_text(e, "tunnel-interface", None),
        "gateways": [g.get("name") for g in e.findall("auto-key/ike-gateway/entry") if g.get("name")],
        "ipsec_profile": xml_text(e, "auto-key/ipsec-crypto-profile", "default") if kind == "auto-key" else None,
        "anti_replay": xml_text(e, "anti-replay", "yes") != "no",
        "monitor": xml_text(e, "tunnel-monitor/enable", "no") == "yes",
        "monitor_destination": xml_text(e, "tunnel-monitor/destination-ip", None),
        "disabled": xml_text(e, "disabled", "no") == "yes",
    }
    if manual is not None:
        esp = manual.find("esp")
        t["manual"] = {
            "protocol": "esp" if esp is not None else "ah",
            "encryption": xml_text(esp, "encryption/algorithm", "aes-128-cbc") if esp is not None else None,
            "authentication": _single_child_tag(esp.find("authentication") if esp is not None else manual.find("ah"),
                                                None),
        }
    return t


def parse_vpn(layers: list[ET.Element]) -> dict:
    """Site-to-site VPN config. `layers` are <config>-shaped roots, lowest priority first; a later
    layer's same-named profile, gateway or tunnel wins."""
    ike: dict[str, dict] = {}
    ipsec: dict[str, dict] = {}
    gateways: dict[str, dict] = {}
    tunnels: dict[str, dict] = {}
    for layer in layers:
        net = layer.find("devices/entry/network")
        if net is None:
            continue
        for e in net.findall("ike/crypto-profiles/ike-crypto-profiles/entry"):
            ike[e.get("name")] = _ike_profile(e)
        for e in net.findall("ike/crypto-profiles/ipsec-crypto-profiles/entry"):
            ipsec[e.get("name")] = _ipsec_profile(e)
        for e in net.findall("ike/gateway/entry"):
            gateways[e.get("name")] = _ike_gateway(e)
        for e in net.findall("tunnel/ipsec/entry"):
            tunnels[e.get("name")] = _ipsec_tunnel(e)

    for g in gateways.values():
        for name in g["ike_profiles"]:
            if name not in ike and name in BUILT_IN_IKE_PROFILES:
                ike[name] = {**BUILT_IN_IKE_PROFILES[name], "built_in": True}
    for t in tunnels.values():
        name = t["ipsec_profile"]
        if name and name not in ipsec and name in BUILT_IN_IPSEC_PROFILES:
            ipsec[name] = {**BUILT_IN_IPSEC_PROFILES[name], "built_in": True}

    return {
        "ike_profiles": [{"name": n, **ike[n]} for n in sorted(ike)],
        "ipsec_profiles": [{"name": n, **ipsec[n]} for n in sorted(ipsec)],
        "gateways": [gateways[n] for n in sorted(gateways)],
        "tunnels": [tunnels[n] for n in sorted(tunnels)],
    }


# ── Management interface & services ─────────────────────────────────────

def parse_management_settings(config_root: ET.Element) -> dict:
    system = config_root.find(".//deviceconfig/system")
    mgmt_permit = system.find(".//permitted-ip") if system is not None else None
    has_mgmt_acl = mgmt_permit is not None and len(list(mgmt_permit)) > 0
    banner = system.find(".//login-banner") if system is not None else None

    return {
        "mgmt_acl": has_mgmt_acl,
        "login_banner": bool(banner is not None and banner.text),
        # PAN-OS 11.1 uses <ntp-server-address>; older exports (and the collect_data.py
        # this was ported from) assumed <server> — verified against a real 11.1 config,
        # kept the old tag as a fallback rather than dropping it unverified.
        "ntp_primary": xml_text_any(system, [
            "ntp-servers/primary-ntp-server/ntp-server-address",
            "ntp-servers/primary-ntp-server/server",
        ], None),
        "ntp_secondary": xml_text_any(system, [
            "ntp-servers/secondary-ntp-server/ntp-server-address",
            "ntp-servers/secondary-ntp-server/server",
        ], None),
    }


# ── Management plane ─────────────────────────────────────────────────────
#
# Paths confirmed against Palo Alto SCM BPA failed-field names for the same checks
# (setting.management.admin_lockout.failed_attempts, setting.management.api.key.lifetime,
# ...) and the pan-os-codegen specs (device/profiles/{ldap,radius,tacacs-plus-profile,
# syslog,snmptrap}.yaml, device/log-settings/{system,config}.yaml).

UPDATE_TYPES = ("anti-virus", "threats", "wildfire", "global-protect-datafile", "global-protect-clientless-vpn")
LOG_DESTINATIONS = ("send-syslog", "send-snmptrap", "send-email", "send-http")


def _int(el: Optional[ET.Element], path: str) -> Optional[int]:
    v = xml_text(el, path, None) if el is not None else None
    return int(v) if v is not None and v.strip().isdigit() else None


def _match_lists(el: Optional[ET.Element]) -> list[dict]:
    if el is None:
        return []
    out = []
    for m in el.findall("match-list/entry"):
        dests = [f"{tag.replace('send-', '')}:{x}" for tag in LOG_DESTINATIONS for x in members(m, f"{tag}/member")]
        if xml_text(m, "send-to-panorama", "no") == "yes":
            dests.append("panorama")
        out.append({"name": m.get("name"), "filter": xml_text(m, "filter", "All Logs"), "destinations": dests})
    return out


def parse_log_forwarding_profiles(scopes: list[ET.Element]) -> list[dict]:
    """Log Forwarding profiles (log-settings/profiles, pan-os-codegen log-forwarding spec) from each
    scope; a later scope's same-named profile wins. Each match list keeps its log type."""
    by_name: dict[str, dict] = {}
    for scope in scopes:
        for e in scope.findall("log-settings/profiles/entry"):
            if not e.get("name"):
                continue
            lists = _match_lists(e)
            for lst, m in zip(lists, e.findall("match-list/entry")):
                lst["log_type"] = xml_text(m, "log-type", "traffic")
            by_name[e.get("name")] = {"name": e.get("name"), "lists": lists}
    return [by_name[n] for n in sorted(by_name)]


def parse_mgmt_plane(layers: list[ET.Element]) -> dict:
    """Management-plane hardening settings. `layers` are <config>-shaped roots, lowest priority
    first (a firewall export is one layer; a Panorama device group's template stack is several).
    A later layer's value, or same-named profile, wins."""
    out: dict = {
        "idle_timeout_min": None, "failed_attempts": None, "lockout_minutes": None,
        "api_key_lifetime_min": None,
        "password_complexity": {"enabled": False, "minimum_length": None},
        "snmp_polling": None, "mgmt_tls_profile": None,
        "update_schedule": {},
        "log_forwarding": {"system": [], "config": []},
    }
    tls: dict[str, dict] = {}
    by_kind: dict[str, dict[str, dict]] = {"ldap": {}, "radius": {}, "tacplus": {}, "syslog": {}, "snmptrap": {}}

    for layer in layers:
        dev = layer.find("devices/entry/deviceconfig")
        mgmt = dev.find("setting/management") if dev is not None else None
        for key, path in (("idle_timeout_min", "idle-timeout"), ("failed_attempts", "admin-lockout/failed-attempts"),
                          ("lockout_minutes", "admin-lockout/lockout-time"), ("api_key_lifetime_min", "api/key/lifetime")):
            v = _int(mgmt, path)
            if v is not None:
                out[key] = v
        system = dev.find("system") if dev is not None else None
        if system is not None:
            snmp = system.find("snmp-setting/access-setting/version")
            if snmp is not None and len(snmp):
                version = list(snmp)[0].tag
                out["snmp_polling"] = {
                    "version": version,
                    "default_community": xml_text(snmp, "v2c/snmp-community-string", None) == "public",
                }
            if xml_text(system, "ssl-tls-service-profile", None):
                out["mgmt_tls_profile"] = xml_text(system, "ssl-tls-service-profile", None)
            for utype in UPDATE_TYPES:
                rec = system.find(f"update-schedule/{utype}/recurring")
                if rec is not None and len(rec):
                    freq = next((c for c in rec if c.tag not in ("sync-to-peer", "threshold")), None)
                    if freq is not None:
                        out["update_schedule"][utype] = {
                            "frequency": freq.tag,
                            "action": xml_text(freq, "action", None),
                            "threshold_hours": _int(rec, "threshold") if rec.find("threshold") is not None
                                               else _int(freq, "threshold"),
                        }
        pc = layer.find("mgt-config/password-complexity")
        if pc is not None:
            out["password_complexity"] = {
                "enabled": xml_text(pc, "enabled", "no") == "yes",
                "minimum_length": _int(pc, "minimum-length"),
            }
        shared = layer.find("shared")
        if shared is None:
            continue
        for e in shared.findall("ssl-tls-service-profile/entry"):
            if e.get("name"):
                tls[e.get("name")] = {"min_version": xml_text(e, "protocol-settings/min-version", "tls1-0")}
        for e in shared.findall("server-profile/ldap/entry"):
            by_kind["ldap"][e.get("name")] = {
                "name": e.get("name"),
                "ssl": xml_text(e, "ssl", None),
                "verify_certificate": xml_text(e, "verify-server-certificate", "no") == "yes",
                "servers": len(e.findall("server/entry")),
            }
        for e in shared.findall("server-profile/radius/entry"):
            by_kind["radius"][e.get("name")] = {"name": e.get("name"),
                                                "protocol": _single_child_tag(e.find("protocol"), None)}
        for e in shared.findall("server-profile/tacplus/entry"):
            by_kind["tacplus"][e.get("name")] = {"name": e.get("name"),
                                                 "protocol": xml_text(e, "protocol", None)
                                                 or _single_child_tag(e.find("protocol"), "CHAP")}
        for e in shared.findall("log-settings/syslog/entry"):
            by_kind["syslog"][e.get("name")] = {"name": e.get("name"), "servers": [
                {"name": s.get("name"), "server": xml_text(s, "server", None), "transport": xml_text(s, "transport", "UDP")}
                for s in e.findall("server/entry")]}
        for e in shared.findall("log-settings/snmptrap/entry"):
            version = e.find("version")
            v = list(version)[0].tag if version is not None and len(version) else None
            by_kind["snmptrap"][e.get("name")] = {
                "name": e.get("name"), "version": v,
                "default_community": any(xml_text(s, "community", None) == "public"
                                         for s in e.findall("version/v2c/server/entry")),
            }
        for kind in ("system", "config"):
            lists = _match_lists(shared.find(f"log-settings/{kind}"))
            if lists:
                out["log_forwarding"][kind] = lists

    out.update({k: list(v.values()) for k, v in by_kind.items()})
    name = out["mgmt_tls_profile"]
    out["mgmt_tls"] = ({"profile": name, "found": name in tls, **tls.get(name, {})} if name else None)
    return out


# ── Panorama management detection ────────────────────────────────────────

def detect_panorama_managed(config_root: ET.Element) -> bool:
    """A firewall managed by Panorama pushes its actual security policy
    (zones, rules, profiles, profile groups, address objects) from Panorama's
    Device Group / Template hierarchy — none of that appears in the managed
    firewall's own running-config export, only local-only settings do.
    Verified against a real Panorama-managed export: <deviceconfig><system>
    <panorama><local-panorama> is present there and absent from two
    independently-checked locally-managed exports."""
    return config_root.find(".//deviceconfig/system/panorama") is not None


# ── Top-level entry point ────────────────────────────────────────────────

def parse_config(xml_bytes: bytes) -> dict:
    """Parse a full PAN-OS config export into the shared data shape used by
    the rules engine. op_root-dependent sections (system runtime info,
    licenses, HA) are marked unavailable; Phase 2's live_client.py will pass
    those roots in separately when connecting to a live device."""
    config_root = ET.fromstring(xml_bytes)

    security_rules = parse_security_rules(config_root)
    profile_entries = parse_security_profile_entries(config_root)
    profiles = {key: list(by_name.keys()) for key, by_name in profile_entries.items()}
    groups = parse_profile_groups(config_root)
    profile_rule_counts, group_rule_counts = compute_profile_usage(security_rules, profiles, groups)

    scope_of = profile_scopes([("shared", config_root.find("shared"))] +
                              [(v.get("name"), v) for v in config_root.findall(".//vsys/entry")])
    security_profiles = {
        ptype: [
            {
                "name": name,
                "scope": scope_of.get((ptype, name)),
                "rule_count": profile_rule_counts[ptype][name],
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
    zone_protection_profiles, interface_mgmt_profiles = parse_network_profiles(config_root)
    vsys_entries = config_root.findall("devices/entry/vsys/entry")
    shared = config_root.find("shared")

    return {
        "panorama_managed": detect_panorama_managed(config_root),
        "mgmt_interfaces": parse_mgmt_interfaces(config_root.findall(".//network/interface")),
        "policy_objects": parse_policy_objects(([shared] if shared is not None else []) + vsys_entries),
        "default_rule_actions": parse_default_rule_actions(
            [rb for v in vsys_entries if (rb := v.find("rulebase")) is not None]),
        "default_rule_logging": parse_default_rule_logging([rb for v in vsys_entries for rb in v.findall("rulebase")]),
        "decryption": parse_decryption(config_root),
        "globalprotect": parse_globalprotect(([shared] if shared is not None else []) + vsys_entries, vsys_entries),
        "zone_protection_profiles": zone_protection_profiles,
        "interface_mgmt_profiles": interface_mgmt_profiles,
        "system_info": parse_system_info(config_root),
        "licenses": parse_licenses(),
        "admin_accounts": parse_admin_accounts(config_root),
        "zones": parse_zones(config_root),
        "security_rules": security_rules,
        "nat_rules": parse_nat_rules(config_root),
        "security_profiles": security_profiles,
        "profile_groups": profile_groups,
        "syslog_profiles": parse_syslog_profiles(config_root),
        "ha": parse_ha(),
        "management": parse_management_settings(config_root),
        "mgmt_plane": parse_mgmt_plane([config_root]),
        "ha_config": parse_ha_config([config_root]),
        "vpn": parse_vpn([config_root]),
        "dos": parse_dos(([shared] if shared is not None else []) + vsys_entries,
                         [(rb, None) for v in vsys_entries for rb in v.findall("rulebase")]),
        "session_settings": parse_session_settings([config_root]),
        "log_forwarding_profiles": parse_log_forwarding_profiles(([shared] if shared is not None else []) + vsys_entries),
        "device_settings": parse_device_settings([config_root]),
        "identity": parse_identity([config_root]),
        "certificates": parse_certificates([config_root]),
        "object_usage": find_unused(config_root),
        "misc_policy": parse_misc_policy([rb for v in vsys_entries for rb in v.findall("rulebase")], [config_root]),
    }

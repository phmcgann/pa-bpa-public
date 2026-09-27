"""
Threat-intelligence blocking coverage: which enabled deny rules block Palo Alto Networks'
built-in IP lists (inbound = list as Source, outbound = list as Destination), and whether
QUIC is blocked.

Follows Palo Alto Networks' Internet Gateway Best Practice Security Policy, "Step 1: Create
Rules Based on Trusted Threat Intelligence Sources" (two deny rules per list: the list as the
Destination for outbound traffic and as the Source for inbound traffic) and "Step 3: Create
the Application Block Rules" (block the QUIC application so browsers fall back to TLS, which
the firewall can decrypt).

A custom external dynamic list whose type is predefined-ip and whose source is a built-in
list counts as that list.
"""
from __future__ import annotations

BLOCK_ACTIONS = {"deny", "drop", "reset-client", "reset-server", "reset-both"}

# Built-in IP lists: config name -> label shown in the PAN-OS UI.
BUILT_IN_LISTS = {
    "panw-known-ip-list": "Palo Alto Networks - Known malicious IP addresses",
    "panw-highrisk-ip-list": "Palo Alto Networks - High risk IP addresses",
    "panw-bulletproof-ip-list": "Palo Alto Networks - Bulletproof IP addresses",
    "panw-torexit-ip-list": "Palo Alto Networks - Tor exit IP addresses",
}
# Advanced IP Defense predefined lists (need an Advanced IP Defense license): config name -> label.
# docs.paloaltonetworks.com/advanced-ip-defense/getting-started/advanced-ip-defense-edl-based-protection
AIPD_LISTS = {
    "panw-aipd-c2-infra-ip-list": "Adv. IP Defense: C2 infrastructure",
    "panw-aipd-in-malware-ip-list": "Adv. IP Defense: Hardcoded in malware",
    "panw-aipd-vpn-ip-list": "Adv. IP Defense: VPN",
    "panw-aipd-proxies-ip-list": "Adv. IP Defense: Proxies",
    "panw-aipd-scanning-ip-list": "Adv. IP Defense: Scanner and brute-force",
    "panw-aipd-vuln-svcs-ip-list": "Adv. IP Defense: Exposed vulnerable services",
}
ALL_LISTS = {**BUILT_IN_LISTS, **AIPD_LISTS}
DIRECTIONS = ("inbound", "outbound")


def _built_in_for(name: str, edls: dict) -> str | None:
    if name in ALL_LISTS:
        return name
    edl = edls.get(name)
    if edl and edl.get("type") == "predefined-ip" and edl.get("source") in ALL_LISTS:
        return edl["source"]
    return None


def _applications(rule: dict, app_groups: dict) -> set[str]:
    out: set[str] = set()
    stack = list(rule.get("applications") or [])
    seen: set[str] = set()
    while stack:
        a = stack.pop()
        if a in seen:
            continue
        seen.add(a)
        if a in app_groups:
            stack.extend(app_groups[a])
        else:
            out.add(a)
    return out


def coverage(data: dict) -> dict:
    objs = data.get("policy_objects") or {}
    edls = objs.get("external_lists") or {}
    app_groups = objs.get("application_groups") or {}
    lists = {lid: {"id": lid, "label": label, "inbound": [], "outbound": [], "disabled_rules": []}
             for lid, label in ALL_LISTS.items()}
    quic_rules: list[str] = []
    quic_disabled: list[str] = []

    for rule in data.get("security_rules") or []:
        if rule.get("action") not in BLOCK_ACTIONS:
            continue
        disabled = rule.get("disabled") == "yes"
        for field, direction, negate in (("sources", "inbound", "negate_source"),
                                         ("destinations", "outbound", "negate_destination")):
            if rule.get(negate) == "yes":
                continue
            for name in rule.get(field) or []:
                lid = _built_in_for(name, edls)
                if lid is None:
                    continue
                if disabled:
                    if rule["name"] not in lists[lid]["disabled_rules"]:
                        lists[lid]["disabled_rules"].append(rule["name"])
                elif rule["name"] not in lists[lid][direction]:
                    lists[lid][direction].append(rule["name"])
        if "quic" in _applications(rule, app_groups):
            (quic_disabled if disabled else quic_rules).append(rule["name"])

    decryption = data.get("decryption") or {}
    decrypting = any(r.get("action") == "decrypt" and r.get("disabled") != "yes"
                     for r in decryption.get("rules") or [])
    return {
        "lists": [lists[lid] for lid in BUILT_IN_LISTS],
        # Shown only when the firewall has an Advanced IP Defense license.
        "aipd_lists": [lists[lid] for lid in AIPD_LISTS],
        "quic": {"rules": quic_rules, "disabled_rules": quic_disabled, "decryption_in_use": decrypting},
        # Configs parsed before policy objects were captured can't resolve custom EDLs.
        "objects_captured": "policy_objects" in data,
    }

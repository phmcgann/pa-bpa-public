"""
Who can actually reach management services on a data-plane interface.

An Interface Management profile's permitted-IP list is only one layer.
Traffic to the firewall's own interface IP is also subject to security policy
(source zone → the interface's own zone), so a profile with no permitted IPs
can still be locked down by rules that allow only specific admin sources — or
left wide open by an allow-any rule or the implicit intrazone-default.

For each interface / admin service / source zone, this walks the security
rules top-down, first match wins, exactly as the firewall does. The implicit
intrazone-default (allow) / interzone-default (deny) rules — or their
overridden actions — only decide when no explicit rule matched, e.g. a
catch-all "deny remaining" rule ends the walk long before them.

Matching is tri-state. Anything that can't be resolved from the config — a
dynamic address group, an FQDN object, an application filter, a DHCP
interface's address — makes a rule a "maybe" rather than a guess, and a maybe
on a rule that could flip the outcome marks the result "uncertain". Only a
definite "open" produces a finding.

Assumption: access is analyzed to each interface's own IP, governed by that
interface's own management profile.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

YES, NO, MAYBE = "yes", "no", "maybe"

# App-IDs a connection to each service is identified as, and its standard port.
ADMIN_SERVICES: dict[str, dict] = {
    "https": {"label": "HTTPS", "apps": {"panos-web-interface", "ssl", "web-browsing"}, "proto": "tcp", "port": 443},
    "http": {"label": "HTTP", "apps": {"panos-web-interface", "web-browsing"}, "proto": "tcp", "port": 80},
    "ssh": {"label": "SSH", "apps": {"ssh"}, "proto": "tcp", "port": 22},
    "telnet": {"label": "Telnet", "apps": {"telnet"}, "proto": "tcp", "port": 23},
    "snmp": {"label": "SNMP", "apps": {"snmp", "snmp-base", "snmpv3"}, "proto": "udp", "port": 161},
}

PREDEFINED_SERVICES = {
    "service-http": {"tcp": "80,8080", "udp": None},
    "service-https": {"tcp": "443", "udp": None},
}


def _and(*results: str) -> str:
    if NO in results:
        return NO
    return MAYBE if MAYBE in results else YES


# ── Object resolution ────────────────────────────────────────────────────

def _literal_networks(value: str) -> Optional[list]:
    """A CIDR/host literal or an a-b range, else None."""
    try:
        return [ipaddress.ip_network(value, strict=False)]
    except ValueError:
        pass
    if "-" in value:
        start, _, end = value.partition("-")
        try:
            return list(ipaddress.summarize_address_range(
                ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())))
        except (ValueError, TypeError):
            return None
    return None


def _cause(field: str, kind: str, obj: Optional[str] = None) -> dict:
    """Why a rule couldn't be matched definitively."""
    return {"field": field, "kind": kind, "object": obj}


def resolve_addresses(name: str, objects: dict, _seen: Optional[set] = None) -> tuple[list, list[dict]]:
    """(networks, unresolved causes) for an address literal, object, or group."""
    seen = _seen if _seen is not None else set()
    obj = objects.get("addresses", {}).get(name)
    if obj is not None:
        if obj["type"] in ("ip-netmask", "ip-range"):
            nets = _literal_networks(obj["value"])
            return (nets, []) if nets is not None else ([], [_cause("destination", "unparseable address", name)])
        kind = "FQDN address object" if obj["type"] == "fqdn" else "wildcard address object"
        return [], [_cause("destination", kind, name)]
    group = objects.get("address_groups", {}).get(name)
    if group is not None:
        if group["dynamic"]:
            return [], [_cause("destination", "dynamic address group", name)]
        if name in seen:
            return [], []
        seen.add(name)
        nets, causes = [], []
        for member in group["members"]:
            m_nets, m_causes = resolve_addresses(member, objects, seen)
            nets += m_nets
            causes += m_causes
        return nets, causes
    nets = _literal_networks(name)
    if nets is not None:
        return nets, []
    return [], [_cause("destination", "not a defined address object (EDL, region, or another scope)", name)]


def interface_ips(iface: dict, objects: dict) -> Optional[list]:
    """The interface's static addresses, or None if they can't be known."""
    if iface.get("dhcp") or not iface.get("ips"):
        return None
    ips = []
    for ref in iface["ips"]:
        value = objects.get("addresses", {}).get(ref, {}).get("value", ref)
        try:
            ips.append(ipaddress.ip_interface(value).ip)
        except ValueError:
            return None
    return ips


def _ports_match(spec: Optional[str], port: int) -> bool:
    if not spec:
        return False
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


# ── Rule matching for one hypothetical connection ────────────────────────

Match = tuple[str, list[dict]]  # (YES | NO | MAYBE, causes when MAYBE)


def match_destination(rule: dict, ips: Optional[list], objects: dict) -> Match:
    dests = rule.get("destinations") or ["any"]
    negate = rule.get("negate_destination") == "yes"
    if "any" in dests:
        return (NO if negate else YES), []
    if ips is None:
        return MAYBE, [_cause("destination", "interface address unknown (DHCP or unset)")]
    nets, causes = [], []
    for d in dests:
        d_nets, d_causes = resolve_addresses(d, objects)
        nets += d_nets
        causes += d_causes
    hit = any(ip in net for ip in ips for net in nets if ip.version == net.version)
    if hit:
        return (NO if negate else YES), []
    if causes:
        return MAYBE, causes
    return (YES if negate else NO), []


def match_application(rule: dict, service: str, objects: dict) -> Match:
    apps = rule.get("applications") or ["any"]
    if "any" in apps:
        return YES, []
    wanted = ADMIN_SERVICES[service]["apps"]
    groups = objects.get("application_groups", {})
    filters = set(objects.get("application_filters", []))
    causes, stack, seen = [], list(apps), set()
    while stack:
        app = stack.pop()
        if app in wanted:
            return YES, []
        if app in groups and app not in seen:
            seen.add(app)
            stack += groups[app]
        elif app in filters:
            causes.append(_cause("application", "application filter", app))
    return (MAYBE, causes) if causes else (NO, [])


def match_service(rule: dict, service: str, objects: dict) -> Match:
    services = rule.get("services") or ["any"]
    # application-default: the admin apps run on the standard ports checked here.
    if "any" in services or "application-default" in services:
        return YES, []
    proto, port = ADMIN_SERVICES[service]["proto"], ADMIN_SERVICES[service]["port"]
    svc_objs = {**PREDEFINED_SERVICES, **objects.get("services", {})}
    groups = objects.get("service_groups", {})
    causes, stack, seen = [], list(services), set()
    while stack:
        name = stack.pop()
        if name in groups:
            if name not in seen:
                seen.add(name)
                stack += groups[name]
        elif name in svc_objs:
            if _ports_match(svc_objs[name].get(proto), port):
                return YES, []
        else:
            causes.append(_cause("service", "not a defined service object", name))
    return (MAYBE, causes) if causes else (NO, [])


def match_zones(rule: dict, source_zone: str, dest_zone: str) -> bool:
    from_zones = rule.get("from_zones") or ["any"]
    to_zones = rule.get("to_zones") or ["any"]
    rule_type = rule.get("rule_type", "universal")
    if rule_type == "intrazone" and source_zone != dest_zone:
        return False
    if rule_type == "interzone" and source_zone == dest_zone:
        return False
    from_ok = "any" in from_zones or source_zone in from_zones
    # An intrazone rule has no destination-zone list of its own.
    to_ok = rule_type == "intrazone" or "any" in to_zones or dest_zone in to_zones
    return from_ok and to_ok


def any_source(rule: dict) -> bool:
    """True if the rule matches every source address and user."""
    sources = rule.get("sources") or ["any"]
    users = rule.get("source_users") or ["any"]
    return sources == ["any"] and users == ["any"] and rule.get("negate_source") != "yes"


def simulate(rules: list[dict], source_zone: str, dest_zone: str, service: str,
             ips: Optional[list], objects: dict, default_actions: dict) -> dict:
    """First-match walk for a connection from an arbitrary source address in
    source_zone to the interface on `service`."""
    specific_allows: list[str] = []
    # Any-source rules that might have matched first, but depend on objects that can't be resolved.
    unresolved: list[dict] = []

    def result(allowed: bool, via: str) -> dict:
        status = "open" if allowed else ("restricted" if specific_allows else "blocked")
        # Only an unresolved rule that could flip the outcome makes it uncertain; "lean" is the
        # outcome if none of them actually match.
        flips = [u for u in unresolved if (u["action"] == "allow") != allowed]
        lean = None
        if flips:
            status, lean = "uncertain", ("open" if allowed else "closed")
        return {"source_zone": source_zone, "status": status, "lean": lean, "via": via,
                "specific_allows": specific_allows, "unresolved_rules": flips}

    for rule in rules:
        if rule.get("disabled") == "yes" or not match_zones(rule, source_zone, dest_zone):
            continue
        parts = [match_destination(rule, ips, objects), match_application(rule, service, objects),
                 match_service(rule, service, objects)]
        m = _and(*(state for state, _ in parts))
        if m == NO:
            continue
        allow = rule.get("action", "allow") == "allow"
        if not any_source(rule):
            if allow and m == YES:
                specific_allows.append(rule["name"])
            continue
        if m == MAYBE:
            unresolved.append({"rule": rule["name"], "action": "allow" if allow else "block",
                               "causes": [c for state, causes in parts if state == MAYBE for c in causes]})
            continue
        return result(allow, rule["name"])

    if source_zone == dest_zone:
        return result(default_actions.get("intrazone-default", "allow") == "allow", "intrazone-default")
    return result(default_actions.get("interzone-default", "deny") == "allow", "interzone-default")


# ── Whole-assessment analysis ────────────────────────────────────────────

REQUIRED_KEYS = ("mgmt_interfaces", "policy_objects", "interface_mgmt_profiles")


def analyze(data: dict) -> Optional[list[dict]]:
    """Per-interface reachability, or None for an assessment parsed before
    these inputs were captured."""
    if any(k not in data for k in REQUIRED_KEYS):
        return None
    zones = data.get("zones", [])
    if zones and any("interfaces" not in z for z in zones):
        return None
    objects = data["policy_objects"]
    rules = data.get("security_rules", [])
    defaults = data.get("default_rule_actions", {})
    profiles = {p["name"]: p for p in data["interface_mgmt_profiles"]}
    zone_of = {i: z["name"] for z in zones for i in z["interfaces"]}
    zone_names = [z["name"] for z in zones]

    out = []
    for iface in data["mgmt_interfaces"]:
        profile = profiles.get(iface["mgmt_profile"])
        if profile is None:
            continue
        services = [s for s in ADMIN_SERVICES if profile["services"].get(s)]
        if not services:
            continue
        zone = zone_of.get(iface["name"])
        ips = interface_ips(iface, objects)
        entry = {
            "interface": iface["name"],
            "profile": profile["name"],
            "zone": zone,
            "permitted_ips": len(profile.get("permitted_ip", [])),
            "address_known": ips is not None,
            "services": {},
        }
        if zone is not None:
            for svc in services:
                entry["services"][svc] = [
                    simulate(rules, sz, zone, svc, ips, objects, defaults) for sz in zone_names
                ]
        else:
            entry["services"] = {svc: [] for svc in services}
        out.append(entry)
    return out

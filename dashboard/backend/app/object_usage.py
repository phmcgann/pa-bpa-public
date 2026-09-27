"""
Objects nothing in the configuration uses.

Every object definition (address, address group, service, service group, application group and
filter, external dynamic list, custom URL category, security profile, security profile group)
is a node. A reference is any value naming it: an element's text (<member>web-srv</member>,
<name>…</name>) or an entry's name (an interface's <ip><entry name="web-srv"/>, an anti-spyware
profile's <lists><entry name="my-edl">).
References found outside the object definitions — rules of every type, NAT, interfaces,
GlobalProtect, routing, zones — are the roots; references inside a definition are edges (a group
to its members, a URL filtering profile to its custom categories and EDLs, a profile group to its
profiles). An object is used when it's reachable from a root, so an address only listed in an
unused group is unused too. A dynamic address group reaches every address carrying a tag its
filter names; addresses counted as used only that way are listed separately, since the filter's
and/or logic isn't evaluated.

Matching is by name across kinds, which errs toward "used": a name that appears anywhere as a
reference counts.
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from typing import Optional

SECURITY_PROFILE_TAGS = {
    "virus": "Antivirus", "spyware": "Anti-Spyware", "vulnerability": "Vulnerability Protection",
    "url-filtering": "URL Filtering", "file-blocking": "File Blocking", "wildfire-analysis": "WildFire Analysis",
    "data-filtering": "Data Filtering",
}

# kind → (path under a shared or vsys scope, label)
KINDS: dict[str, tuple[list[str], str]] = {
    "addresses": (["address"], "address objects"),
    "address_groups": (["address-group"], "address groups"),
    "services": (["service"], "service objects"),
    "service_groups": (["service-group"], "service groups"),
    "application_groups": (["application-group"], "application groups"),
    "application_filters": (["application-filter"], "application filters"),
    "external_lists": (["external-list"], "external dynamic lists"),
    "custom_url_categories": (["profiles/custom-url-category"], "custom URL categories"),
    "security_profiles": ([f"profiles/{t}" for t in SECURITY_PROFILE_TAGS], "security profiles"),
    "profile_groups": (["profile-group"], "security profile groups"),
}

_QUOTED = re.compile(r"'([^']+)'|\"([^\"]+)\"")


def _refs(el: ET.Element, skip: Optional[set[int]] = None) -> set[str]:
    """Every value under `el` that could name an object, not descending into elements in `skip`."""
    out: set[str] = set()
    stack = [el]
    while stack:
        e = stack.pop()
        if skip is not None and id(e) in skip:
            continue
        children = list(e)
        if e.text and e.text.strip() and not children:
            out.add(e.text.strip())
        if e.tag == "entry" and e.get("name"):
            out.add(e.get("name"))  # <ip><entry name="web-srv"/>, <lists><entry name="my-edl">…
        stack.extend(children)
    return out


def find_unused(config_root: ET.Element) -> dict:
    scopes = [s for s in [config_root.find("shared")] if s is not None] + config_root.findall(".//vsys/entry")
    defs: list[tuple[str, str, ET.Element, str]] = []   # (kind, name, entry, profile type label)
    where: dict[int, dict] = {}   # entry → its scope ("shared" or a vsys name) and config path, for CLI commands
    containers: set[int] = set()
    for scope in scopes:
        scope_name = "shared" if scope.tag == "shared" else scope.get("name")
        for kind, (paths, _) in KINDS.items():
            for path in paths:
                container = scope.find(path)
                if container is None:
                    continue
                containers.add(id(container))
                ptype = SECURITY_PROFILE_TAGS.get(path.split("/")[-1], "")
                for e in container.findall("entry"):
                    if e.get("name"):
                        defs.append((kind, e.get("name"), e, ptype))
                        where[id(e)] = {"scope": scope_name, "path": path.replace("/", " ")}

    roots = _refs(config_root, containers)
    edges: dict[str, set[str]] = {}
    for kind, name, entry, _ in defs:
        edges.setdefault(name, set()).update(_refs(entry) - {name})

    # A dynamic address group reaches the addresses tagged with a tag its filter names. The filter's
    # and/or logic isn't evaluated: any one named tag is enough, which errs toward "used".
    address_tags = {name: set(m.text.strip() for m in entry.findall("tag/member") if m.text)
                    for kind, name, entry, _ in defs if kind == "addresses"}
    dag_members: dict[str, dict[str, set[str]]] = {}   # dynamic group → address → tags that matched
    dag_filters: dict[str, str] = {}
    for kind, name, entry, _ in defs:
        filt = entry.findtext("dynamic/filter") if kind == "address_groups" else None
        if filt:
            dag_filters[name] = " ".join(filt.split())
            tags = {a or b for a, b in _QUOTED.findall(filt)} or set(re.findall(r"[\w.-]+", filt))
            dag_members[name] = {addr: t & tags for addr, t in address_tags.items() if t & tags}

    def reach(with_tags: bool) -> set[str]:
        used, stack = set(), [r for r in roots if r in edges]
        while stack:
            n = stack.pop()
            if n in used:
                continue
            used.add(n)
            nxt = set(edges.get(n, ()))
            if with_tags:
                nxt |= set(dag_members.get(n, ()))
            stack.extend(r for r in nxt if r in edges and r not in used)
        return used

    used = reach(with_tags=True)
    # Addresses that count as used only because an in-use dynamic group names one of their tags.
    tag_only = [
        {"name": addr,
         "groups": [{"name": g, "filter": dag_filters[g]}
                    for g, m in sorted(dag_members.items()) if g in used and addr in m],
         "tags": sorted(set().union(*(m[addr] for g, m in dag_members.items() if g in used and addr in m)))}
        for addr in sorted(set(address_tags) & (used - reach(with_tags=False)))
    ]

    unused: dict[str, list[str]] = {}
    detail: list[dict] = []
    for kind, name, entry, ptype in defs:
        if name not in used:
            label = f"{name} ({ptype})" if ptype else name
            if label not in unused.setdefault(kind, []):
                unused[kind].append(label)
            detail.append({"kind": kind, "name": name, **where[id(entry)]})
    return {"available": True, "unused": {k: sorted(v) for k, v in unused.items() if v},
            "unused_detail": detail, "used_via_dynamic_group": tag_only}


def unavailable_for_panorama() -> dict:
    return {"available": False, "unused": {},
            "reason": "Not checked on a Panorama export: shared and device-group objects can be used by other "
                      "device groups this assessment doesn't cover."}


# ── Duplicates (from the parsed policy objects, so older uploads get them too) ──

def _norm_address(obj: dict) -> str:
    t, v = obj.get("type"), (obj.get("value") or "").strip()
    if t == "ip-netmask":
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            return v
    if t == "ip-range":
        lo, _, hi = v.partition("-")
        return f"{lo.strip()}-{hi.strip()}"
    return v.lower() if t == "fqdn" else v


def _norm_ports(spec: Optional[str]) -> str:
    return ",".join(sorted(p.strip() for p in (spec or "").split(",") if p.strip()))


def find_duplicates(objects: dict) -> list[dict]:
    """Sets of address objects with the same address, and service objects with the same protocol and ports."""
    by_value: dict[tuple, list[str]] = {}
    labels: dict[tuple, str] = {}
    for name, obj in (objects.get("addresses") or {}).items():
        key = ("addresses", obj.get("type"), _norm_address(obj))
        by_value.setdefault(key, []).append(name)
        labels[key] = key[2]
    services = objects.get("services") or {}
    if all("source_port" in o for o in services.values()):  # older uploads didn't record source ports
        for name, obj in services.items():
            ports = tuple(_norm_ports(obj.get(p)) for p in ("tcp", "udp", "sctp"))
            key = ("services", *ports, obj.get("source_port") or "")
            by_value.setdefault(key, []).append(name)
            labels[key] = ", ".join(f"{p.upper()} {v}" for p, v in zip(("tcp", "udp", "sctp"), ports) if v) + \
                (f", source port {key[4]}" if key[4] else "")
    return [{"kind": k[0], "value": labels[k], "names": sorted(n)}
            for k, n in sorted(by_value.items(), key=lambda kv: (kv[0][0], labels[kv[0]])) if len(n) > 1]

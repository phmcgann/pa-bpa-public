"""
Security rules that never match: an earlier rule already matches all of their traffic.

The firewall evaluates rules top-down and stops at the first match, so a rule whose
traffic is entirely covered by an earlier rule is dead — "shadowed". PAN-OS warns about
some of these at commit; this finds them from the config.

Rule A covers rule B when every one of A's match criteria is at least as broad as B's:
zones (and rule type), source and destination addresses, source users, applications,
services, URL categories and HIP profiles. Addresses resolve to IP ranges through objects
and groups; services to port ranges per protocol; application groups to their members.

Only certain coverage counts. Anything that can't be compared exactly — an FQDN or
wildcard object, a dynamic address group, an EDL, a region, an application filter, a
service with a source port — only covers the same named thing in the earlier rule. A rule
with a schedule, a negated address, or (on Panorama) a device target never shadows
anything, since it doesn't always apply. Coverage by several earlier rules together isn't
detected: only one earlier rule covering the whole of a later one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from .mgmt_exposure import PREDEFINED_SERVICES, _literal_networks

BLOCK_ACTIONS = {"deny", "drop", "reset-client", "reset-server", "reset-both"}


def _merge(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(lo, hi) for lo, hi in out]


def _contains(outer: list[tuple[int, int]], inner: list[tuple[int, int]]) -> bool:
    """Every interval of `inner` lies within the merged, sorted `outer`."""
    for lo, hi in inner:
        if not any(o_lo <= lo and hi <= o_hi for o_lo, o_hi in outer):
            return False
    return True


# ── Match sets ───────────────────────────────────────────────────────────

@dataclass
class Names:
    """A plain name list where 'any' matches everything (zones, users, categories, HIP, apps)."""
    any: bool
    names: frozenset

    def covers(self, other: "Names") -> bool:
        return self.any or (not other.any and other.names <= self.names)


def _names(values: Optional[list[str]]) -> Names:
    values = values or ["any"]
    return Names("any" in values, frozenset(v for v in values if v != "any"))


def _users_cover(a: Names, b: Names) -> bool:
    if a.covers(b):
        return True
    # 'known-user' matches every named user or group (not 'unknown' or 'pre-logon').
    if "known-user" in a.names and not b.any:
        rest = {n for n in b.names if n not in a.names}
        return not (rest & {"unknown", "pre-logon", "any"})
    return False


@dataclass
class Addresses:
    any: bool = False
    v4: list = field(default_factory=list)
    v6: list = field(default_factory=list)
    tokens: frozenset = frozenset()

    def full(self) -> bool:
        return self.v4 == [(0, 2**32 - 1)] and self.v6 == [(0, 2**128 - 1)]

    def __post_init__(self) -> None:
        self.everything = self.any or self.full()

    def quick_reject(self, other: "Addresses") -> bool:
        """A cheap test that rules out most pairs before the interval check."""
        if self.everything:
            return False
        if other.any or (other.tokens and not self.tokens):
            return True
        for mine, theirs in ((self.v4, other.v4), (self.v6, other.v6)):
            if theirs and (not mine or mine[0][0] > theirs[0][0] or mine[-1][1] < theirs[-1][1]):
                return True
        return False

    def covers(self, other: "Addresses") -> bool:
        if self.everything:
            return True
        if other.any:
            return False
        return other.tokens <= self.tokens and _contains(self.v4, other.v4) and _contains(self.v6, other.v6)


def _addresses(values: Optional[list[str]], objects: dict) -> Addresses:
    values = values or ["any"]
    if "any" in values:
        return Addresses(any=True)
    v4, v6, tokens = [], [], set()

    def add(name: str, seen: set) -> None:
        obj = objects.get("addresses", {}).get(name)
        if obj is not None:
            nets = _literal_networks(obj["value"]) if obj["type"] in ("ip-netmask", "ip-range") else None
            if nets is None:
                tokens.add(name)
            for n in nets or []:
                (v4 if n.version == 4 else v6).append((int(n.network_address), int(n.broadcast_address)))
            return
        group = objects.get("address_groups", {}).get(name)
        if group is not None:
            if group["dynamic"]:
                tokens.add(name)
            elif name not in seen:
                seen.add(name)
                for m in group["members"]:
                    add(m, seen)
            return
        nets = _literal_networks(name)
        if nets is None:
            tokens.add(name)  # EDL, region, or an object from another scope
        for n in nets or []:
            (v4 if n.version == 4 else v6).append((int(n.network_address), int(n.broadcast_address)))

    for v in values:
        add(v, set())
    return Addresses(False, _merge(v4), _merge(v6), frozenset(tokens))


@dataclass
class Services:
    any: bool = False
    app_default: bool = False
    ports: dict = field(default_factory=dict)   # protocol → merged port intervals
    tokens: frozenset = frozenset()

    def covers(self, other: "Services") -> bool:
        if self.any:
            return True
        if other.any:
            return False
        if other.app_default and not self.app_default:
            return False
        if other.tokens - self.tokens:
            return False
        return all(_contains(self.ports.get(proto, []), iv) for proto, iv in other.ports.items())


def _port_intervals(spec: Optional[str]) -> Optional[list[tuple[int, int]]]:
    out = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            return None
        out.append((int(lo), int(hi or lo)))
    return out


def _services(values: Optional[list[str]], objects: dict) -> Services:
    values = values or ["any"]
    if "any" in values:
        return Services(any=True)
    svc_objs = {**PREDEFINED_SERVICES, **objects.get("services", {})}
    groups = objects.get("service_groups", {})
    ports: dict[str, list] = {}
    tokens: set[str] = set()
    app_default = False

    def add(name: str, seen: set) -> None:
        nonlocal app_default
        if name == "application-default":
            app_default = True
        elif name in groups:
            if name not in seen:
                seen.add(name)
                for m in groups[name]:
                    add(m, seen)
        elif name in svc_objs:
            obj = svc_objs[name]
            if obj.get("source_port"):
                tokens.add(name)
                return
            for proto in ("tcp", "udp", "sctp"):
                if obj.get(proto):
                    iv = _port_intervals(obj[proto])
                    if iv is None:
                        tokens.add(name)
                        return
                    ports.setdefault(proto, []).extend(iv)
        else:
            tokens.add(name)

    for v in values:
        add(v, set())
    return Services(False, app_default, {p: _merge(iv) for p, iv in ports.items()}, frozenset(tokens))


def _applications(values: Optional[list[str]], objects: dict) -> Names:
    values = values or ["any"]
    if "any" in values:
        return Names(True, frozenset())
    groups = objects.get("application_groups", {})
    out, stack, seen = set(), list(values), set()
    while stack:
        app = stack.pop()
        if app in groups:
            if app not in seen:
                seen.add(app)
                stack += groups[app]
        else:
            out.add(app)  # an App-ID, or an application filter compared by name
    return Names(False, frozenset(out))


# ── Rules ────────────────────────────────────────────────────────────────

@dataclass
class _Rule:
    index: int
    raw: dict
    rule_type: str
    from_z: Names
    to_z: Names
    src: Addresses
    dst: Addresses
    users: Names
    apps: Names
    svc: Services
    category: Names
    src_hip: Names
    dst_hip: Names


def _prepare(i: int, r: dict, objects: dict) -> _Rule:
    return _Rule(i, r, r.get("rule_type") or "universal", _names(r.get("from_zones")), _names(r.get("to_zones")),
                 _addresses(r.get("sources"), objects), _addresses(r.get("destinations"), objects),
                 _names(r.get("source_users")), _applications(r.get("applications"), objects),
                 _services(r.get("services"), objects), _names(r.get("category")),
                 _names(r.get("source_hip")), _names(r.get("destination_hip")))


def _zones_cover(a: _Rule, b: _Rule) -> bool:
    if b.rule_type == "intrazone":
        if a.rule_type == "intrazone":
            return a.from_z.covers(b.from_z)
        return a.rule_type == "universal" and a.from_z.covers(b.from_z) and a.to_z.covers(b.from_z)
    if a.rule_type == "universal" or a.rule_type == b.rule_type == "interzone":
        return a.from_z.covers(b.from_z) and a.to_z.covers(b.to_z)
    return False


def _can_shadow(r: dict) -> bool:
    return (r.get("disabled") != "yes" and not r.get("schedule") and not r.get("targeted")
            and r.get("negate_source") != "yes" and r.get("negate_destination") != "yes")


def covers(a: _Rule, b: _Rule) -> bool:
    """Whether rule `a` matches all of rule `b`'s traffic. Cheapest and most selective tests first."""
    return (a.raw.get("vsys") == b.raw.get("vsys") and not a.src.quick_reject(b.src)
            and not a.dst.quick_reject(b.dst) and _zones_cover(a, b) and a.apps.covers(b.apps)
            and a.svc.covers(b.svc) and _users_cover(a.users, b.users) and a.category.covers(b.category)
            and a.src_hip.covers(b.src_hip) and a.dst_hip.covers(b.dst_hip)
            and a.src.covers(b.src) and a.dst.covers(b.dst))


def _is_block(action: Optional[str]) -> bool:
    return (action or "allow") in BLOCK_ACTIONS


def find_shadowed(rules: list[dict], objects: dict) -> list[dict]:
    prepared = [_prepare(i, r, objects) for i, r in enumerate(rules)]
    shadowers: list[_Rule] = []
    out = []
    for b in prepared:
        if b.raw.get("disabled") == "yes" or b.raw.get("negate_source") == "yes" or \
                b.raw.get("negate_destination") == "yes":
            if _can_shadow(b.raw):
                shadowers.append(b)
            continue
        for a in shadowers:
            if covers(a, b):
                b_block, a_block = _is_block(b.raw.get("action")), _is_block(a.raw.get("action"))
                out.append({
                    "rule": b.raw["name"], "position": b.index + 1, "action": b.raw.get("action") or "allow",
                    "by": a.raw["name"], "by_position": a.index + 1, "by_action": a.raw.get("action") or "allow",
                    "vsys": b.raw.get("vsys"),
                    # redundant: same outcome either way. block_allowed: traffic the rule means to block is
                    # allowed by the earlier rule. allow_blocked: traffic it means to allow is blocked.
                    "kind": "redundant" if a_block == b_block else ("block_allowed" if b_block else "allow_blocked"),
                })
                break
        if _can_shadow(b.raw):
            shadowers.append(b)
    return out


# ── Entry point (cached: findings are computed on every page view) ──────

_cache: dict[str, dict] = {}
_CACHE_SIZE = 32


def analyze(data: dict) -> dict:
    rules = data.get("security_rules") or []
    objects = data.get("policy_objects")
    if objects is None or any("category" not in r for r in rules):
        return {"available": False, "shadowed": [],
                "reason": "This assessment was uploaded before rulebase analysis — re-upload the file to run it."}
    digest = hashlib.sha1(json.dumps([rules, objects], sort_keys=True, default=str).encode()).hexdigest()
    if digest not in _cache:
        if len(_cache) >= _CACHE_SIZE:
            _cache.pop(next(iter(_cache)))
        _cache[digest] = {"available": True, "rule_count": len(rules), "shadowed": find_shadowed(rules, objects)}
    return _cache[digest]

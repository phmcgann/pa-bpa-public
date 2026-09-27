"""
NAT policy review.

NAT rules are evaluated top-down, first match wins, on the pre-NAT packet — the same shape as the
security rulebase, so shadowing reuses its address and service resolution (rulebase.py): an earlier
rule covering all of a later rule's from/to zones, egress interface, source, destination and
service means the later rule, and its translation, never applies.

For inbound (destination) NAT the security rule that must allow the traffic matches the pre-NAT
destination address and the post-NAT zone. The post-NAT zone depends on routing, which isn't
modelled, so "no security rule allows this" only considers the source zone and the pre-NAT
destination, and only when every allow rule definitely can't match: any unresolvable address, or
a negated one, counts as "could match".

Internet-facing zones are recognised by name (untrust, outside, internet, wan, external, isp,
public) — the config doesn't say which zone faces the internet.
"""

from __future__ import annotations

import re
from typing import Optional

from .rulebase import Addresses, Names, _addresses, _names, _services

EXTERNAL_ZONE = re.compile(r"untrust|outside|internet|wan|external|isp|public", re.IGNORECASE)


def is_external(zone: str) -> bool:
    return bool(EXTERNAL_ZONE.search(zone))


def _translation_key(r: dict) -> tuple:
    st, dt = r.get("source_translation") or {}, r.get("destination_translation") or {}
    return (st.get("type"), tuple(st.get("translated") or ()), st.get("interface"), st.get("bidirectional"),
            dt.get("type"), dt.get("address"), dt.get("port"))


class _Nat:
    def __init__(self, i: int, r: dict, objects: dict) -> None:
        self.index, self.raw = i, r
        self.from_z, self.to_z = _names(r.get("from_zones")), _names(r.get("to_zones"))
        self.src, self.dst = _addresses(r.get("sources"), objects), _addresses(r.get("destinations"), objects)
        self.svc = _services([r.get("service") or "any"], objects)

    def covers(self, b: "_Nat") -> bool:
        a = self
        return (a.raw.get("vsys") == b.raw.get("vsys") and a.raw.get("nat_type") == b.raw.get("nat_type")
                and a.raw.get("to_interface", "any") in ("any", b.raw.get("to_interface", "any"))
                and not a.src.quick_reject(b.src) and not a.dst.quick_reject(b.dst)
                and a.from_z.covers(b.from_z) and a.to_z.covers(b.to_z) and a.svc.covers(b.svc)
                and a.src.covers(b.src) and a.dst.covers(b.dst))


def find_shadowed(nat_rules: list[dict], objects: dict) -> list[dict]:
    prepared = [_Nat(i, r, objects) for i, r in enumerate(nat_rules)]
    live: list[_Nat] = []
    out = []
    for b in prepared:
        if b.raw.get("disabled"):
            continue
        for a in live:
            if a.covers(b):
                out.append({"rule": b.raw["name"], "position": b.index + 1, "by": a.raw["name"],
                            "by_position": a.index + 1, "vsys": b.raw.get("vsys"),
                            "same_translation": _translation_key(a.raw) == _translation_key(b.raw)})
                break
        if not b.raw.get("targeted"):
            live.append(b)
    return out


def _may_overlap(a: Addresses, b: Addresses) -> bool:
    """False only when both sides are plain IP ranges that don't intersect."""
    if a.any or b.any or a.tokens or b.tokens:
        return True
    for mine, theirs in ((a.v4, b.v4), (a.v6, b.v6)):
        for lo, hi in mine:
            if any(t_lo <= hi and lo <= t_hi for t_lo, t_hi in theirs):
                return True
    return False


def _zones_may_overlap(a: Names, b: Names) -> bool:
    return a.any or b.any or bool(a.names & b.names)


def unpermitted_dnat(data: dict) -> list[str]:
    """Destination-NAT rules that no enabled allow rule could possibly match."""
    objects = data.get("policy_objects") or {}
    rules = data.get("security_rules") or []
    if not rules:
        return []  # a Panorama-managed firewall's local export has no policy to compare against
    allows = [r for r in rules if r.get("disabled") != "yes" and (r.get("action") or "allow") == "allow"]
    prepared = [(r, _names(r.get("from_zones")), _addresses(r.get("destinations"), objects)) for r in allows]
    out = []
    for n in data.get("nat_rules") or []:
        if n.get("disabled") or not n.get("destination_translation"):
            continue
        from_z, dst = _names(n.get("from_zones")), _addresses(n.get("destinations"), objects)
        if not any(r.get("vsys") == n.get("vsys") and _zones_may_overlap(rz, from_z)
                   and (r.get("negate_destination") == "yes" or _may_overlap(rd, dst))
                   for r, rz, rd in prepared):
            out.append(n["name"])
    return out


def analyze(data: dict) -> Optional[dict]:
    nat_rules = data.get("nat_rules")
    if nat_rules is None:
        return None
    return {"shadowed": find_shadowed(nat_rules, data.get("policy_objects") or {}),
            "unpermitted_dnat": unpermitted_dnat(data)}

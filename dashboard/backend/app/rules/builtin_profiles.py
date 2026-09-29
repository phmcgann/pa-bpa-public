"""
PAN-OS predefined (built-in) profiles, graded when the configuration uses one.

A security rule or profile group can name `default`, `strict`, `basic file blocking` and so on, and a
decryption rule can use the `default` decryption profile, without the configuration defining them:
they are built into PAN-OS. Palo Alto SCM's BPA grades them; the core checks only saw profiles in the
configuration. `with_builtins` adds the ones in use, parsed from builtin_profiles.xml by the same
parsers as the real configuration, so every profile check judges them. They have no scope, so no CLI
commands are generated: built-ins can't be edited, only cloned. `annotate` says so on their findings.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

from ..parser import PROFILE_TYPE_TAGS, parse_decryption_profile_entry, parse_profile_settings

_XML = Path(__file__).with_name("builtin_profiles.xml")

# The words each profile type's findings use for it ("Antivirus profile 'default'").
_LABELS = {
    "antivirus": ("Antivirus",), "spyware": ("Anti-Spyware",), "vulnerability": ("Vulnerability Protection",),
    "url_filtering": ("URL Filtering",), "wildfire_analysis": ("WildFire", "WildFire Analysis"),
    "file_blocking": ("File Blocking",), "decryption": ("Decryption", "decryption"),
}
_SCM_TYPES = {
    "antivirus": "antivirus_profile", "spyware": "anti_spyware_profile",
    "vulnerability": "vulnerability_protection_profile", "url_filtering": "url_filtering_profile",
    "wildfire_analysis": "wildfire_analysis_profile", "file_blocking": "file_blocking_profile",
    "decryption": "decryption_profile",
}
NOTE = ("'{name}' is a predefined PAN-OS profile, which can't be edited: clone it, apply these changes to the "
        "clone, and point the rules and profile groups that use '{name}' at the clone.")


@lru_cache(maxsize=1)
def _reference() -> dict[str, dict[str, dict]]:
    """Profile type → name → parsed settings (decryption: the parsed profile)."""
    root = ET.parse(_XML).getroot()
    out: dict[str, dict[str, dict]] = {}
    for ptype, tag in PROFILE_TYPE_TAGS.items():
        out[ptype] = {e.get("name"): parse_profile_settings(e, ptype) for e in root.findall(f"{tag}/entry")}
    out["decryption"] = {e.get("name"): parse_decryption_profile_entry(e) for e in root.findall("decryption/entry")}
    return out


def _used_security_profiles(data: dict) -> dict[str, dict[str, int]]:
    """Profile type → name → enabled security rules using it, directly or through a profile group."""
    tag_to_type = {tag: key for key, tag in PROFILE_TYPE_TAGS.items()}
    groups = {g["name"]: g for g in data.get("profile_groups") or []}
    used: dict[str, dict[str, int]] = {}
    for rule in data.get("security_rules") or []:
        if rule.get("disabled") == "yes":
            continue
        names: set[tuple[str, str]] = set()
        for tag, members in (rule.get("indiv_profiles") or {}).items():
            if tag in tag_to_type:
                names.update((tag_to_type[tag], n) for n in members)
        group = groups.get((rule.get("profile_group") or "").strip())
        if group:
            names.update((ptype, n) for ptype, members in group["members"].items() for n in members)
        for ptype, name in names:
            used.setdefault(ptype, {})[name] = used.get(ptype, {}).get(name, 0) + 1
    return used


def with_builtins(data: dict) -> tuple[dict, set[tuple[str, str]]]:
    """A copy of `data` with the built-in profiles in use added (the input is left alone), and the
    (profile type, name) pairs that were added."""
    ref = _reference()
    added: set[tuple[str, str]] = set()
    profiles = data.get("security_profiles")
    if profiles is not None:
        used = _used_security_profiles(data)
        new_profiles = dict(profiles)
        for ptype, counts in used.items():
            defined = {p["name"] for p in profiles.get(ptype) or []}
            extra = [{"name": name, "scope": None, "builtin": True, "rule_count": n, "settings": ref[ptype][name]}
                     for name, n in sorted(counts.items()) if name in ref.get(ptype, {}) and name not in defined]
            if extra:
                new_profiles[ptype] = list(profiles.get(ptype) or []) + extra
                added.update((ptype, p["name"]) for p in extra)
        if added:
            data = {**data, "security_profiles": new_profiles}

    decryption = data.get("decryption")
    if decryption is not None:
        defined = {p["name"] for p in decryption.get("profiles") or []}
        # No-decrypt rules use a profile too, for its server-certificate checks.
        in_use = {r.get("profile") for r in decryption.get("rules") or [] if r.get("disabled") != "yes"}
        extra = [{**ref["decryption"][name], "builtin": True}
                 for name in sorted(n for n in in_use if n) if name in ref["decryption"] and name not in defined]
        if extra:
            data = {**data, "decryption": {**decryption, "profiles": list(decryption.get("profiles") or []) + extra}}
            added.update(("decryption", p["name"]) for p in extra)
    return data, added


def unused_builtins(data: dict) -> set[tuple[str, str]]:
    """(SCM object type, name) of the predefined profiles this configuration doesn't define or use.
    Palo Alto SCM grades them anyway; they can't be edited and affect no traffic, so the core rules
    leave them out and the coverage view marks SCM's findings on them as not applicable."""
    ref = _reference()
    out: set[tuple[str, str]] = set()
    profiles = data.get("security_profiles") or {}
    used = _used_security_profiles(data)
    for ptype, names in ref.items():
        if ptype == "decryption":
            continue
        defined = {p["name"] for p in profiles.get(ptype) or []}
        out.update((_SCM_TYPES[ptype], n) for n in names if n not in defined and n not in used.get(ptype, {}))
    decryption = data.get("decryption") or {}
    defined = {p["name"] for p in decryption.get("profiles") or []}
    in_use = {r.get("profile") for r in decryption.get("rules") or [] if r.get("disabled") != "yes"}
    out.update(("decryption_profile", n) for n in ref["decryption"] if n not in defined and n not in in_use)
    return out


def _about(finding: dict, ptype: str, name: str) -> bool:
    obj = finding.get("scm_object")
    if obj:
        return obj.get("type") == _SCM_TYPES[ptype] and obj.get("name") == name
    message = finding.get("message", "")
    return any(f"{label} profile '{name}'" in message for label in _LABELS[ptype])


def annotate(findings: list[dict], added: set[tuple[str, str]]) -> None:
    """Tells the reader, on findings about an added built-in, to clone it rather than edit it."""
    if not added:
        return
    for f in findings:
        if f.get("program", "core") != "core":
            continue
        for ptype, name in added:
            if _about(f, ptype, name):
                f["builtin_profile"] = name
                f["recommendation"] = f"{f['recommendation']} {NOTE.format(name=name)}"
                break

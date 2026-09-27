"""
Check the dashboard's decryption / zone protection / interface management /
log forwarding / Inline Cloud Analysis parsing against a real tech support
file, without the file leaving this machine.

    cd dashboard/backend
    python3 scripts/verify_tsf.py /path/to/techsupport.tgz -o tsf_report.txt

Standard library only — no venv or pip install needed. On Windows:

    cd dashboard\\backend
    py scripts\\verify_tsf.py C:\\path\\to\\techsupport.tgz -o tsf_report.txt

The report is meant to be pasted back for review, so it never prints password
hashes, keys, addresses, or free-text values. Rule, profile, zone, and
interface names are replaced with placeholders (rule-1, profile-2, ...)
unless --show-names is passed. Only a fixed allowlist of PAN-OS enum values
(yes/no, TLS versions, actions) is printed as-is; any other text shows as
<other>. Read the report before sharing it.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import parser, tsf_parser  # noqa: E402
from app.rules import mgmt_exposure  # noqa: E402
from app.rules.checks import inline_cloud_analysis_gate  # noqa: E402
from app.rules.engine import run_rules  # noqa: E402

SAFE_VALUES = {
    "yes", "no", "tls1-0", "tls1-1", "tls1-2", "tls1-3", "max",
    "allow", "deny", "alert", "block", "block-ip", "drop", "default", "disable",
    "reset-both", "reset-client", "reset-server", "sinkhole",
    "decrypt", "no-decrypt", "decrypt-and-forward", "syn-cookies", "red",
    "source", "source-and-destination", "both", "upload", "download",
}

NEW_RULE_IDS = [
    "decryption_no_outbound", "decryption_profile_weak_tls", "decryption_profile_cert_checks_disabled",
    "zone_protection_no_recon", "zone_protection_flood_disabled", "mgmt_profile_cleartext",
    "mgmt_interface_open_to_any_source", "security_rule_no_log_forwarding",
    "spyware_inline_cloud_analysis_disabled", "vulnerability_inline_cloud_analysis_disabled",
    "spyware_inline_cloud_model_not_reset", "vulnerability_inline_cloud_model_not_reset",
]

# Every lookup path the new parsing relies on — a zero count on a path where
# the device has that feature configured means the parser is looking in the
# wrong place.
PARSER_PATHS = [
    ".//vsys/entry/rulebase/decryption/rules/entry",
    ".//profiles/decryption/entry",
    ".//network/profiles/zone-protection-profile/entry",
    ".//network/profiles/interface-management-profile/entry",
    ".//network/interface",
    ".//vsys/entry/rulebase/security/rules/entry",
    ".//profiles/spyware/entry",
    ".//profiles/vulnerability/entry",
    # management-access reachability inputs
    ".//vsys/entry/zone/entry/network/layer3/member",
    "shared/address/entry",
    "devices/entry/vsys/entry/address/entry",
    "shared/address-group/entry",
    "devices/entry/vsys/entry/address-group/entry",
    "devices/entry/vsys/entry/service/entry",
    "devices/entry/vsys/entry/application-group/entry",
    "devices/entry/vsys/entry/application-filter/entry",
    "devices/entry/vsys/entry/rulebase/default-security-rules/rules/entry",
    ".//vsys/entry/rulebase/security/rules/entry/rule-type",
    ".//vsys/entry/rulebase/security/rules/entry/source-user/member",
]

# Containers whose full set of descendant tag paths is listed, so a tag name
# the parser doesn't know about (or knows under a different name) shows up.
STRUCTURE_PATHS = {
    "Decryption rule entries": ".//vsys/entry/rulebase/decryption/rules/entry",
    "Decryption profile entries": ".//profiles/decryption/entry",
    "Zone protection profile entries": ".//network/profiles/zone-protection-profile/entry",
    "Interface management profile entries": ".//network/profiles/interface-management-profile/entry",
    "Anti-Spyware profile entries": ".//profiles/spyware/entry",
    "Vulnerability Protection profile entries": ".//profiles/vulnerability/entry",
}

# Subtrees under those containers that are large and irrelevant here.
SKIP_SUBTREES = {"rules", "threat-exception", "botnet-domains", "dns-security-categories", "whitelist",
                 "certificates", "category", "source", "destination", "source-user", "from", "to", "tag",
                 "service", "permitted-ip", "exempt-ip", "inline-exception-ip-address",
                 "inline-exception-edl-url"}


class Namer:
    def __init__(self, show: bool):
        self.show = show
        self.maps: dict[str, dict[str, str]] = defaultdict(dict)

    def __call__(self, kind: str, name: str | None) -> str:
        if name is None:
            return "—"
        if self.show:
            return name
        m = self.maps[kind]
        if name not in m:
            m[name] = f"{kind}-{len(m) + 1}"
        return m[name]


def safe(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    # Whole numbers (thresholds, rates, scan IDs) are safe; addresses contain dots/colons.
    if value in SAFE_VALUES or (value.isdigit() and len(value) <= 7):
        return value
    return "<other>"


def tag_paths(el: ET.Element, prefix: str = "") -> list[tuple[str, str | None]]:
    """(relative tag path, leaf text) for every descendant, skipping big
    irrelevant subtrees. 'entry' elements are kept in the path without
    their name attribute."""
    out = []
    for child in el:
        path = f"{prefix}/{child.tag}" if prefix else child.tag
        if child.tag in SKIP_SUBTREES:
            out.append((path + "/…", None))
            continue
        grandchildren = list(child)
        if grandchildren:
            out.extend(tag_paths(child, path))
        else:
            out.append((path, (child.text or "").strip() or None))
    return out


def section(title: str) -> None:
    print(f"\n== {title} " + "=" * max(0, 70 - len(title)))


def report(tsf_bytes: bytes, show_names: bool) -> None:
    name = Namer(show_names)
    config_bytes, cli_text = tsf_parser.extract_config_and_cli_text(tsf_bytes)
    root = ET.fromstring(config_bytes)
    data = tsf_parser.build_assessment_data_from_tsf(tsf_bytes)

    print("TSF verification report — decryption, zone protection, interface mgmt, log forwarding, "
          "Inline Cloud Analysis")
    print(f"Names: {'shown' if show_names else 'replaced with placeholders'}. "
          "Free-text values print as <other>.")
    print(f"PAN-OS version: {data['system_info'].get('sw_version', '—')}")

    section("Parser lookup paths (match counts in the merged config)")
    for path in PARSER_PATHS:
        print(f"  {len(root.findall(path)):5d}  {path}")

    section("Tag structure seen under each container (count of entries using each path)")
    for title, path in STRUCTURE_PATHS.items():
        entries = root.findall(path)
        print(f"\n  {title} ({len(entries)})")
        counts: Counter = Counter()
        values: dict[str, Counter] = defaultdict(Counter)
        for e in entries:
            seen = set()
            for p, text in tag_paths(e):
                if p not in seen:
                    counts[p] += 1
                    seen.add(p)
                if text is not None:
                    values[p][safe(text)] += 1
        for p in sorted(counts):
            vals = ", ".join(f"{v}×{n}" for v, n in values[p].most_common()) if values[p] else ""
            print(f"    {counts[p]:4d}  {p}" + (f"   [{vals}]" if vals else ""))

    section("Decryption (as parsed)")
    dec = data.get("decryption", {})
    for r in dec.get("rules", []):
        print(f"  rule {name('rule', r['name'])}: action={safe(r['action'])} type={r['type']} "
              f"disabled={safe(r['disabled'])} profile={name('profile', r['profile'])}")
    for p in dec.get("profiles", []):
        print(f"  profile {name('profile', p['name'])}: min_version={safe(p['min_version'])} "
              f"(explicit={safe(p['min_version_explicit'])}) "
              f"block_expired={safe(p['forward_proxy_block_expired'])} "
              f"block_untrusted={safe(p['forward_proxy_block_untrusted'])} "
              f"no_decrypt_block_expired={safe(p.get('no_proxy_block_expired'))} "
              f"no_decrypt_block_untrusted={safe(p.get('no_proxy_block_untrusted'))}")

    section("Zone protection (as parsed)")
    zones_by_profile: dict[str, list[str]] = defaultdict(list)
    for z in data.get("zones", []):
        if z.get("zone_protection_profile"):
            zones_by_profile[z["zone_protection_profile"]].append(name("zone", z["name"]))
    for p in data.get("zone_protection_profiles", []):
        flood = ", ".join(f"{k}={safe(v)}" for k, v in p["flood"].items())
        scans = ", ".join(f"{s['id']}:{safe(s['action'])}" for s in p["scans"]) or "none"
        print(f"  {name('profile', p['name'])}: zones=[{', '.join(zones_by_profile.get(p['name'], []))}] "
              f"flood({flood}) syn_action={safe(p['syn_action'])} scans({scans})")
    referenced = {z["zone_protection_profile"] for z in data.get("zones", []) if z.get("zone_protection_profile")}
    defined = {p["name"] for p in data.get("zone_protection_profiles", [])}
    print(f"  zones referencing a profile: {len(referenced)} distinct; defined: {len(defined)}; "
          f"referenced but not found: {len(referenced - defined)}")

    section("Interface management profiles (as parsed)")
    for p in data.get("interface_mgmt_profiles", []):
        on = ", ".join(s for s, v in p["services"].items() if v) or "none"
        print(f"  {name('profile', p['name'])}: services=[{on}] permitted_ips={len(p['permitted_ip'])} "
              f"attached_to={len(p['interfaces'])} interface(s)")
    raw_refs = root.findall(".//network/interface//interface-management-profile")
    attached = sum(len(p["interfaces"]) for p in data.get("interface_mgmt_profiles", []))
    print(f"  interface-management-profile references anywhere under network/interface: {len(raw_refs)}; "
          f"attached by parser: {attached}")

    section("Management access reachability (as analyzed)")
    rtypes = Counter(r.get("rule_type", "universal") for r in data.get("security_rules", []))
    print(f"  rule types: {dict(rtypes)}; default-rule overrides: "
          f"{ {k: safe(v) for k, v in data.get('default_rule_actions', {}).items()} or 'none'}")
    objs = data.get("policy_objects", {})
    print(f"  objects: {len(objs.get('addresses', {}))} addresses, {len(objs.get('address_groups', {}))} address "
          f"groups ({sum(1 for g in objs.get('address_groups', {}).values() if g['dynamic'])} dynamic), "
          f"{len(objs.get('services', {}))} services, {len(objs.get('application_groups', {}))} app groups, "
          f"{len(objs.get('application_filters', []))} app filters")

    def via(v: str) -> str:
        return v if v.endswith("-default") else name("rule", v)

    for entry in mgmt_exposure.analyze(data) or []:
        print(f"  {name('interface', entry['interface'])} zone={name('zone', entry['zone'])} "
              f"profile={name('profile', entry['profile'])} permitted_ips={entry['permitted_ips']} "
              f"address_known={safe(entry['address_known'])}")
        for svc, results in entry["services"].items():
            if not results:
                print(f"      {svc}: interface not in a zone")
                continue
            print(f"      {svc}:")
            # Zones with an identical outcome share one line.
            by_detail: dict[str, list[str]] = defaultdict(list)
            for r in results:
                detail = f"{r['status']}" + (f" (leans {r['lean']})" if r["lean"] else "") + f" via {via(r['via'])}"
                if r["specific_allows"]:
                    detail += f"; specific-source allows: {', '.join(name('rule', n) for n in r['specific_allows'])}"
                for u in r["unresolved_rules"]:
                    causes = ", ".join(
                        c["field"] + (f" {name('object', c['object'])}" if c["object"] else "") + f" is {c['kind']}"
                        for c in u["causes"])
                    detail += f"; unless {name('rule', u['rule'])} ({u['action']}) matches first — {causes}"
                by_detail[detail].append(name("zone", r["source_zone"]))
            for detail, zones in by_detail.items():
                print(f"        [{', '.join(zones)}] {detail}")

    section("Security rules — log forwarding")
    rules = data.get("security_rules", [])
    with_ls = sum(1 for r in rules if r.get("log_setting"))
    print(f"  {len(rules)} rules; {with_ls} with a log-setting, {len(rules) - with_ls} without")

    section("Inline Cloud Analysis (as parsed)")
    for ptype in ("spyware", "vulnerability"):
        for p in data.get("security_profiles", {}).get(ptype, []):
            ica = p.get("settings", {}).get("inline_cloud_analysis")
            if ica is None:
                continue
            models = ", ".join(f"{m}:{safe(a)}" for m, a in ica["models"].items()) or "none"
            print(f"  {ptype} {name('profile', p['name'])}: enabled={safe(ica['enabled'])} models({models})")

    section("Licenses (feature name / expired)")
    print(f"  'request license info' section found: {'yes' if tsf_parser.extract_cli_section(cli_text, 'request license info').strip() else 'NO'}")
    for lic in data.get("licenses", {}).get("licenses", []):
        print(f"  {lic['feature']!r}: expired={safe(lic.get('expired'))} expires={lic.get('expires', '—')}")
    gate = inline_cloud_analysis_gate(data)
    print(f"  Inline Cloud Analysis gate: {gate['status']} — {gate['reason']}")

    section("Findings from the new checks")
    findings = [f for f in run_rules(data, {}) if f["rule_id"] in NEW_RULE_IDS]
    by_rule = Counter(f["rule_id"] for f in findings)
    for rid in NEW_RULE_IDS:
        print(f"  {by_rule.get(rid, 0):4d}  {rid}")
    if show_names:
        for f in findings:
            print(f"        - {f['message']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tsf", help="path to the tech support file (.tgz)")
    ap.add_argument("--show-names", action="store_true",
                    help="print real rule/profile/zone names instead of placeholders")
    ap.add_argument("-o", "--output",
                    help="write the report to this file (UTF-8) instead of the console — use this on "
                         "Windows, where PowerShell's > redirect re-encodes the output")
    args = ap.parse_args(argv)
    # A legacy Windows console code page (e.g. cp437) can't encode — or ×; substitute rather than crash.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    with open(args.tsf, "rb") as f:
        raw = f.read()
    if not tsf_parser.looks_like_tsf(os.path.basename(args.tsf), raw):
        print(f"{args.tsf} doesn't look like a tech support file (.tgz)", file=sys.stderr)
        return 2
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out, contextlib.redirect_stdout(out):
            report(raw, args.show_names)
        print(f"Report written to {args.output}")
    else:
        report(raw, args.show_names)
    return 0


if __name__ == "__main__":
    sys.exit(main())

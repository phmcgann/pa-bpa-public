"""
Diagnostic report for a tech support file: how well the parser understands it, without
revealing what's in it.

    python -m app.tsf_probe /path/to/techsupport.tgz

Prints structure and counts only — which files and command outputs the archive has, which XML
fields certificates carry, how many advisories, shadowed rules and unused objects were found —
so the output can be shared to debug the parser. It never prints object, rule, user or zone
names, addresses, keys or secrets; the hostname and serial are masked wherever they'd appear.
Read the output before sharing it anyway.
"""

from __future__ import annotations

import collections
import io
import re
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

from . import advisories, tsf_parser
from .object_usage import find_duplicates
from .rules import rulebase
from .rules.definitions import RULES
from .rules.engine import run_rules

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
# Full (8 groups) or compressed (with "::") IPv6 addresses, optionally with a prefix length.
_IPV6 = re.compile(r"(?<![\w:])(?=[0-9a-fA-F:]*::|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})[0-9a-fA-F:]{2,39}(?:/\d{1,3})?")
_KEYWORD = re.compile(r"^[a-z][a-z-]*$")
# Words a CLI table header can contain; anything else in a header line is masked.
_HEADER_WORDS = re.compile(r"^[A-Za-z][A-Za-z()/_.-]{0,20}$")


class Masker:
    def __init__(self) -> None:
        self.secrets: list[str] = []

    def add(self, value: str | None) -> None:
        if value and value not in ("N/A", "unknown") and len(value) >= 3:
            self.secrets.append(value)

    def __call__(self, text: str) -> str:
        for s in self.secrets:
            text = text.replace(s, "<masked>")
        return _IPV6.sub("<ip>", _IPV4.sub("<ip>", text))


def _command_stem(line: str) -> str:
    """'> show rule-hit-count vsys vsys-name vsys1 …' → 'show rule-hit-count vsys vsys-name' (keywords only)."""
    words = []
    for w in line[2:].split():
        if not _KEYWORD.match(w):
            break
        words.append(w)
        if len(words) == 4:
            break
    return " ".join(words) or "<unreadable>"


def _header_shape(line: str) -> str:
    return " ".join(w if _HEADER_WORDS.match(w) else "<…>" for w in line.split())


def _tag_paths_containing(root: ET.Element, needle: str, limit: int = 15) -> list[str]:
    out: list[str] = []

    def walk(el: ET.Element, path: list[str]) -> None:
        for c in el:
            p = path + [c.tag]
            if needle in c.tag and "/".join(p[-3:]) not in out:
                out.append("/".join(p[-3:]))
            if len(out) < limit:
                walk(c, p)

    walk(root, [])
    return out[:limit]


def probe(raw: bytes, out=print) -> None:
    """Writes report lines through `out`; main() masks them once the hostname and serial are known."""
    # ── Archive ──
    out("== Archive")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        names = tar.getnames()
    out(f"files in archive: {len(names)}")
    for label, suffix in (("merged running config", tsf_parser.MERGED_CONFIG_SUFFIX),
                          ("plain running config", tsf_parser.PLAIN_CONFIG_SUFFIX)):
        out(f"{label}: {'yes' if any(n.endswith(suffix) for n in names) else 'no'}")
    has_cli = any(re.search(r"tmp/cli/techsupport_.*\.txt$", n) for n in names)
    out(f"CLI text dump: {'yes' if has_cli else 'no'}")
    hitty = [n for n in names if re.search(r"hit|rule[-_]?use|rule[-_]?usage", n, re.I)]
    out(f"files whose name mentions hit counts / rule use: {len(hitty)}")

    try:
        config_bytes, cli_text = tsf_parser.extract_config_and_cli_text(raw)
    except Exception as e:  # noqa: BLE001 — report the failure type, not its text
        out(f"!! couldn't extract config/CLI: {type(e).__name__}")
        return
    config_root = ET.fromstring(config_bytes)

    # ── CLI dump ──
    out("\n== CLI dump")
    lines = cli_text.splitlines()
    markers = [ln for ln in lines if ln.startswith("> ")]
    stems = collections.Counter(_command_stem(ln) for ln in markers)
    out(f"lines: {len(lines)}, command outputs: {len(markers)}, distinct commands: {len(stems)}")
    for key in ("hit", "rule-use", "rule-usage", "certificate", "system info", "license", "high-availability"):
        found = sorted(s for s in stems if key in s)
        out(f"commands mentioning '{key}': {', '.join(found) if found else 'none'}")
    headers = [ln for ln in lines if re.search(r"hit\s*-?\s*count", ln, re.I) and not ln.startswith("> ")]
    out(f"non-command lines mentioning 'hit count': {len(headers)}")
    for h in headers[:5]:
        out(f"  shape: {_header_shape(h)}")

    # ── Parsing ──
    out("\n== Parsing")
    t = time.time()
    try:
        data = tsf_parser.build_assessment_data_from_tsf(raw)
    except Exception as e:  # noqa: BLE001
        out(f"!! parse failed: {type(e).__name__}")
        return
    out(f"parsed in {time.time() - t:.1f}s")
    info = data.get("system_info") or {}
    out(f"system info available: {info.get('available')}, model: {info.get('model')}, "
        f"PAN-OS: {info.get('sw_version')}, Panorama-managed: {data.get('panorama_managed')}")
    rules = data.get("security_rules") or []
    objs = data.get("policy_objects") or {}
    out(f"security rules: {len(rules)} ({sum(r.get('disabled') == 'yes' for r in rules)} disabled) "
        f"across {len({r.get('vsys') for r in rules})} vsys; zones: {len(data.get('zones') or [])}")
    out("objects: " + ", ".join(f"{k} {len(v)}" for k, v in objs.items()))
    lic = data.get("licenses") or {}
    out(f"licenses available: {lic.get('available')}, entries: {len(lic.get('licenses') or [])}")
    out(f"config tag paths containing 'hit': {', '.join(_tag_paths_containing(config_root, 'hit')) or 'none'}")

    # ── Certificates ──
    out("\n== Certificates")
    xml_certs = config_root.findall(".//certificate/entry")
    fields = collections.Counter(c.tag for e in xml_certs for c in e)
    out(f"certificate entries in XML: {len(xml_certs)}")
    out("XML fields seen (entries with each): " + (", ".join(f"{k} {v}" for k, v in sorted(fields.items())) or "none"))
    certs = (data.get("certificates") or {}).get("certificates") or []
    n = len(certs)
    out(f"parsed: {n}; with expiry {sum(bool(c['not_after']) for c in certs)}/{n}, "
        f"key size {sum(bool(c['key_bits']) for c in certs)}/{n}, "
        f"signature {sum(bool(c['signature_hash']) for c in certs)}/{n}, "
        f"private key {sum(c['has_private_key'] for c in certs)}/{n}, CA {sum(c['ca'] for c in certs)}/{n}, "
        f"self-signed {sum(c['self_signed'] for c in certs)}/{n}, in use {sum(bool(c['used_by']) for c in certs)}/{n}")
    uses = collections.Counter(u.split("'")[0].strip() or u for c in certs for u in c["used_by"])
    out("used by (kinds): " + (", ".join(f"{k} {v}" for k, v in uses.most_common()) or "none"))
    out("key types: " + ", ".join(f"{k} {v}" for k, v in collections.Counter(
        f"{c['key_algorithm']} {c['key_bits']}" for c in certs).most_common()))
    out("signatures: " + ", ".join(f"{k} {v}" for k, v in collections.Counter(
        str(c["signature_hash"]) for c in certs).most_common()))

    # ── Advisories ──
    out("\n== Security advisories")
    feed = advisories.snapshot()
    if feed is None and not advisories._enabled():
        out("feed turned off (PAN_ADVISORY_FEED=off)")
    elif feed is None:
        try:
            feed = advisories.fetch()
        except Exception as e:  # noqa: BLE001
            out(f"feed unavailable: {type(e).__name__}")
    if feed is not None:
        hits = advisories.affecting(feed, info.get("sw_version") or "") if info.get("available") else []
        out(f"advisories in feed: {len(feed)}; matching this version: {len(hits)} "
            f"({', '.join(f'{k} {v}' for k, v in collections.Counter(h['severity'] for h in hits).most_common())})")
        out(f"recommended upgrade: {advisories.recommended_upgrade(feed, info.get('sw_version') or '') if hits else '-'}")

    # ── Rulebase ──
    out("\n== Rulebase analysis")
    t = time.time()
    analysis = rulebase.analyze(data)
    out(f"available: {analysis['available']}, analysed in {time.time() - t:.1f}s")
    out("shadowed rules: " + (", ".join(f"{k} {v}" for k, v in collections.Counter(
        s["kind"] for s in analysis["shadowed"]).items()) or "none"))
    usage = data.get("object_usage") or {}
    out(f"unused objects available: {usage.get('available')}; " + (", ".join(
        f"{k} {len(v)}" for k, v in (usage.get("unused") or {}).items()) or "none unused"))
    out(f"addresses used only through a dynamic group: {len(usage.get('used_via_dynamic_group') or [])}")
    groups = objs.get("address_groups") or {}
    out(f"dynamic address groups: {sum(g['dynamic'] for g in groups.values())} of {len(groups)} groups")
    out("duplicate sets: " + (", ".join(f"{k} {v}" for k, v in collections.Counter(
        d["kind"] for d in find_duplicates(objs)).items()) or "none"))

    # ── Findings ──
    out("\n== Findings (default settings)")
    findings = run_rules({**data, "_advisories": feed}, {})
    out("by severity: " + ", ".join(f"{k} {v}" for k, v in collections.Counter(f["severity"] for f in findings).most_common()))
    out(f"rules evaluated: {len(RULES)}; rules with findings: {len({f['rule_id'] for f in findings})}")


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    with open(sys.argv[1], "rb") as f:
        raw = f.read()
    lines: list[str] = []
    probe(raw, out=lines.append)
    # Mask at the end, once the hostname and serial are known.
    mask = Masker()
    try:
        config_bytes, cli_text = tsf_parser.extract_config_and_cli_text(raw)
        mask.add(ET.fromstring(config_bytes).findtext(".//deviceconfig/system/hostname"))
        info = tsf_parser.parse_cli_system_info(cli_text)
        mask.add(info.get("hostname"))
        mask.add(info.get("serial"))
    except Exception:  # noqa: BLE001 — probe() already reported it
        pass
    print("\n".join(mask(line) for line in lines))


if __name__ == "__main__":
    main()

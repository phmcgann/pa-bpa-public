"""Turn a stored SCM BPA run into dashboard findings alongside the core findings."""
from __future__ import annotations

from . import scm_catalog, threat_intel
from .builtin_profiles import unused_builtins, with_builtins
from .checks import (ALWAYS_ON, IOT_DEFAULT_LOG_FORWARDING, _agent_configs, _license_active as license_active,
                     _profiles_of, decrypting, file_blocking_shortfalls)
from .definitions import RULES, RULES_BY_ID


def scm_rule_id(check_id: int) -> str:
    return f"scm_{check_id}"


def core_rules_by_scm_check() -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for r in RULES:
        for cid in r.scm_check_ids:
            out.setdefault(cid, []).append(r.id)
    return out


def not_applicable(data: dict | None):
    """A predicate over SCM run rows (object_type, object_name): True for objects the core rules deliberately
    don't grade, and whose SCM results aren't findings either:
    - a PAN-OS predefined profile nothing uses (default, strict, basic/strict file blocking, ...): it can't be
      edited and no traffic goes through it. One a rule uses is graded, with a note to clone it.
    - HA settings on a firewall with HA off: SCM grades the HA defaults even on a standalone firewall.
    - a disabled policy-based forwarding rule: it routes nothing.
    `data` should include the predefined profiles in use (builtin_profiles.with_builtins)."""
    if data is None:
        return lambda row: False
    skip = unused_builtins(data)
    ha_off = not (data.get("ha_config") or {}).get("enabled")
    skip |= {("policy_based_forwarding_rule", r["name"]) for r in (data.get("misc_policy") or {}).get("pbf_rules", [])
             if r.get("disabled")}
    return lambda row: (row["object_type"], row.get("object_name")) in skip or (
        ha_off and row["object_type"] == "high_availability")


def reported(row: dict, data: dict, rule_settings: dict) -> bool:
    """Whether a run row is one this dashboard reports on at all: failed, not excluded in SCM, licensed, and
    its check not turned off in Settings."""
    if row["passed"] or row["excluded"]:
        return False
    cid = row["check_id"]
    if cid in scm_catalog.LICENSE_GATED and license_active(data, scm_catalog.LICENSE_GATED[cid]) != "yes":
        return False
    return rule_settings.get(scm_rule_id(cid), {}).get("enabled", scm_catalog.enabled_by_default(cid))


def deliberate_differences(data: dict | None) -> dict[int, dict[str | None, str]]:
    """check id -> {object name: why} for objects a linked core rule saw and skipped on purpose."""
    if data is None:
        return {}
    out: dict[int, dict[str | None, str]] = {}
    for p in (data.get("mgmt_plane") or {}).get("radius") or []:
        if (p.get("protocol") or "").upper().startswith("PEAP"):
            out.setdefault(233, {})[p["name"]] = (f"uses {p['protocol']}, an EAP method that tunnels the credentials; "
                                                  "SCM accepts only EAP-TTLS with PAP")
    for portal, c in _agent_configs(data):
        if (c.get("user_override") in ("allowed", "with-comment") and not c.get("override_timeout_min")
                and c.get("connect_method") not in ALWAYS_ON):
            out.setdefault(69, {})[portal["name"]] = (f"connect method is {c.get('connect_method')}, not always-on, so "
                                                      "a disable timeout has nothing to restore")
        if not c.get("internal_host_detection") and not (c.get("internal_gateways") and c.get("external_gateways")):
            out.setdefault(68, {})[portal["name"]] = ("internal host detection only matters when the portal lists both "
                                                      "internal and external gateways")
    # SCM fails #45 even on Palo Alto's own strict File Blocking profile, so a profile that does what the
    # check asks is passed on purpose rather than missed.
    for p in _profiles_of(with_builtins(data)[0], "file_blocking"):
        rules = p["settings"].get("rules", [])
        if any(r["action"] == "block" for r in rules) and not file_blocking_shortfalls(rules):
            out.setdefault(45, {})[p["name"]] = ("blocks all the listed file types and alerts on every other type, for "
                                                 "any application in both directions, as the check asks; SCM fails "
                                                 "this check even on Palo Alto's own strict File Blocking profile")
    # SCM #203 asks for decrypted content to be forwarded to WildFire; with nothing decrypted it changes nothing.
    if not decrypting(data):
        out.setdefault(203, {})["*"] = "nothing is decrypted, so there's no decrypted content to forward"
    # SCM #261-264 also want the block rule to log at session end and forward its logs. The core rule checks the
    # block itself; a rule without log forwarding is security_rule_no_log_forwarding's finding.
    rules = {r["name"]: r for r in data.get("security_rules") or []}
    lists = {e["id"]: e for e in threat_intel.coverage(data)["lists"]}
    for cid, list_id, direction in ((261, "panw-known-ip-list", "inbound"), (262, "panw-known-ip-list", "outbound"),
                                    (263, "panw-highrisk-ip-list", "inbound"), (264, "panw-highrisk-ip-list", "outbound")):
        blocking = [rules[n] for n in lists[list_id][direction] if n in rules]
        if not blocking or any(_logs_forwarded(r) for r in blocking):
            continue
        names = ", ".join(repr(r["name"]) for r in blocking)
        missing = "doesn't log at session end" if all(r.get("log_end") == "no" for r in blocking) else \
            "has no Log Forwarding profile"
        out.setdefault(cid, {})["*"] = (f"rule {names} blocks {list_id}, but it {missing}, which SCM also wants; "
                                        "log forwarding is its own check")
    return out


def _logs_forwarded(rule: dict) -> bool:
    lf = (rule.get("log_setting") or "").strip()
    return rule.get("log_end") != "no" and bool(lf) and lf.lower() != IOT_DEFAULT_LOG_FORWARDING


def why(reasons: dict[str | None, str], name: str | None) -> str | None:
    """The documented reason a core rule skipped this object, if any ("*": any object of the check)."""
    return reasons.get(name) or reasons.get("*")


def build(rows: list[dict], data: dict, core_findings: list[dict], rule_settings: dict) -> list[dict]:
    """One finding per failed, non-excluded (check, object). A finding whose check is linked
    to a core rule that already flagged the same problem is marked `duplicate`, so it isn't
    scored twice; it's still listed, citing Palo Alto's wording. When the core finding names
    its object (`scm_object`, e.g. a GlobalProtect portal), only the SCM result for that same
    object counts as covered; a core finding without one covers the whole check.

    A finding on an object a linked (and enabled) core rule skips on purpose carries that reason as
    `by_design` and isn't scored either, like a duplicate (see deliberate_differences)."""
    catalog = scm_catalog.checks_by_id()
    linked = core_rules_by_scm_check()
    # rule id -> the objects its findings cover; None = a finding not tied to one object.
    core_objects: dict[str, list[dict | None]] = {}
    for f in core_findings:
        core_objects.setdefault(f["rule_id"], []).append(f.get("scm_object"))

    def covered_by(rule_id: str, object_type: str, name: str | None) -> bool:
        return any(o is None or (o["type"] == object_type and o["name"] == name)
                   for o in core_objects.get(rule_id, []))
    disabled_rule_names = {r["name"] for r in data.get("security_rules", []) if r.get("disabled") == "yes"}

    deliberate = deliberate_differences(data)

    def enabled(rule_id: str) -> bool:
        return rule_settings.get(rule_id, {}).get("enabled", RULES_BY_ID[rule_id].enabled_by_default)

    skip = not_applicable(data)
    findings = []
    seen = set()
    for row in rows:
        # Objects that don't apply are listed in the coverage view, not as findings.
        if not reported(row, data, rule_settings) or skip(row):
            continue
        cid = row["check_id"]
        rule_id = scm_rule_id(cid)
        setting = rule_settings.get(rule_id, {})
        check = catalog.get(cid) or {
            "id": cid, "name": row.get("check_name") or f"SCM check {cid}",
            "severity": row.get("check_type") or "Informational",
            "object_type": row["object_type"], "description": row.get("check_message") or "",
        }
        default_severity = scm_catalog.SEVERITY_MAP.get(check["severity"], "INFORMATIONAL")
        severity = setting.get("severity_override") or default_severity
        name = row["object_name"]
        key = f"{rule_id}:{row['object_type']}:{name or 'global'}"
        if key in seen:
            continue
        seen.add(key)

        subject = scm_catalog.object_type_label(row["object_type"]) + (f" '{name}'" if name else "")
        fields = row.get("failed_fields") or {}
        detail = ", ".join(f"{k}={v!r}" for k, v in list(fields.items())[:4]) if isinstance(fields, dict) else ""
        overlaps = [r for r in linked.get(cid, []) if covered_by(r, row["object_type"], name)]
        by_design = (why(deliberate[cid], name or None)
                     if cid in deliberate and not overlaps and any(enabled(r) for r in linked.get(cid, [])) else None)
        findings.append({
            "rule_id": rule_id,
            "finding_key": key,
            "title": check["name"],
            "category": scm_catalog.category_for(row["object_type"]),
            "severity": severity,
            "default_severity": default_severity,
            "severity_overridden": severity != default_severity,
            "message": subject + (f" — {detail}" if detail else ""),
            "recommendation": check.get("description") or check["name"],
            "program": "scm",
            "source_type": "scm",
            "source_ref": f"Palo Alto Networks Strata Cloud Manager BPA check #{cid} ({check['severity']})",
            "scm_check_ids": [cid],
            "location": row.get("location") or None,
            "rule_disabled": row["object_type"] == "security_rule" and name in disabled_rule_names,
            "duplicate_of": overlaps,
            "by_design": by_design,
        })
    return findings

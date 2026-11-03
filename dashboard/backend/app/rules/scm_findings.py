"""Turn a stored SCM BPA run into dashboard findings alongside the core findings."""
from __future__ import annotations

from . import scm_catalog
from .builtin_profiles import unused_builtins
from .checks import _license_active as license_active
from .definitions import RULES


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


def build(rows: list[dict], data: dict, core_findings: list[dict], rule_settings: dict) -> list[dict]:
    """One finding per failed, non-excluded (check, object). A finding whose check is linked
    to a core rule that already flagged the same problem is marked `duplicate`, so it isn't
    scored twice; it's still listed, citing Palo Alto's wording. When the core finding names
    its object (`scm_object`, e.g. a GlobalProtect portal), only the SCM result for that same
    object counts as covered; a core finding without one covers the whole check."""
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
        })
    return findings

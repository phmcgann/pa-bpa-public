"""
How well the core rules cover a stored Palo Alto SCM BPA run.

For every SCM check that failed on this assessment, why it did or didn't overlap a core finding:

  covered          a core rule linked to the check flagged the same problem, so SCM wasn't scored twice
  core_missed      a linked core rule is on but found nothing: its logic or the parser misses what SCM saw
  object_mismatch  a linked core rule fired, but on other objects than the ones SCM failed
  core_off         every linked core rule is turned off in Settings
  no_rule          no core rule covers this check
  by_design        the linked core rule looked at the object and skipped it for a documented reason
                   (for example a RADIUS profile already using an EAP method SCM doesn't accept)
  not_applicable   every object SCM failed is one the core rules deliberately skip: a PAN-OS predefined
                   profile nothing uses (it can't be edited and affects no traffic), or HA settings on a
                   firewall with HA not enabled (SCM grades the HA defaults even on a standalone firewall),
                   or a disabled policy-based forwarding rule

The stored run is kept after SCM stops being reachable, so this stays available. The text export
lists check numbers, titles, statuses and the names (not values) of the fields SCM failed, plus
values that are only a boolean or number — nothing that names the client's objects.
"""

from __future__ import annotations

from ..rules.definitions import RULES_BY_ID
from .builtin_profiles import unused_builtins
from .checks import ALWAYS_ON, _agent_configs
from .scm_findings import core_rules_by_scm_check

STATUS_ORDER = ["core_missed", "object_mismatch", "no_rule", "core_off", "by_design", "not_applicable", "covered"]


def _deliberate(data: dict | None) -> dict[int, dict[str | None, str]]:
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
    return out


def _not_applicable(data: dict | None):
    """A predicate over SCM run rows: True for objects the core rules deliberately don't grade."""
    if data is None:
        return lambda row: False
    skip = unused_builtins(data)
    ha_off = not (data.get("ha_config") or {}).get("enabled")
    # Disabled PBF rules route nothing; the core rules don't grade them.
    skip |= {("policy_based_forwarding_rule", r["name"]) for r in (data.get("misc_policy") or {}).get("pbf_rules", [])
             if r.get("disabled")}
    return lambda row: (row["object_type"], row.get("object_name")) in skip or (
        ha_off and row["object_type"] == "high_availability")


def _safe_fields(rows: list[dict]) -> list[str]:
    """Failed field names, with the value only when it can't identify anything (bool, number, empty)."""
    out: list[str] = []
    for r in rows:
        fields = r.get("failed_fields")
        if not isinstance(fields, dict):
            continue
        for k, v in fields.items():
            label = f"{k}={v}" if isinstance(v, (bool, int, float)) or v is None or v == "" else k
            if label not in out:
                out.append(label)
    return out[:8]


def _scm_object(finding: dict) -> dict:
    """The SCM object an SCM finding is about, from its key (scm_<check>:<object type>:<name or global>)."""
    _, object_type, name = finding["finding_key"].split(":", 2)
    return {"object_type": object_type, "object_name": None if name == "global" else name}


def build(findings: list[dict], run_rows: list[dict], rule_settings: dict, weights: dict,
          data: dict | None = None) -> dict:
    linked = core_rules_by_scm_check()
    not_applicable = _not_applicable(data)
    deliberate = _deliberate(data)
    fired: dict[str, int] = {}
    for f in findings:
        if f.get("program") == "core":
            fired[f["rule_id"]] = fired.get(f["rule_id"], 0) + 1

    by_check: dict[int, list[dict]] = {}
    for f in findings:
        if f.get("program") == "scm" and f.get("scm_check_ids"):
            by_check.setdefault(f["scm_check_ids"][0], []).append(f)

    def enabled(rule_id: str) -> bool:
        rule = RULES_BY_ID[rule_id]
        return rule_settings.get(rule_id, {}).get("enabled", rule.enabled_by_default)

    checks = []
    for cid, all_fs in by_check.items():
        rules = linked.get(cid, [])
        rows = [r for r in run_rows if r["check_id"] == cid and not r["passed"] and not r["excluded"]]
        # Judge the check on the objects the core rules are meant to grade; the rest are listed as n/a.
        fs = [f for f in all_fs if not not_applicable(_scm_object(f))] or all_fs
        if all(not_applicable(_scm_object(f)) for f in all_fs):
            status = "not_applicable"
        elif all(f.get("duplicate_of") for f in fs):
            status = "covered"
        elif not rules:
            status = "no_rule"
        elif not any(enabled(r) for r in rules):
            status = "core_off"
        elif cid in deliberate and all(_scm_object(f)["object_name"] in deliberate[cid] for f in fs
                                       if not f.get("duplicate_of")):
            status = "by_design"
        elif any(fired.get(r) for r in rules):
            status = "object_mismatch"
        else:
            status = "core_missed"
        scored = [f for f in fs if not f.get("dismissed") and f.get("not_scored_reason") in (None, "scm_excluded")
                  and not f.get("duplicate_of")]
        checks.append({
            "check_id": cid, "title": fs[0]["title"], "category": fs[0]["category"], "severity": fs[0]["severity"],
            "status": status, "objects": len(fs), "object_type": rows[0]["object_type"] if rows else None,
            "not_applicable_objects": len(all_fs) - len(fs) if status != "not_applicable" else len(all_fs),
            "points": sum(weights.get(f["severity"], 0) for f in scored),
            "core_rules": [{"id": r, "title": RULES_BY_ID[r].title, "enabled": enabled(r), "findings": fired.get(r, 0)}
                          for r in rules],
            "failed_fields": _safe_fields([r for r in rows if not not_applicable(r)] or rows),
            "reason": "; ".join(sorted({deliberate[cid][_scm_object(f)["object_name"]] for f in fs
                                        if not f.get("duplicate_of")})) if status == "by_design" else None,
        })
    checks.sort(key=lambda c: (STATUS_ORDER.index(c["status"]), -c["points"], c["check_id"]))
    summary = {s: {"checks": sum(1 for c in checks if c["status"] == s),
                   "points": sum(c["points"] for c in checks if c["status"] == s)} for s in STATUS_ORDER}
    return {"checks": checks, "summary": summary}


def as_text(coverage: dict) -> str:
    """Plain-text gap list to share for fixing core rules — check numbers, titles and field names only."""
    lines = ["Core rule coverage of the Palo Alto SCM run"]
    # Everything but "covered"; not_applicable is listed so it can be checked, but isn't a gap.
    for status in STATUS_ORDER[:-1]:
        rows = [c for c in coverage["checks"] if c["status"] == status]
        if not rows:
            continue
        lines.append(f"\n[{status}] {len(rows)} checks, {sum(c['points'] for c in rows)} pts")
        for c in rows:
            rules = ", ".join(r["id"] + ("" if r["enabled"] else " (off)") + (f" x{r['findings']}" if r["findings"] else "")
                              for r in c["core_rules"]) or "-"
            na = f" (+{c['not_applicable_objects']} n/a)" if c.get("not_applicable_objects") and status != "not_applicable" else ""
            lines.append(f"SCM {c['check_id']} | {c['title']} | {c['object_type']} x{c['objects']}{na} | "
                         f"{c['points']} pts | Core: {rules} | fields: {', '.join(c['failed_fields']) or '-'}"
                         + (f" | why: {c['reason']}" if c.get("reason") else ""))
    return "\n".join(lines)

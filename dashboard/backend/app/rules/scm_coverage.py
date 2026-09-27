"""
How well the core rules cover a stored Palo Alto SCM BPA run.

For every SCM check that failed on this assessment, why it did or didn't overlap a core finding:

  covered          a core rule linked to the check flagged the same problem, so SCM wasn't scored twice
  core_missed      a linked core rule is on but found nothing: its logic or the parser misses what SCM saw
  object_mismatch  a linked core rule fired, but on other objects than the ones SCM failed
  core_off         every linked core rule is turned off in Settings
  no_rule          no core rule covers this check

The stored run is kept after SCM stops being reachable, so this stays available. The text export
lists check numbers, titles, statuses and the names (not values) of the fields SCM failed, plus
values that are only a boolean or number — nothing that names the client's objects.
"""

from __future__ import annotations

from ..rules.definitions import RULES_BY_ID
from .scm_findings import core_rules_by_scm_check

STATUS_ORDER = ["core_missed", "object_mismatch", "no_rule", "core_off", "covered"]


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


def build(findings: list[dict], run_rows: list[dict], rule_settings: dict, weights: dict) -> dict:
    linked = core_rules_by_scm_check()
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
    for cid, fs in by_check.items():
        rules = linked.get(cid, [])
        if all(f.get("duplicate_of") for f in fs):
            status = "covered"
        elif not rules:
            status = "no_rule"
        elif not any(enabled(r) for r in rules):
            status = "core_off"
        elif any(fired.get(r) for r in rules):
            status = "object_mismatch"
        else:
            status = "core_missed"
        scored = [f for f in fs if not f.get("dismissed") and f.get("not_scored_reason") in (None, "scm_excluded")
                  and not f.get("duplicate_of")]
        rows = [r for r in run_rows if r["check_id"] == cid and not r["passed"] and not r["excluded"]]
        checks.append({
            "check_id": cid, "title": fs[0]["title"], "category": fs[0]["category"], "severity": fs[0]["severity"],
            "status": status, "objects": len(fs), "object_type": rows[0]["object_type"] if rows else None,
            "points": sum(weights.get(f["severity"], 0) for f in scored),
            "core_rules": [{"id": r, "title": RULES_BY_ID[r].title, "enabled": enabled(r), "findings": fired.get(r, 0)}
                          for r in rules],
            "failed_fields": _safe_fields(rows),
        })
    checks.sort(key=lambda c: (STATUS_ORDER.index(c["status"]), -c["points"], c["check_id"]))
    summary = {s: {"checks": sum(1 for c in checks if c["status"] == s),
                   "points": sum(c["points"] for c in checks if c["status"] == s)} for s in STATUS_ORDER}
    return {"checks": checks, "summary": summary}


def as_text(coverage: dict) -> str:
    """Plain-text gap list to share for fixing core rules — check numbers, titles and field names only."""
    lines = ["Core rule coverage of the Palo Alto SCM run"]
    for status in STATUS_ORDER[:-1]:
        rows = [c for c in coverage["checks"] if c["status"] == status]
        if not rows:
            continue
        lines.append(f"\n[{status}] {len(rows)} checks, {sum(c['points'] for c in rows)} pts")
        for c in rows:
            rules = ", ".join(r["id"] + ("" if r["enabled"] else " (off)") + (f" x{r['findings']}" if r["findings"] else "")
                              for r in c["core_rules"]) or "-"
            lines.append(f"SCM {c['check_id']} | {c['title']} | {c['object_type']} x{c['objects']} | "
                         f"{c['points']} pts | Core: {rules} | fields: {', '.join(c['failed_fields']) or '-'}")
    return "\n".join(lines)

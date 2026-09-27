from __future__ import annotations

from .checks import CHECKS
from .definitions import RULES

DEFAULT_WEIGHTS = {"CRITICAL": 10, "WARNING": 5, "LOW": 2, "INFORMATIONAL": 1}
DEFAULT_THRESHOLDS = {"informational_max": 0, "low_max": 15, "warning_max": 40}

SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "WARNING", "CRITICAL"]
SEVERITIES = ("CRITICAL", "WARNING", "LOW", "INFORMATIONAL")
SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def score_based_label(score: int, thresholds: dict) -> str:
    """The label the point total alone would produce, ignoring any floor."""
    if score <= thresholds["informational_max"]:
        return "INFORMATIONAL"
    if score <= thresholds["low_max"]:
        return "LOW"
    if score <= thresholds["warning_max"]:
        return "WARNING"
    return "CRITICAL"


def highest_active_severity(severity_counts: dict) -> str | None:
    for sev in reversed(SEVERITY_ORDER):
        if severity_counts.get(sev, 0) > 0:
            return sev
    return None


def risk_label(score: int, thresholds: dict, floor: str | None = None) -> str:
    """Point-based label, raised to at least `floor` if given. A single active
    CRITICAL finding guarantees an overall CRITICAL label even when the point
    total alone (governed by adjustable weights/thresholds) wouldn't cross
    that bucket — the label is never lower than the worst thing actually found."""
    label = score_based_label(score, thresholds)
    if floor and SEVERITY_RANK[floor] > SEVERITY_RANK[label]:
        return floor
    return label


def run_rules(data: dict, rule_settings: dict[str, dict]) -> list[dict]:
    """rule_settings: {rule_id: {"enabled": bool, "threshold_overrides": dict|None,
    "severity_override": str|None}}. Missing entries use rule defaults."""
    # Per-rule checks (rule_id starting with "security_rule_") key their finding
    # on the security-policy rule name — cross-reference against disabled rules
    # so those findings can be auto-excluded from the score, same as a dismiss,
    # but distinguishable as "the rule itself is off" rather than a manual call.
    disabled_rule_names = {
        r["name"] for r in data.get("security_rules", []) if r.get("disabled") == "yes"
    }

    findings = []
    for rule in RULES:
        setting = rule_settings.get(
            rule.id, {"enabled": rule.enabled_by_default, "threshold_overrides": None, "severity_override": None}
        )
        if not setting.get("enabled", rule.enabled_by_default):
            continue

        thresholds = {**rule.thresholds, **(setting.get("threshold_overrides") or {})}
        severity = setting.get("severity_override") or rule.default_severity
        check_fn = CHECKS[rule.id]
        is_per_rule_check = rule.id.startswith("security_rule_")
        for item in check_fn(data, thresholds):
            findings.append({
                "rule_id": rule.id,
                "finding_key": f"{rule.id}:{item['key']}",
                "title": rule.title,
                "category": rule.category,
                "severity": severity,
                "default_severity": rule.default_severity,
                "severity_overridden": severity != rule.default_severity,
                "message": item["message"],
                "recommendation": item["recommendation"],
                "program": "core",
                "source_type": rule.source_type,
                "source_ref": rule.source_ref,
                "scm_check_ids": list(rule.scm_check_ids),
                "rule_disabled": is_per_rule_check and item["key"] in disabled_rule_names,
                # The object this finding is about, in SCM's terms, when the check knows it —
                # lets an SCM result count as a duplicate only for that same object.
                "scm_object": item.get("scm_object"),
            })
    return findings


def summarize(findings: list[dict], weights: dict | None = None, thresholds: dict | None = None) -> dict:
    weights = weights or DEFAULT_WEIGHTS
    thresholds = thresholds or DEFAULT_THRESHOLDS

    severity_counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        severity_counts[f["severity"]] += 1

    breakdown = {sev: {"count": severity_counts[sev], "weight": weights[sev], "points": severity_counts[sev] * weights[sev]}
                 for sev in SEVERITIES}
    score = sum(b["points"] for b in breakdown.values())

    floor = highest_active_severity(severity_counts)
    points_label = score_based_label(score, thresholds)
    final_label = risk_label(score, thresholds, floor)

    return {
        "severity_counts": severity_counts,
        "score": score,
        "score_breakdown": breakdown,
        "weights": weights,
        "thresholds": thresholds,
        "points_based_label": points_label,
        "risk_label": final_label,
        "floor_applied": final_label != points_label,
        "total": len(findings),
    }

"""
Remediation plan: the assessment's scored findings grouped into work items, most urgent first.

A work item is a piece of work a firewall engineer would do in one go — upgrade PAN-OS, attach
security profiles to allow rules, clean up the rulebase — so one change resolves a group of
findings. Core rules are placed by rule id; anything else (Palo Alto SCM findings, a rule not
listed here) by its category. Items are ordered by the worst severity they resolve, then by the
risk points they'd remove from the score.

Only findings that count toward the score are included: dismissed findings, findings on disabled
security rules, and SCM duplicates or excluded SCM results are left out.
"""

from __future__ import annotations

from typing import Optional

from .rules.engine import SEVERITY_RANK

# (key, title, summary, rule ids, categories that fall back to it)
ITEMS: list[tuple[str, str, str, set[str], set[str]]] = [
    ("upgrade", "Upgrade PAN-OS",
     "Move to a PAN-OS build that fixes the published vulnerabilities affecting this firewall and is still "
     "supported. Plan it as a maintenance window, upgrading the HA peer first if there is one.",
     {"eol_pan_os_version", "panos_advisory_critical", "panos_advisory_high", "panos_advisory_medium",
      "panos_advisory_low"}, set()),
    ("block_known_bad", "Block known-malicious and high-risk traffic",
     "Add deny rules at the top of the policy for Palo Alto Networks' built-in threat IP lists (both directions), "
     "block QUIC so browsers fall back to inspectable TLS, and control generative-AI apps.",
     {"edl_known_malicious_not_blocked", "edl_high_risk_not_blocked", "edl_bulletproof_not_blocked",
      "edl_tor_exit_not_blocked", "quic_not_blocked", "aipd_c2_not_blocked", "aipd_malware_ip_not_blocked",
      "aipd_inbound_list_not_blocked", "aipd_rule_missing_pair", "genai_no_block_rule", "genai_tolerated_no_users",
      "genai_allow_no_dlp"}, set()),
    ("broad_rules", "Tighten over-permissive security rules",
     "Replace any/any rules and service-any rules with rules scoped to the applications, sources and ports that "
     "are needed, end the policy with an explicit logged deny, and fix rules that never take effect.",
     {"security_rule_any_any_any", "security_rule_app_any_service_any", "security_rule_service_any",
      "security_rule_inbound_untrust_any_source", "security_policy_no_deny_remaining", "app_override_rule",
      "no_new_appid_rule", "user_id_zone_disabled", "security_rule_server_response_inspection_off",
      "security_rule_shadowed_block"}, {"Security Policy"}),
    ("attach_profiles", "Apply security profiles to every allow rule",
     "Attach a best-practice security profile group (antivirus, anti-spyware, vulnerability protection, URL "
     "filtering, file blocking, WildFire) to every rule that allows traffic.",
     {"threat_profile_missing_antivirus", "threat_profile_missing_vulnerability", "threat_profile_missing_spyware",
      "threat_profile_missing_url_filtering", "threat_profile_missing_file_blocking", "wildfire_profile_missing",
      "security_rule_missing_profile_non_infra", "security_rule_missing_profile_infra",
      "advanced_profile_not_applied"}, set()),
    ("harden_profiles", "Harden security profile settings",
     "Bring the profiles in use up to Palo Alto Networks' best-practice settings: block actions for critical and "
     "high threats, the recommended URL categories, WildFire file types and inline cloud analysis.",
     set(), {"Security Profiles"}),
    ("decryption", "Decrypt and inspect encrypted traffic",
     "Decrypt outbound traffic (excluding sensitive categories) with profiles that block weak protocols and bad "
     "certificates, so security profiles can see threats inside TLS.",
     set(), {"Decryption"}),
    ("mgmt_access", "Lock down management access",
     "Restrict who can reach the management interfaces and how: permitted-IP lists, no cleartext protocols, MFA "
     "and lockout for administrators, strong TLS, and secure authentication servers.",
     set(), {"Access Control", "Device Hardening"}),
    ("network_protection", "Protect zones and sessions",
     "Attach Zone Protection profiles to every zone (recon, flood and packet-based protection), protect critical "
     "servers with DoS Protection policy, and restore the recommended session settings.",
     set(), {"Network Security", "DoS Protection"}),
    ("vpn", "Strengthen site-to-site VPN", "Move tunnels to IKEv2 with strong encryption, authentication and DH "
     "groups, and turn on tunnel monitoring and anti-replay.", set(), {"VPN"}),
    ("globalprotect", "Harden GlobalProtect", "Tighten the GlobalProtect portal and gateways: strong TLS, "
     "multi-factor authentication, certificate checks, and connection enforcement.", set(), {"GlobalProtect"}),
    ("certificates", "Renew and replace certificates", "Renew expiring certificates and replace ones with weak "
     "keys, weak signatures, or self-signed certificates on user-facing services.", set(), {"Certificates"}),
    ("nat", "Fix NAT policy", "Remove NAT rules that never match or have no security rule, and narrow port "
     "forwards to only the ports that are needed.", set(), {"NAT"}),
    ("ha", "Fix high availability", "Complete the HA configuration so failover is fast and sessions survive it.",
     set(), {"High Availability"}),
    ("logging", "Complete logging and log forwarding", "Log every allow and deny rule at session end and forward "
     "traffic, threat, system and configuration logs to a SIEM or syslog server over TLS.",
     {"security_rule_no_logging_allow"}, {"Logging"}),
    ("updates_licenses", "Renew licenses and fix content updates", "Renew expired subscriptions and schedule "
     "threat, antivirus, WildFire and GlobalProtect content updates at the recommended frequency.",
     {"content_updates_not_timely", "update_server_verification_off", "content_updates_gp_not_hourly"},
     {"Licensing", "Software"}),
    ("cleanup", "Clean up the rulebase", "Remove redundant and unreachable rules, temporary and undocumented rules, "
     "unused objects and duplicates, so the policy stays reviewable.",
     {"security_rule_shadowed", "security_rule_temp_test_name", "security_rule_no_description", "unused_objects",
      "duplicate_objects"}, set()),
]

# Why each piece of work matters, in plain language for the executive summary.
RISKS: dict[str, str] = {
    "upgrade": "The installed PAN-OS version has published vulnerabilities that attackers can look up and exploit.",
    "block_known_bad": "Traffic to and from addresses Palo Alto Networks knows are malicious or high-risk isn't "
                       "blocked outright.",
    "broad_rules": "Some rules allow far more traffic than the business needs, so an attacker has more ways in "
                   "and more room to move once inside.",
    "attach_profiles": "Traffic allowed by some rules isn't scanned for malware, exploits or malicious sites.",
    "harden_profiles": "The threat-prevention profiles in use would let some known threats through.",
    "decryption": "Encrypted traffic isn't inspected, so threats hidden inside it pass unseen.",
    "mgmt_access": "The firewall's own management access could be reached or misused more easily than it should.",
    "network_protection": "Zones and servers aren't fully protected from floods, scans and malformed packets.",
    "vpn": "Some site-to-site VPN tunnels use weaker cryptography or lack monitoring.",
    "globalprotect": "Remote access through GlobalProtect is less protected than recommended.",
    "certificates": "Certificates that have expired, will expire soon or use weak cryptography can cause outages "
                    "or weaken trust in the firewall's services.",
    "nat": "Some NAT rules expose more of internal hosts than needed, or are left over and never used.",
    "ha": "The high-availability setup may not fail over cleanly, risking an outage.",
    "logging": "Gaps in logging would make it hard to detect or investigate an incident.",
    "updates_licenses": "Expired subscriptions or slow content updates leave the firewall without current threat "
                        "protection.",
    "cleanup": "Unused and redundant rules and objects make the policy harder to review and easier to get wrong.",
    "other": "Other configuration items differ from best practice.",
}

_BY_RULE = {rid: key for key, _, _, rids, _ in ITEMS for rid in rids}
_BY_CATEGORY = {cat: key for key, _, _, _, cats in ITEMS for cat in cats}


def _scored(f: dict) -> bool:
    return not f.get("dismissed") and not f.get("rule_disabled") and f.get("not_scored_reason") is None


def build(findings: list[dict], weights: dict, recommended_upgrade: Optional[str] = None) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for f in findings:
        if not _scored(f):
            continue
        key = (_BY_RULE.get(f["rule_id"]) if f.get("program") != "scm" else None) \
            or _BY_CATEGORY.get(f.get("category", ""), "other")
        groups.setdefault(key, []).append(f)

    meta = {key: (title, summary) for key, title, summary, _, _ in ITEMS}
    meta["other"] = ("Other items", "Findings that don't belong to one of the work items above.")
    items = []
    for key, fs in groups.items():
        title, summary = meta[key]
        if key == "upgrade" and recommended_upgrade:
            title = f"Upgrade PAN-OS to {recommended_upgrade} or later"
        checks: dict[str, dict] = {}
        for f in fs:
            c = checks.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "title": f["title"], "severity": f["severity"],
                                                 "program": f.get("program", "core"), "count": 0})
            c["count"] += 1
            if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK[c["severity"]]:
                c["severity"] = f["severity"]
        items.append({
            "key": key, "title": title, "summary": summary, "risk": RISKS[key],
            "severity": max((f["severity"] for f in fs), key=SEVERITY_RANK.__getitem__),
            "points": sum(weights.get(f["severity"], 0) for f in fs),
            "finding_count": len(fs),
            "finding_keys": [f["finding_key"] for f in fs],
            "checks": sorted(checks.values(), key=lambda c: (-SEVERITY_RANK[c["severity"]], -c["count"], c["title"])),
        })
    items.sort(key=lambda i: (-SEVERITY_RANK[i["severity"]], -i["points"], i["title"]))
    for n, item in enumerate(items, 1):
        item["order"] = n
    return items

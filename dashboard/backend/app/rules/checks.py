"""
Per-rule check functions, ported out of collect_data.py's analysis logic.

Each function takes the full parsed data dict and that rule's threshold dict,
and returns a list of {"key", "message", "recommendation"} — one per
offending object (a rule name, an admin name, a license feature, etc), or a
single "global" key for whole-config checks. `key` is combined with the rule
id upstream to build a stable, dismissible finding_key.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .. import advisories
from ..certificates import USER_FACING
from ..object_usage import KINDS as OBJECT_KINDS, find_duplicates
from . import mgmt_exposure, nat, rulebase, threat_intel

# Known infrastructure apps that don't need security profiles.
INFRA_APPS = {"ike", "ipsec", "ping", "bgp", "ospf", "rip", "ms-rdp",
              "snmp", "ssh", "ntp", "dns", "icmp", "syslog"}

# Inbound-only services (health probes, load balancers) — lower risk for missing profiles.
INFRA_RULE_PATTERNS = ["healthprobe", "health-probe", "bgp", "ipsec", "ntp",
                        "snmp", "ospf", "veeam", "rdp", "peering"]

TEMP_TEST_KEYWORDS = ["temp", "test", "testing", "tmp", "debug", "old", "backup"]


def is_infra_rule(name: str, apps: list[str]) -> bool:
    name_lower = name.lower()
    if any(p in name_lower for p in INFRA_RULE_PATTERNS):
        return True
    if apps and all(a in INFRA_APPS for a in apps):
        return True
    return False


# ── Software / Licensing (live-mode only) ──────────────────────────────────

def check_eol_pan_os_version(data: dict, thresholds: dict) -> list[dict]:
    info = data.get("system_info", {})
    if not info.get("available"):
        return []
    version = info.get("sw_version", "")
    if not version or not version[0].isdigit():
        return []
    major = int(version.split(".")[0])
    if major < thresholds["eol_major_version"]:
        return [{
            "key": "global",
            "message": f"PAN-OS version {version} is End-of-Life or nearing EOL",
            "recommendation": "Upgrade to the latest supported PAN-OS release",
        }]
    return []


def check_license_expired(data: dict, thresholds: dict) -> list[dict]:
    lic_data = data.get("licenses", {})
    if not lic_data.get("available"):
        return []
    out = []
    for lic in lic_data.get("licenses", []):
        if lic.get("expired", "no").lower() == "yes":
            out.append({
                "key": lic["feature"],
                "message": f"License EXPIRED: {lic['feature']}",
                "recommendation": "Renew license immediately to restore security coverage",
            })
    return out


def check_license_expiring_soon(data: dict, thresholds: dict) -> list[dict]:
    lic_data = data.get("licenses", {})
    if not lic_data.get("available"):
        return []
    out = []
    today = datetime.now()
    for lic in lic_data.get("licenses", []):
        if lic.get("expired", "no").lower() == "yes":
            continue
        try:
            exp_date = datetime.strptime(lic.get("expires", ""), "%B %d, %Y")
        except ValueError:
            continue
        days_left = (exp_date - today).days
        if days_left < thresholds["expiry_warning_days"]:
            out.append({
                "key": lic["feature"],
                "message": f"License expiring in {days_left} days: {lic['feature']}",
                "recommendation": "Renew before expiration to avoid a security gap",
            })
    return out


# ── Access Control ──────────────────────────────────────────────────────

def check_default_admin_account(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for admin in data.get("admin_accounts", []):
        if admin["name"] == "admin":
            out.append({
                "key": admin["name"],
                "message": f"Default admin account '{admin['name']}' exists",
                "recommendation": "Rename or disable the default 'admin' account; use named accounts",
            })
    return out


def check_admin_local_auth_no_mfa(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for admin in data.get("admin_accounts", []):
        if admin.get("auth_profile", "local") in ("local", "N/A", ""):
            out.append({
                "key": admin["name"],
                "message": f"Admin '{admin['name']}' uses local authentication (no MFA)",
                "recommendation": "Enforce MFA via an authentication profile (RADIUS/SAML/LDAP)",
            })
    return out


# ── Network Security ─────────────────────────────────────────────────────

def check_zone_missing_protection_profile(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for zone in data.get("zones", []):
        if not zone.get("zone_protection_profile"):
            out.append({
                "key": zone["name"],
                "message": f"Zone '{zone['name']}' has no Zone Protection Profile assigned",
                "recommendation": "Apply a Zone Protection Profile with flood protection and "
                                   "reconnaissance detection",
            })
    return out


def _assigned_zone_protection_profiles(data: dict) -> list[tuple[dict, list[str]]]:
    """(profile, zones using it) for every defined profile. Unassigned profiles are graded too, as Palo
    Alto SCM does: one attach away from protecting a zone with weak settings."""
    zones_by_profile: dict[str, list[str]] = {}
    for zone in data.get("zones", []):
        name = zone.get("zone_protection_profile")
        if name:
            zones_by_profile.setdefault(name, []).append(zone["name"])
    return [(p, zones_by_profile.get(p["name"], [])) for p in data.get("zone_protection_profiles", [])]


def _zones_text(zones: list[str]) -> str:
    return f"zones: {', '.join(zones)}" if zones else "not assigned to any zone"


def check_zone_protection_no_recon(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile, zones in _assigned_zone_protection_profiles(data):
        scans = profile.get("scans", [])
        if scans and any(s["action"] != "allow" for s in scans):
            continue
        detail = "has no reconnaissance protection enabled" if not scans else \
            "detects scans but every scan type's action is allow"
        out.append({
            "key": profile["name"],
            "message": f"Zone Protection Profile '{profile['name']}' ({_zones_text(zones)}) {detail}",
            "recommendation": "Enable Reconnaissance Protection for TCP/UDP port scans and host sweeps with "
                              "a block or block-ip action, keeping the default threshold",
        })
    return out


SCAN_LABEL = {"8001": "TCP port scan", "8002": "host sweep", "8003": "UDP port scan"}


def check_zone_protection_recon_alert_only(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile, zones in _assigned_zone_protection_profiles(data):
        alert_only = [s for s in profile.get("scans", []) if s["action"] == "alert"]
        if not alert_only:
            continue
        labels = ", ".join(f"{SCAN_LABEL.get(s['id'], 'scan')} ({s['id']})" for s in alert_only)
        out.append({
            "key": profile["name"],
            "message": f"Zone Protection Profile '{profile['name']}' ({_zones_text(zones)}) only alerts "
                       f"on {labels} — the scan is logged but not stopped",
            "recommendation": "Set the reconnaissance action to block-ip (or block) so the scanning source is "
                              "cut off, not just logged",
        })
    return out


def check_zone_protection_flood_disabled(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile, zones in _assigned_zone_protection_profiles(data):
        for ftype, enabled in profile.get("flood", {}).items():
            if enabled is False:
                out.append({
                    "key": f"{profile['name']}:{ftype}",
                    "message": f"Zone Protection Profile '{profile['name']}' ({_zones_text(zones)}) "
                               f"has {ftype} flood protection disabled",
                    "recommendation": "Enable flood protection for this type with alarm/activate/maximum "
                                      "thresholds based on the zone's measured baseline connections per second",
                })
    return out


# ── Security Policy (per-rule) ───────────────────────────────────────────

def check_security_rule_any_any_any(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow":
            continue
        if rule["sources"] == ["any"] and rule["destinations"] == ["any"] and rule["applications"] == ["any"]:
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}' allows ANY source, ANY destination, ANY application",
                "recommendation": "Restrict to specific sources, destinations, and applications",
            })
    return out


def _profile_present(rule: dict) -> bool:
    pg = (rule.get("profile_group") or "").strip()
    return bool(pg and pg != "N/A") or bool(rule.get("indiv_profiles"))


def check_security_rule_missing_profile_non_infra(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow" or _profile_present(rule):
            continue
        if not is_infra_rule(rule["name"], rule["applications"]):
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}' has no security profile group attached",
                "recommendation": "Attach a security profile group (AV, IPS, Anti-Spyware, URL)",
            })
    return out


def check_security_rule_missing_profile_infra(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow" or _profile_present(rule):
            continue
        if is_infra_rule(rule["name"], rule["applications"]):
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}' (infrastructure) has no security profile group",
                "recommendation": "Confirm this is an intentional infrastructure exception and document it",
            })
    return out


def check_security_rule_inbound_untrust_any_source(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow":
            continue
        if "untrust" in rule["from_zones"] and rule["sources"] == ["any"]:
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}' allows inbound traffic from ANY source on the internet",
                "recommendation": "Restrict source to known IP addresses or ranges; use Geo-IP blocking",
            })
    return out


def check_security_rule_app_any_service_any(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow":
            continue
        src_any = rule["sources"] == ["any"]
        dst_any = rule["destinations"] == ["any"]
        app_any = rule["applications"] == ["any"]
        svc_any = rule["services"] == ["any"]
        if app_any and svc_any and not src_any and not dst_any:
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}': Application=any + Service=any",
                "recommendation": "Specify application(s) to enable App-ID-based enforcement",
            })
    return out


def check_security_rule_service_any(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow":
            continue
        svc_any = rule["services"] == ["any"]
        app_any = rule["applications"] == ["any"]
        if svc_any and not app_any:
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}': Service=any with specific apps",
                "recommendation": "Use 'application-default' to restrict ports instead of service=any",
            })
    return out


def check_security_rule_no_description(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] == "allow" and not rule.get("description"):
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}' has no description",
                "recommendation": "Document rule purpose for auditing",
            })
    return out


def check_security_rule_temp_test_name(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow":
            continue
        name_lower = rule["name"].lower()
        if any(kw in name_lower for kw in TEMP_TEST_KEYWORDS):
            out.append({
                "key": rule["name"],
                "message": f"Rule '{rule['name']}' appears to be a temporary/test rule still active",
                "recommendation": "Review and remove or rename this rule if no longer needed",
            })
    return out


def check_security_rule_no_logging_allow(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] != "allow":
            continue
        if rule["log_end"] == "no" and rule["log_start"] == "no":
            out.append({
                "key": rule["name"],
                "message": f"Allow rule '{rule['name']}' has logging disabled",
                "recommendation": "Enable log-at-session-end for an audit trail",
            })
    return out


def check_security_rule_deny_no_logging(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        if rule["action"] not in ("deny", "drop"):
            continue
        if rule["log_end"] == "no" and rule["log_start"] == "no":
            out.append({
                "key": rule["name"],
                "message": f"Deny/drop rule '{rule['name']}' has logging disabled",
                "recommendation": "Enable logging on deny rules to detect blocked attack attempts",
            })
    return out


def check_security_rule_no_log_forwarding(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for rule in data.get("security_rules", []):
        # Rules stored before log-setting was parsed have no key at all — skip
        # rather than read that as "no profile attached".
        if "log_setting" not in rule or rule["log_setting"]:
            continue
        out.append({
            "key": rule["name"],
            "message": f"Rule '{rule['name']}' has no Log Forwarding profile — its logs never leave the firewall",
            "recommendation": "Attach a Log Forwarding profile that sends traffic and threat logs to "
                              "Panorama, syslog, or your SIEM",
        })
    return out


def check_security_policy_no_deny_remaining(data: dict, thresholds: dict) -> list[dict]:
    rules = data.get("security_rules", [])
    active = [r for r in rules if r["disabled"] != "yes"]

    def is_catch_all(r):
        return (r["action"] in ("deny", "drop") and r["sources"] == ["any"]
                and r["destinations"] == ["any"] and r["applications"] == ["any"]
                and r["from_zones"] == ["any"] and r["to_zones"] == ["any"])

    has_enabled = any(is_catch_all(r) for r in active)
    if has_enabled:
        return []

    has_disabled = any(
        r["action"] in ("deny", "drop") and r["sources"] == ["any"]
        and r["destinations"] == ["any"] and r["applications"] == ["any"]
        and r["disabled"] == "yes"
        for r in rules
    )
    if has_disabled:
        return [{
            "key": "global",
            "message": "Catch-all deny/drop-all rule exists but is DISABLED — unmatched traffic "
                       "falls to PAN-OS implicit allow",
            "recommendation": "Enable the deny-all rule at the bottom of the rulebase to enforce "
                              "default-deny posture",
        }]
    return [{
        "key": "global",
        "message": "No catch-all deny/drop-all rule at the bottom of the rulebase",
        "recommendation": "Add an explicit deny-all rule as the last rule to enforce default-deny "
                          "and ensure all unmatched traffic is logged",
    }]


# ── Security Profiles ─────────────────────────────────────────────────────

def _security_profile_missing(profile_key: str, label: str):
    def check(data: dict, thresholds: dict) -> list[dict]:
        if data.get("security_profiles", {}).get(profile_key):
            return []
        return [{
            "key": "global",
            "message": f"No {label} profiles defined",
            "recommendation": f"Create and apply {label} profiles to all allow rules",
        }]
    return check


check_threat_profile_missing_antivirus = _security_profile_missing("antivirus", "Antivirus")
check_threat_profile_missing_vulnerability = _security_profile_missing("vulnerability", "Vulnerability Protection")
check_threat_profile_missing_spyware = _security_profile_missing("spyware", "Anti-Spyware")
check_threat_profile_missing_url_filtering = _security_profile_missing("url_filtering", "URL Filtering")
check_threat_profile_missing_file_blocking = _security_profile_missing("file_blocking", "File Blocking")


def check_wildfire_profile_missing(data: dict, thresholds: dict) -> list[dict]:
    if data.get("security_profiles", {}).get("wildfire_analysis"):
        return []
    return [{
        "key": "global",
        "message": "No WildFire analysis profiles configured",
        "recommendation": "Create WildFire profiles and attach to allow rules for unknown file analysis",
    }]


# ── Security Profile Settings vs. BPA ────────────────────────────────────
#
# The checks above only confirm a profile is attached. These look inside the
# profile and compare what's actually configured against Palo Alto's own
# "Create Best Practice Security Profiles for the Internet Gateway" page —
# every baseline value and category name below was cross-checked against a
# real PAN-OS 11.1 profile (see the Security Profile Audit this was built
# from), not assumed. Vulnerability Protection's dedicated brute-force rules
# are deliberately NOT checked: the reference firewall has none configured,
# so there's no real example to confirm the XML shape against. Inline Cloud
# Analysis is checked, but only when the firewall has an active Advanced
# Threat Prevention license — see inline_cloud_analysis_gate() below.

RESET_ACTIONS = {"reset-both", "reset-client", "reset-server"}

AV_DECODERS = ["ftp", "http", "http2", "imap", "pop3", "smb", "smtp"]

# Palo Alto's predefined DNS Security category names — all nine are BPA's
# "sinkhole" list; a subset (cc/grayware/malware/phishing/proxy/adtracking)
# is commonly pre-configured to sinkhole out of the box, but the same
# guidance covers all nine.
DNS_SINKHOLE_CATEGORIES = [
    "pan-dns-sec-cc", "pan-dns-sec-grayware", "pan-dns-sec-malware", "pan-dns-sec-phishing",
    "pan-dns-sec-proxy", "pan-dns-sec-adtracking", "pan-dns-sec-ddns", "pan-dns-sec-parked",
    "pan-dns-sec-recent",
]

URL_MANDATORY_BLOCK_CATEGORIES = [
    "command-and-control", "compromised-website", "grayware", "malware",
    "phishing", "ransomware", "scanning-activity",
]

URL_ELEVATED_RISK_CATEGORIES = [
    "dynamic-dns", "encrypted-dns", "hacking", "insufficient-content",
    "newly-registered-domain", "not-resolved", "parked", "unknown",
    "proxy-avoidance-and-anonymizers",
]

WILDFIRE_RECOMMENDED_FILETYPES = ["pdf", "ms-office"]


def _profiles_of(data: dict, ptype: str) -> list[dict]:
    """Profiles with settings actually captured. Assessments stored before this
    feature shipped have profile dicts with no "settings" key at all — treating
    that the same as a genuinely empty settings dict would flag every BPA
    category as a gap, fabricating findings for data that was never parsed.
    Skip those profiles entirely rather than guess."""
    return [p for p in data.get("security_profiles", {}).get(ptype, []) if "settings" in p]


def check_av_decoder_below_baseline(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "antivirus"):
        decoders = profile.get("settings", {}).get("decoders", {})
        for name in AV_DECODERS:
            d = decoders.get(name)
            if d is None:
                continue
            if d["action"] != "reset-both" or d["wildfire_action"] != "reset-both" or d["mlav_action"] != "reset-both":
                out.append({
                    "key": f"{profile['name']}:{name}",
                    "message": f"Antivirus profile '{profile['name']}' decoder '{name}' isn't set to "
                               f"reset-both (action={d['action']}, wildfire={d['wildfire_action']}, "
                               f"ml={d['mlav_action']})",
                    "recommendation": "Set action, WildFire action, and Machine Learning action to "
                                       "reset-both for this decoder",
                })
    return out


def check_av_inline_ml_disabled(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "antivirus"):
        inline_ml = profile.get("settings", {}).get("inline_ml", {})
        for file_type, action in inline_ml.items():
            if action == "disable":
                out.append({
                    "key": f"{profile['name']}:{file_type}",
                    "message": f"Antivirus profile '{profile['name']}' has Inline ML disabled for "
                               f"'{file_type}'",
                    "recommendation": "Set an enforcing action for all Inline ML file types rather than "
                                       "leaving them disabled",
                })
    return out


def check_spyware_severity_below_baseline(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "spyware"):
        for rule in profile.get("settings", {}).get("severity_rules", []):
            if not set(rule["severities"]) & {"critical", "high", "medium"}:
                continue
            if rule["action"] not in RESET_ACTIONS:
                out.append({
                    "key": f"{profile['name']}:{rule['name']}",
                    "message": f"Anti-Spyware profile '{profile['name']}' rule '{rule['name']}' "
                               f"({'/'.join(rule['severities'])}) action is '{rule['action']}', not a reset",
                    "recommendation": "Set critical/high/medium severity rules to Reset Both with "
                                       "single-packet capture",
                })
    return out


def check_vulnerability_severity_below_baseline(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "vulnerability"):
        for rule in profile.get("settings", {}).get("severity_rules", []):
            if not set(rule["severities"]) & {"critical", "high", "medium"}:
                continue
            if rule["action"] not in RESET_ACTIONS:
                out.append({
                    "key": f"{profile['name']}:{rule['name']}",
                    "message": f"Vulnerability Protection profile '{profile['name']}' rule '{rule['name']}' "
                               f"({'/'.join(rule['severities'])}) action is '{rule['action']}', not a reset",
                    "recommendation": "Set critical/high/medium severity rules to Reset Both with "
                                       "single-packet capture",
                })
    return out


def check_spyware_dns_category_mismatch(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "spyware"):
        dns_categories = profile.get("settings", {}).get("dns_categories", {})
        for name in DNS_SINKHOLE_CATEGORIES:
            cat = dns_categories.get(name)
            if cat is None:
                continue
            if cat["action"] != "sinkhole":
                out.append({
                    "key": f"{profile['name']}:{name}",
                    "message": f"Anti-Spyware profile '{profile['name']}' DNS security category '{name}' "
                               f"is set to '{cat['action']}', not sinkhole",
                    "recommendation": "Set this DNS security category to Sinkhole per Palo Alto's "
                                       "best-practice per-category table",
                })
    return out


# ── Inline Cloud Analysis (Advanced Threat Prevention license only) ───────

ATP_LICENSE_FEATURE = "advanced threat prevention"


def inline_cloud_analysis_gate(data: dict) -> dict:
    """Whether the Inline Cloud Analysis checks apply to this assessment.
    The feature can't be enabled without an Advanced Threat Prevention
    license, so flagging it as off on an unlicensed firewall would be noise.
    status: "applies" | "no_license" | "license_unknown"."""
    lic = data.get("licenses", {})
    if not lic.get("available"):
        return {
            "status": "license_unknown",
            "reason": "License status isn't in a config export, so these checks run anyway and say they apply "
                      "if the firewall has an Advanced Threat Prevention license. A tech support file confirms it.",
        }
    # A renewed license can sit next to its expired predecessor — any active one counts.
    matches = [e for e in lic.get("licenses", []) if e.get("feature", "").strip().lower() == ATP_LICENSE_FEATURE]
    active = [e for e in matches if e.get("expired", "no").lower() != "yes"]
    if active:
        return {"status": "applies",
                "reason": f"Active Advanced Threat Prevention license (expires {active[0].get('expires', 'N/A')})."}
    if matches:
        return {"status": "no_license",
                "reason": f"The Advanced Threat Prevention license expired ({matches[0].get('expires', 'N/A')})."}
    return {"status": "no_license",
            "reason": "No Advanced Threat Prevention license on this firewall — the feature isn't available."}


def _license_note(status: str, label: str) -> str:
    """Suffix for a finding whose feature needs a license the assessment can't confirm (a config export
    carries no license data). Palo Alto SCM flags these regardless; so do the core rules, saying so."""
    return "" if status in ("yes", "applies") else f" (if the firewall has an {label} license)"


def _inline_cloud_disabled(ptype: str, label: str):
    def check(data: dict, thresholds: dict) -> list[dict]:
        gate = inline_cloud_analysis_gate(data)["status"]
        if gate == "no_license":
            return []
        note = _license_note(gate, "Advanced Threat Prevention")
        out = []
        for profile in _profiles_of(data, ptype):
            ica = profile["settings"].get("inline_cloud_analysis")
            if ica is None or ica["enabled"]:
                continue
            out.append({
                "key": profile["name"],
                "message": f"{label} profile '{profile['name']}' has Inline Cloud Analysis disabled{note}",
                "recommendation": "Enable Inline Cloud Analysis in this profile and set every analysis model's "
                                  "action to Reset Both",
            })
        return out
    return check


def _inline_cloud_model_not_reset(ptype: str, label: str):
    def check(data: dict, thresholds: dict) -> list[dict]:
        if inline_cloud_analysis_gate(data)["status"] == "no_license":
            return []
        out = []
        for profile in _profiles_of(data, ptype):
            ica = profile["settings"].get("inline_cloud_analysis")
            # A disabled profile is already reported; its model actions are moot.
            if ica is None or not ica["enabled"]:
                continue
            for model, action in ica["models"].items():
                if action != "reset-both":
                    out.append({
                        "key": f"{profile['name']}:{model}",
                        "message": f"{label} profile '{profile['name']}' Inline Cloud Analysis model "
                                   f"'{model}' action is '{action}', not reset-both",
                        "recommendation": "Set this analysis model's action to Reset Both",
                    })
        return out
    return check


check_spyware_inline_cloud_analysis_disabled = _inline_cloud_disabled("spyware", "Anti-Spyware")
check_vulnerability_inline_cloud_analysis_disabled = _inline_cloud_disabled("vulnerability", "Vulnerability Protection")
check_spyware_inline_cloud_model_not_reset = _inline_cloud_model_not_reset("spyware", "Anti-Spyware")
check_vulnerability_inline_cloud_model_not_reset = _inline_cloud_model_not_reset("vulnerability", "Vulnerability Protection")


def check_url_mandatory_category_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "url_filtering"):
        block_categories = set(profile.get("settings", {}).get("block_categories", []))
        for name in URL_MANDATORY_BLOCK_CATEGORIES:
            if name not in block_categories:
                out.append({
                    "key": f"{profile['name']}:{name}",
                    "message": f"URL Filtering profile '{profile['name']}' doesn't block category '{name}'",
                    "recommendation": "Add this category to the block list — it's one of Palo Alto's "
                                       "always-block categories for the internet gateway",
                })
    return out


def check_url_elevated_risk_category_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "url_filtering"):
        block_categories = set(profile.get("settings", {}).get("block_categories", []))
        for name in URL_ELEVATED_RISK_CATEGORIES:
            if name not in block_categories:
                out.append({
                    "key": f"{profile['name']}:{name}",
                    "message": f"URL Filtering profile '{profile['name']}' doesn't block elevated-risk "
                               f"category '{name}'",
                    "recommendation": "Add this category to the block list — Palo Alto's best practice "
                                       "treats the elevated-risk tier as block, not alert",
                })
    return out


def check_url_credential_enforcement_disabled(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "url_filtering"):
        mode = profile.get("settings", {}).get("credential_enforcement_mode", "disabled")
        if mode == "disabled":
            out.append({
                "key": profile["name"],
                "message": f"URL Filtering profile '{profile['name']}' has credential-submission "
                           "enforcement disabled",
                "recommendation": "Enable credential enforcement, scoped to malicious categories, to "
                                   "detect corporate credential reuse on phishing sites",
            })
    return out


def check_file_blocking_nothing_blocked(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "file_blocking"):
        rules = profile.get("settings", {}).get("rules", [])
        if rules and not any(r["action"] == "block" for r in rules):
            out.append({
                "key": profile["name"],
                "message": f"File Blocking profile '{profile['name']}' has no rule set to block — every "
                           "rule only alerts or continues",
                "recommendation": "Set at least the high-risk file types (executables, encrypted "
                                   "archives, script files) to Block",
            })
    return out


def check_wildfire_missing_recommended_filetype(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in _profiles_of(data, "wildfire_analysis"):
        rules = profile.get("settings", {}).get("rules", [])
        for file_type in WILDFIRE_RECOMMENDED_FILETYPES:
            if not any(file_type in r.get("file_types", []) for r in rules):
                out.append({
                    "key": f"{profile['name']}:{file_type}",
                    "message": f"WildFire profile '{profile['name']}' doesn't submit '{file_type}' files "
                               "for analysis",
                    "recommendation": "Confirm this is a deliberate exclusion (e.g. avoiding sensitive "
                                       "documents in a public cloud sandbox) rather than an oversight — "
                                       "PDF and Office documents are common malware delivery formats",
                })
    return out


# ── Decryption ────────────────────────────────────────────────────────────

DECRYPT_ACTIONS = {"decrypt", "decrypt-and-forward"}
WEAK_TLS_VERSIONS = {"tls1-0", "tls1-1"}
TLS_LABEL = {"tls1-0": "TLSv1.0", "tls1-1": "TLSv1.1", "tls1-2": "TLSv1.2", "tls1-3": "TLSv1.3"}


def _active_decrypt_rules(decryption: dict) -> list[dict]:
    return [
        r for r in decryption.get("rules", [])
        if r["action"] in DECRYPT_ACTIONS and r["disabled"] != "yes"
    ]


def _profiles_used_by(decryption: dict, rules: list[dict]) -> list[tuple[dict, list[str]]]:
    used: dict[str, list[str]] = {}
    for r in rules:
        if r.get("profile"):
            used.setdefault(r["profile"], []).append(r["name"])
    return [(p, used[p["name"]]) for p in decryption.get("profiles", []) if p["name"] in used]


def check_decryption_no_outbound(data: dict, thresholds: dict) -> list[dict]:
    decryption = data.get("decryption")
    if decryption is None:
        return []
    active = _active_decrypt_rules(decryption)
    if any(r["type"] == "ssl-forward-proxy" for r in active):
        return []
    inbound = [r for r in active if r["type"] == "ssl-inbound-inspection"]
    disabled_forward = [
        r for r in decryption.get("rules", [])
        if r["type"] == "ssl-forward-proxy" and r["action"] in DECRYPT_ACTIONS and r["disabled"] == "yes"
    ]
    if disabled_forward:
        message = (f"Outbound traffic isn't decrypted — {len(disabled_forward)} SSL Forward Proxy decrypt "
                   f"rule(s) exist but are disabled")
    elif inbound:
        message = (f"Outbound traffic isn't decrypted — decryption only covers inbound traffic to your own "
                   f"servers ({len(inbound)} inbound-inspection rule(s)); users' outbound TLS goes uninspected")
    else:
        message = "Outbound traffic isn't decrypted — no decryption policy at all"
    return [{
        "key": "global",
        "message": message,
        "recommendation": "Deploy SSL Forward Proxy decryption for outbound traffic, excluding sensitive "
                          "categories (financial, health) as local regulations require, so security "
                          "profiles can inspect encrypted sessions",
    }]


def _best_practice_decryption_profile(p: dict | None) -> bool:
    """Strong minimum TLS version, and expired or untrusted server certificates blocked."""
    return p is not None and p["min_version"] in ("tls1-2", "tls1-3") \
        and p.get("forward_proxy_block_expired") is True and p.get("forward_proxy_block_untrusted") is True


def check_decryption_no_best_practice_profile(data: dict, thresholds: dict) -> list[dict]:
    decryption = data.get("decryption")
    if decryption is None:
        return []
    forward = [r for r in _active_decrypt_rules(decryption) if r["type"] == "ssl-forward-proxy"]
    if not forward:
        return []  # decryption_no_outbound covers this
    profiles = {p["name"]: p for p in decryption.get("profiles", [])}
    if any(_best_practice_decryption_profile(profiles.get(r.get("profile") or "")) for r in forward):
        return []
    used = sorted({r["profile"] for r in forward if r.get("profile")})
    return [{
        "key": "global",
        "message": f"None of the {len(forward)} outbound (SSL Forward Proxy) decrypt rule(s) uses a best-practice "
                   f"decryption profile" + (f" — profiles used: {', '.join(used)}" if used else " — none has a profile"),
        "recommendation": "Attach a decryption profile to the outbound decrypt rules that sets the minimum version to "
                          "TLSv1.2 and blocks sessions with expired certificates and untrusted issuers",
    }]


def check_decryption_profile_weak_tls(data: dict, thresholds: dict) -> list[dict]:
    decryption = data.get("decryption")
    if decryption is None:
        return []
    out = []
    for profile, rule_names in _profiles_used_by(decryption, _active_decrypt_rules(decryption)):
        if profile["min_version"] not in WEAK_TLS_VERSIONS:
            continue
        version = TLS_LABEL[profile["min_version"]]
        setting = version if profile["min_version_explicit"] else f"not set, which PAN-OS treats as {version}"
        out.append({
            "key": profile["name"],
            "message": f"Decryption profile '{profile['name']}' (used by {', '.join(rule_names)}) allows "
                       f"TLS below 1.2 — minimum version is {setting}",
            "recommendation": "Set the minimum protocol version to TLSv1.2 and the maximum to Max",
        })
    return out


def check_decryption_profile_cert_checks_disabled(data: dict, thresholds: dict) -> list[dict]:
    decryption = data.get("decryption")
    if decryption is None:
        return []
    forward_proxy_rules = [r for r in _active_decrypt_rules(decryption) if r["type"] == "ssl-forward-proxy"]
    out = []
    for profile, rule_names in _profiles_used_by(decryption, forward_proxy_rules):
        for field, label in [
            ("forward_proxy_block_expired", "expired certificates"),
            ("forward_proxy_block_untrusted", "untrusted issuers"),
        ]:
            if profile.get(field) is False:
                out.append({
                    "key": f"{profile['name']}:{field}",
                    "message": f"Decryption profile '{profile['name']}' (used by {', '.join(rule_names)}) "
                               f"doesn't block sessions with {label}",
                    "recommendation": f"Enable 'Block sessions with {label}' under SSL Forward Proxy "
                                      "server certificate verification",
                })
    return out


def check_decryption_no_decrypt_cert_checks(data: dict, thresholds: dict) -> list[dict]:
    decryption = data.get("decryption")
    if decryption is None:
        return []
    no_decrypt = [
        r for r in decryption.get("rules", [])
        if r["action"] == "no-decrypt" and r["disabled"] != "yes"
    ]
    out = []
    for r in no_decrypt:
        if not r.get("profile"):
            out.append({
                "key": f"rule:{r['name']}",
                "message": f"No-decrypt rule '{r['name']}' has no decryption profile, so sessions with expired "
                           "or untrusted server certificates aren't blocked",
                "recommendation": "Attach a No Decryption profile that blocks sessions with expired "
                                  "certificates and untrusted issuers",
            })
    for profile, rule_names in _profiles_used_by(decryption, no_decrypt):
        for field, label in [
            ("no_proxy_block_expired", "expired certificates"),
            ("no_proxy_block_untrusted", "untrusted issuers"),
        ]:
            if profile.get(field) is False:
                out.append({
                    "key": f"{profile['name']}:{field}",
                    "message": f"Decryption profile '{profile['name']}' (used by no-decrypt rule(s) "
                               f"{', '.join(rule_names)}) doesn't block sessions with {label}",
                    "recommendation": f"Enable 'Block sessions with {label}' in the profile's No Decryption "
                                      "settings",
                })
    return out


# ── Logging ───────────────────────────────────────────────────────────────

# ── Management plane ──────────────────────────────────────────────────────

def _mp(data: dict) -> dict | None:
    return data.get("mgmt_plane")


def check_admin_lockout_weak(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    if mp is None:
        return []
    attempts = mp["failed_attempts"] or 0
    lockout = mp["lockout_minutes"] or 0
    out = []
    if attempts == 0:
        out.append({"key": "failed_attempts", "message": "Failed Attempts is 0 — administrator accounts never lock out",
                    "recommendation": f"Set Failed Attempts to {thresholds['max_failed_attempts']} or fewer and a "
                                      f"Lockout Time of at least {thresholds['min_lockout_minutes']} minutes"})
    elif attempts > thresholds["max_failed_attempts"]:
        out.append({"key": "failed_attempts", "message": f"Failed Attempts allows {attempts} tries before lockout",
                    "recommendation": f"Lower Failed Attempts to {thresholds['max_failed_attempts']} or fewer"})
    if attempts and 0 < lockout < thresholds["min_lockout_minutes"]:
        out.append({"key": "lockout_time", "message": f"Lockout Time is only {lockout} minute(s)",
                    "recommendation": f"Set Lockout Time to at least {thresholds['min_lockout_minutes']} minutes "
                                      "(0 keeps the account locked until an administrator unlocks it)"})
    return out


def check_admin_idle_timeout_long(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    if mp is None:
        return []
    limit = thresholds["max_idle_timeout_minutes"]
    timeout = mp["idle_timeout_min"]
    shown = 60 if timeout is None else timeout  # PAN-OS default
    if shown == 0 or shown > limit:
        text = "never" if shown == 0 else f"after {shown} minutes" + (" (PAN-OS default)" if timeout is None else "")
        return [{"key": "global", "message": f"Idle administrator sessions time out {text}",
                 "recommendation": f"Set Device > Setup > Management > Idle Timeout to {limit} minutes or less"}]
    return []


def check_api_key_no_lifetime(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    if mp is None or mp["api_key_lifetime_min"]:
        return []
    return [{"key": "global", "message": "API Key Lifetime isn't set — API keys never expire",
             "recommendation": "Set an API Key Lifetime that matches your key-rotation policy, and rotate keys used "
                               "by scripts and integrations before it expires"}]


def check_password_complexity_weak(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    if mp is None:
        return []
    pc = mp["password_complexity"]
    if not pc["enabled"]:
        return [{"key": "global", "message": "Minimum Password Complexity isn't enabled for local administrators",
                 "recommendation": f"Enable Minimum Password Complexity with a minimum length of at least "
                                   f"{thresholds['min_length']} and character-class requirements"}]
    length = pc["minimum_length"] or 8
    if length < thresholds["min_length"]:
        return [{"key": "global", "message": f"Minimum password length is {length}",
                 "recommendation": f"Raise the minimum length to at least {thresholds['min_length']}"}]
    return []


def check_mgmt_tls_below_1_2(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    t = mp.get("mgmt_tls") if mp else None
    if not t or not t.get("found") or TLS_RANK.get(t["min_version"], 9) >= TLS_RANK["tls1-2"]:
        return []
    return [{"key": "global",
             "message": f"Management SSL/TLS service profile '{t['profile']}' allows "
                        f"{GP_TLS_LABEL.get(t['min_version'], t['min_version'])} and above",
             "recommendation": f"Set the minimum version on '{t['profile']}' to TLSv1.2 and the maximum to Max"}]


def check_snmp_v2c(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    if mp is None:
        return []
    out = []
    polling = mp.get("snmp_polling")
    if polling and polling["version"] == "v2c":
        out.append({"key": "polling",
                    "message": "SNMP polling uses v2c" + (" with the default community 'public'"
                                                          if polling["default_community"] else ""),
                    "recommendation": "Switch SNMP polling to SNMPv3 with per-user authentication and privacy"})
    for t in mp.get("snmptrap") or []:
        if t["version"] == "v2c":
            out.append({"key": f"trap:{t['name']}",
                        "message": f"SNMP trap profile '{t['name']}' uses v2c" + (
                            " with the default community 'public'" if t["default_community"] else ""),
                        "recommendation": f"Change '{t['name']}' to SNMPv3"})
    return out


def check_ldap_profile_no_tls(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    out = []
    for p in (mp or {}).get("ldap") or []:
        if p["ssl"] == "no":
            out.append({"key": p["name"], "message": f"LDAP server profile '{p['name']}' doesn't require SSL/TLS",
                        "recommendation": f"Enable Require SSL/TLS secured connection and Verify Server Certificate "
                                          f"on '{p['name']}' (LDAPS, port 636)"})
        elif not p["verify_certificate"]:
            out.append({"key": p["name"],
                        "message": f"LDAP server profile '{p['name']}' doesn't verify the server's certificate",
                        "recommendation": f"Enable Verify Server Certificate for SSL sessions on '{p['name']}'"})
    return out


def check_radius_weak_protocol(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    return [{"key": p["name"], "message": f"RADIUS server profile '{p['name']}' authenticates with {p['protocol']}",
             "recommendation": f"Use EAP-TTLS with PAP, PEAP-MSCHAPv2 or PEAP with GTC on '{p['name']}'"}
            for p in (mp or {}).get("radius") or [] if p["protocol"] in ("PAP", "CHAP")]


def check_tacacs_pap(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    return [{"key": p["name"], "message": f"TACACS+ server profile '{p['name']}' authenticates with PAP",
             "recommendation": f"Set the authentication protocol on '{p['name']}' to CHAP"}
            for p in (mp or {}).get("tacplus") or [] if p["protocol"] == "PAP"]


def check_syslog_not_tls(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    out = []
    for p in (mp or {}).get("syslog") or []:
        plain = [s for s in p["servers"] if (s["transport"] or "UDP").upper() != "SSL"]
        if plain:
            servers = ", ".join(f"{s['server'] or s['name']} ({s['transport']})" for s in plain)
            out.append({"key": p["name"], "message": f"Syslog profile '{p['name']}' sends to {servers} without TLS",
                        "recommendation": f"Set the transport on '{p['name']}' to SSL (TLS syslog, usually port 6514)"})
    return out


def _logs_not_forwarded(kind: str, label: str):
    def check(data: dict, thresholds: dict) -> list[dict]:
        mp = _mp(data)
        if mp is None:
            return []
        lists = mp["log_forwarding"][kind]
        if any(m["destinations"] for m in lists):
            return []
        detail = (f" — match list {', '.join(repr(m['name']) for m in lists)} has no destination"
                  if lists else "")
        return [{"key": "global", "message": f"{label} logs aren't forwarded to any external destination{detail}",
                 "recommendation": f"Add a {label} log setting (Device > Log Settings) that forwards all severities "
                                   "to syslog, Panorama or your SIEM"}]
    return check


check_system_logs_not_forwarded = _logs_not_forwarded("system", "System")
check_config_logs_not_forwarded = _logs_not_forwarded("config", "Configuration")

# Recurrence tags from most to least frequent; a type must be at least as frequent as its floor.
UPDATE_FREQUENCY = ["real-time", "every-min", "every-5-mins", "every-15-mins", "every-30-mins", "every-hour",
                    "hourly", "daily", "weekly", "none"]
UPDATE_POLICY = {
    "anti-virus": ("Antivirus", "hourly", "hourly"),
    "threats": ("Applications and Threats", "daily", "daily or more often"),
    "wildfire": ("WildFire", "every-min", "in real time (or every minute)"),
}


def check_content_updates_not_timely(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    if mp is None:
        return []
    out = []
    for utype, (label, floor, wanted) in UPDATE_POLICY.items():
        sched = mp["update_schedule"].get(utype)
        if sched is None:
            out.append({"key": utype, "message": f"{label} updates have no schedule",
                        "recommendation": f"Schedule {label} updates to download-and-install {wanted}"})
            continue
        freq, action = sched["frequency"], sched["action"]
        rank = UPDATE_FREQUENCY.index(freq) if freq in UPDATE_FREQUENCY else len(UPDATE_FREQUENCY)
        problems = []
        if rank > UPDATE_FREQUENCY.index(floor):
            problems.append(f"run {freq.replace('-', ' ')}")
        if freq != "real-time" and action and action != "download-and-install":
            problems.append(f"are set to {action.replace('-', ' ')}")
        if problems:
            out.append({"key": utype, "message": f"{label} updates {' and '.join(problems)}",
                        "recommendation": f"Set {label} updates to download-and-install {wanted}"})
    return out


# ── Threat-intelligence blocking ─────────────────────────────────────────

_DIRECTION_TEXT = {
    "inbound": ("as the Source", "inbound traffic from these hosts isn't blocked"),
    "outbound": ("as the Destination", "outbound traffic to these hosts isn't blocked"),
}


def _edl_not_blocked(list_id: str):
    def check(data: dict, thresholds: dict) -> list[dict]:
        if not data.get("security_rules"):
            return []
        entry = next(e for e in threat_intel.coverage(data)["lists"] if e["id"] == list_id)
        out = []
        for direction in threat_intel.DIRECTIONS:
            if entry[direction]:
                continue
            where, effect = _DIRECTION_TEXT[direction]
            note = (f" (rule {', '.join(repr(r) for r in entry['disabled_rules'])} uses it but is disabled)"
                    if entry["disabled_rules"] else "")
            out.append({
                "key": direction,
                "message": f"No enabled deny rule uses '{entry['label']}' ({list_id}) {where} — {effect}{note}",
                "recommendation": f"Add a deny rule with {list_id} {where.lower()} address, log at session end, "
                                  "and place it above the rules that allow traffic",
            })
        return out
    return check


check_edl_known_malicious_not_blocked = _edl_not_blocked("panw-known-ip-list")
check_edl_high_risk_not_blocked = _edl_not_blocked("panw-highrisk-ip-list")
check_edl_bulletproof_not_blocked = _edl_not_blocked("panw-bulletproof-ip-list")
check_edl_tor_exit_not_blocked = _edl_not_blocked("panw-torexit-ip-list")


def check_quic_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    if not data.get("security_rules"):
        return []
    quic = threat_intel.coverage(data)["quic"]
    if quic["rules"]:
        return []
    context = ("SSL decryption is in use, so QUIC sessions bypass it"
               if quic["decryption_in_use"] else "browsers can use QUIC, which the firewall can't decrypt")
    note = f" (rule {', '.join(repr(r) for r in quic['disabled_rules'])} blocks it but is disabled)" if quic["disabled_rules"] else ""
    return [{
        "key": "global",
        "message": f"No enabled deny rule blocks the QUIC application — {context}{note}",
        "recommendation": "Add a deny rule for the quic application (and one for UDP 80/443) above the rules that "
                          "allow web browsing, so browsers fall back to TLS",
    }]


# ── GlobalProtect ─────────────────────────────────────────────────────────

GP_TLS_LABEL = {"sslv3": "SSLv3", "tls1-0": "TLSv1.0", "tls1-1": "TLSv1.1", "tls1-2": "TLSv1.2",
                "tls1-3": "TLSv1.3", "max": "Max"}
TLS_RANK = {"sslv3": 0, "tls1-0": 1, "tls1-1": 2, "tls1-2": 3, "tls1-3": 4, "max": 9}
ALWAYS_ON = {"user-logon", "pre-logon"}
PASSWORD_METHODS = {"local-database", "ldap", "kerberos", "radius", "tacplus"}


def _gp(data: dict) -> dict:
    return data.get("globalprotect") or {"portals": [], "gateways": []}


def _gp_endpoints(data: dict) -> list[tuple[str, dict]]:
    """Every portal and gateway as ("portal"|"gateway", object)."""
    gp = _gp(data)
    return [("portal", p) for p in gp["portals"]] + [("gateway", g) for g in gp["gateways"]]


def _where(kind: str, obj: dict) -> str:
    return f"{kind.capitalize()} '{obj['name']}'"


def _scm_obj(kind: str, name: str) -> dict:
    """The portal/gateway in SCM's object vocabulary (global_protect_portal / _gateway)."""
    return {"type": f"global_protect_{kind}", "name": name}


def check_gp_tls_below_1_2(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for kind, obj in _gp_endpoints(data):
        tls = obj.get("tls")
        if not tls or not tls.get("found"):
            continue
        if TLS_RANK.get(tls["min_version"], 9) < TLS_RANK["tls1-2"]:
            out.append({
                "key": f"{kind}:{obj['name']}",
                "scm_object": _scm_obj(kind, obj["name"]),
                "message": f"{_where(kind, obj)} — SSL/TLS service profile '{tls['name']}' allows "
                           f"{GP_TLS_LABEL.get(tls['min_version'], tls['min_version'])} and above",
                "recommendation": f"Set the minimum version on '{tls['name']}' to TLSv1.2 and the maximum to Max",
            })
    return out


def check_gp_tls_weak_ciphers(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for kind, obj in _gp_endpoints(data):
        tls = obj.get("tls")
        if tls and tls.get("found") and tls["weak_algorithms"]:
            out.append({
                "key": f"{kind}:{obj['name']}",
                "scm_object": _scm_obj(kind, obj["name"]),
                "message": f"{_where(kind, obj)} — SSL/TLS service profile '{tls['name']}' allows "
                           f"{', '.join(tls['weak_algorithms'])}",
                "recommendation": f"Disable {', '.join(tls['weak_algorithms'])} in '{tls['name']}' protocol settings",
            })
    return out


def _second_factor(profile: dict | None) -> bool:
    if not profile or not profile.get("found"):
        return True  # unresolved reference: don't guess
    if profile.get("sequence"):
        return all(_second_factor(m) for m in profile.get("members") or []) and bool(profile.get("members"))
    return bool(profile.get("mfa") or profile.get("external_mfa_capable"))


def check_gp_single_factor_auth(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for kind, obj in _gp_endpoints(data):
        if obj.get("certificate_profile") or not obj.get("auth_profiles"):
            continue
        weak = [a for a in obj["auth_profiles"] if not _second_factor(a["profile"])]
        if weak:
            names = ", ".join(f"'{a['profile']['name']}' ({a['profile']['method']})" for a in weak)
            out.append({
                "key": f"{kind}:{obj['name']}",
                "scm_object": _scm_obj(kind, obj["name"]),
                "message": f"{_where(kind, obj)} — password-only login via {names}, no certificate profile",
                "recommendation": "Add a second factor: enable MFA on the authentication profile, use SAML or "
                                  "RADIUS backed by an MFA service, or require a client certificate "
                                  "(certificate profile) alongside the password",
            })
    return out


def check_gp_auth_no_lockout(data: dict, thresholds: dict) -> list[dict]:
    seen: dict[str, list[str]] = {}
    for kind, obj in _gp_endpoints(data):
        for a in obj.get("auth_profiles") or []:
            prof = a["profile"]
            candidates = (prof.get("members") or []) if prof and prof.get("sequence") else [prof]
            for p in candidates:
                if p and p.get("found") and p["method"] in PASSWORD_METHODS and not p["lockout_attempts"]:
                    seen.setdefault(p["name"], []).append(_where(kind, obj))
    return [{
        "key": name,
        "message": f"Authentication profile '{name}' has no lockout — used by {', '.join(dict.fromkeys(users))}",
        "recommendation": f"Set Failed Attempts and Lockout Time on '{name}' so repeated wrong passwords lock the account",
    } for name, users in seen.items()]


def check_gp_cert_profile_no_revocation(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for kind, obj in _gp_endpoints(data):
        cp = obj.get("certificate_profile")
        if cp and cp.get("found") and not (cp["use_crl"] or cp["use_ocsp"]):
            out.append({
                "key": f"{kind}:{obj['name']}",
                "scm_object": _scm_obj(kind, obj["name"]),
                "message": f"{_where(kind, obj)} — certificate profile '{cp['name']}' checks neither CRL nor OCSP",
                "recommendation": f"Enable OCSP and/or CRL on '{cp['name']}' so revoked client certificates are refused",
            })
    return out


def check_gp_no_trusted_root_ca(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": p["name"],
        "scm_object": _scm_obj("portal", p["name"]),
        "message": f"Portal '{p['name']}' has no Trusted Root CA in its agent settings",
        "recommendation": "Add the root and intermediate CA certificates that issued the portal and gateway "
                          "certificates to the portal's Agent > Trusted Root CA list",
    } for p in _gp(data)["portals"] if p["agent_configs"] and not p["root_ca"]]


def _agent_configs(data: dict):
    for p in _gp(data)["portals"]:
        for c in p["agent_configs"]:
            yield p, c


def check_gp_connect_on_demand(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": f"{p['name']}:{c['name']}",
        "scm_object": _scm_obj("portal", p["name"]),
        "message": f"Portal '{p['name']}' agent config '{c['name']}' uses the On-demand connect method",
        "recommendation": "Use User-logon (Always On) or Pre-logon (Always On) so endpoints are protected "
                          "whenever they're off the corporate network",
    } for p, c in _agent_configs(data) if c["connect_method"] == "on-demand"]


def check_gp_not_enforced(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": f"{p['name']}:{c['name']}",
        "scm_object": _scm_obj("portal", p["name"]),
        "message": f"Portal '{p['name']}' agent config '{c['name']}' is always-on but doesn't enforce "
                   "GlobalProtect for network access",
        "recommendation": "Set Enforce GlobalProtect Connection for Network Access to Yes (with a captive-portal "
                          "exception timeout if users need hotel/airport Wi-Fi logins)",
    } for p, c in _agent_configs(data) if c["connect_method"] in ALWAYS_ON and not c["enforce_globalprotect"]]


def check_gp_user_can_disable(data: dict, thresholds: dict) -> list[dict]:
    label = {"allowed": "Allow", "with-comment": "Allow with Comment"}
    return [{
        "key": f"{p['name']}:{c['name']}",
        "scm_object": _scm_obj("portal", p["name"]),
        "message": f"Portal '{p['name']}' agent config '{c['name']}' — users can disable GlobalProtect "
                   f"({label[c['user_override']]}) with no Disable Timeout",
        "recommendation": "Set Allow User to Disable GlobalProtect App to Disallow (or Allow with Ticket/Passcode), "
                          "or at least set a Disable Timeout so the app reconnects on its own",
    } for p, c in _agent_configs(data)
        if c["connect_method"] in ALWAYS_ON and c["user_override"] in label and not c["override_timeout_min"]]


def check_gp_hip_collection_disabled(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": f"{p['name']}:{c['name']}",
        "scm_object": _scm_obj("portal", p["name"]),
        "message": f"Portal '{p['name']}' agent config '{c['name']}' has Collect HIP Data turned off",
        "recommendation": "Enable Collect HIP Data so security rules can match on endpoint posture (HIP profiles)",
    } for p, c in _agent_configs(data) if not c["collect_hip"]]


def check_gp_no_internal_host_detection(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": f"{p['name']}:{c['name']}",
        "scm_object": _scm_obj("portal", p["name"]),
        "message": f"Portal '{p['name']}' agent config '{c['name']}' lists {c['internal_gateways']} internal and "
                   f"{c['external_gateways']} external gateway(s) without internal host detection",
        "recommendation": "Configure Internal Host Detection (an internal IP address and its reverse-DNS hostname)",
    } for p, c in _agent_configs(data)
        if c["internal_gateways"] and c["external_gateways"] and not c["internal_host_detection"]]


FULL_TUNNEL = {"0.0.0.0/0", "::/0"}


def check_gp_split_tunnel(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for g in _gp(data)["gateways"]:
        for c in g["client_configs"]:
            # No access routes at all means the gateway sends everything through the tunnel.
            routes = c["access_routes"]
            if routes and not FULL_TUNNEL.intersection(routes):
                shown = ", ".join(routes[:4]) + (f" +{len(routes) - 4} more" if len(routes) > 4 else "")
                out.append({
                    "key": f"{g['name']}:{c['name']}",
                    "scm_object": _scm_obj("gateway", g["name"]),
                    "message": f"Gateway '{g['name']}' client config '{c['name']}' tunnels only {shown}",
                    "recommendation": "Include 0.0.0.0/0 as an access route so all traffic is inspected, and "
                                      "exclude only specific trusted destinations if you must",
                })
    return out


def check_gp_long_cookie_lifetime(data: dict, thresholds: dict) -> list[dict]:
    limit = thresholds["max_cookie_lifetime_hours"]
    out = []
    items = [("portal", p, c) for p, c in _agent_configs(data)] + \
            [("gateway", g, c) for g in _gp(data)["gateways"] for c in g["client_configs"]]
    for kind, obj, cfg in items:
        hours = cfg.get("cookie_lifetime_hours")
        if hours is not None and hours > limit:
            span = f"{hours / 24:g} days" if hours >= 24 else f"{hours:g} hours"
            out.append({
                "key": f"{kind}:{obj['name']}:{cfg['name']}",
                "scm_object": _scm_obj(kind, obj["name"]),
                "message": f"{_where(kind, obj)} config '{cfg['name']}' accepts authentication cookies for {span}",
                "recommendation": f"Shorten the cookie lifetime to {limit} hours or less, or stop accepting "
                                  "cookies where MFA is required on every login",
            })
    return out


def check_gp_satellite_no_root_ca(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": p["name"],
        "scm_object": _scm_obj("portal", p["name"]),
        "message": f"Portal '{p['name']}' configures satellites but no satellite Trusted Root CA",
        "recommendation": "Add the root and intermediate CAs that issued the gateway certificates to the "
                          "portal's Satellite > Trusted Root CA list",
    } for p in _gp(data)["portals"] if p["satellite"]["configured"] and not p["satellite"]["root_ca"]]


def check_no_syslog_profile(data: dict, thresholds: dict) -> list[dict]:
    if data.get("syslog_profiles", 0) > 0:
        return []
    return [{
        "key": "global",
        "message": "No syslog server profiles configured",
        "recommendation": "Configure syslog forwarding to a SIEM or central log server",
    }]


# ── High Availability (live-mode only) ─────────────────────────────────────

def check_ha_not_synced(data: dict, thresholds: dict) -> list[dict]:
    ha = data.get("ha", {})
    if not ha.get("available") or not ha.get("enabled"):
        return []
    sync = ha.get("sync_status", "unknown")
    if sync.lower() != "synchronized":
        return [{
            "key": "global",
            "message": f"HA sync status is '{sync}' (not synchronized)",
            "recommendation": "Investigate HA sync issue immediately; devices may have diverged configs",
        }]
    return []


# ── High Availability (configuration) ───────────────────────────────────

def _ha_config(data: dict) -> dict:
    ha = data.get("ha_config") or {}
    return ha if ha.get("enabled") else {}


def _ha_finding(message: str, recommendation: str, key: str = "global") -> list[dict]:
    return [{"key": key, "message": message, "recommendation": recommendation}]


def check_ha_config_sync_disabled(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha or ha.get("config_sync", True):
        return []
    return _ha_finding("HA configuration synchronization is disabled",
                       "Enable Config Sync under Device > High Availability > General > Setup")


def check_ha_session_sync_disabled(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha or ha.get("session_sync", True):
        return []
    return _ha_finding("HA session synchronization is disabled; sessions drop on failover",
                       "Enable Session Synchronization on the HA2 data link")


def check_ha2_keepalive_disabled(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha or ha.get("ha2_keep_alive"):
        return []
    return _ha_finding("HA2 keep-alive is disabled",
                       "Enable HA2 Keep-alive (Log Only in active/passive, Split Datapath in active/active)")


def check_ha1_encryption_disabled(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha or ha.get("ha1_encryption"):
        return []
    return _ha_finding("HA1 control link encryption is disabled",
                       "Export and import the HA keys on both peers, then enable Encryption on the HA1 link")


def check_ha1_no_backup(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha or ha.get("peer_ip_backup"):
        return []
    return _ha_finding("No HA1 backup peer address is configured",
                       "Configure an HA1 Backup control link and set the peer's HA1 backup IP address")


def check_ha_heartbeat_backup_off(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    port = (ha.get("ha1_port") or "").lower()
    if not ha or not port or port == "management" or ha.get("heartbeat_backup"):
        return []
    return _ha_finding(f"Heartbeat backup is disabled while HA1 uses {ha['ha1_port']}",
                       "Enable Heartbeat Backup so heartbeats also travel over the management port")


def check_ha_passive_link_state_shutdown(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha or ha.get("mode") != "active-passive" or ha.get("passive_link_state") == "auto":
        return []
    return _ha_finding(f"Passive link state is '{ha.get('passive_link_state')}'",
                       "Set Passive Link State to Auto to shorten failover")


def check_ha_no_monitoring(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha:
        return []
    link, path = ha.get("link_monitoring") or {}, ha.get("path_monitoring") or {}
    links = link.get("enabled", True) and any(g.get("interfaces") for g in link.get("groups", []))
    paths = path.get("enabled", True) and bool(path.get("groups"))
    if links or paths:
        return []
    return _ha_finding("HA monitors no links or paths, so it won't fail over when a data interface goes down",
                       "Add a link monitoring group with the critical data interfaces, and path monitoring "
                       "for upstream next hops")


def check_ha_active_active_incomplete(data: dict, thresholds: dict) -> list[dict]:
    ha = _ha_config(data)
    if not ha or ha.get("mode") != "active-active":
        return []
    out = []
    if not ha.get("ha3_port"):
        out += _ha_finding("Active/active HA has no HA3 packet-forwarding link",
                           "Configure an HA3 interface on both peers", key="ha3")
    if ha.get("session_owner") != "first-packet":
        out += _ha_finding(f"Session owner selection is '{ha.get('session_owner') or 'not set'}'",
                           "Set Session Owner Selection to First Packet", key="session_owner")
    return out


# ── Device Hardening ─────────────────────────────────────────────────────

def check_mgmt_no_acl(data: dict, thresholds: dict) -> list[dict]:
    if data.get("management", {}).get("mgmt_acl"):
        return []
    return [{
        "key": "global",
        "message": "Management interface has no permitted-ip restriction",
        "recommendation": "Add permitted-ip entries to restrict management access to trusted IPs only",
    }]


def check_mgmt_profile_cleartext(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile in data.get("interface_mgmt_profiles", []):
        if not profile.get("interfaces"):
            continue
        services = profile.get("services", {})
        enabled = [s for s in ("telnet", "http") if services.get(s)]
        if enabled:
            protocols = " and ".join(s.upper() if s == "http" else s.capitalize() for s in enabled)
            out.append({
                "key": profile["name"],
                "message": f"Interface management profile '{profile['name']}' enables {protocols} on "
                           f"{', '.join(profile['interfaces'])}",
                "recommendation": "Disable Telnet and HTTP; allow only HTTPS and SSH for management, and "
                                  "restrict the profile's permitted IPs",
            })
    return out


def check_mgmt_interface_open_to_any_source(data: dict, thresholds: dict) -> list[dict]:
    analysis = mgmt_exposure.analyze(data)
    if not analysis:
        return []
    out = []
    for entry in analysis:
        if entry["permitted_ips"]:
            continue  # the profile's own address list already restricts every service
        open_paths: dict[str, list[str]] = {}
        for svc, results in entry["services"].items():
            for r in results:
                if r["status"] == "open":
                    open_paths.setdefault(svc, []).append(
                        f"from {r['source_zone']} via "
                        + (r["via"] if r["via"].endswith("-default") else f"rule '{r['via']}'"))
        if not open_paths:
            continue
        labels = ", ".join(mgmt_exposure.ADMIN_SERVICES[s]["label"] for s in open_paths)
        paths = sorted({p for ps in open_paths.values() for p in ps})
        out.append({
            "key": entry["interface"],
            "message": f"{labels} on {entry['interface']} (zone {entry['zone']}, profile '{entry['profile']}') "
                       f"reachable from any source address — the profile has no permitted-IP list and security "
                       f"policy allows it {'; '.join(paths)}",
            "recommendation": "Restrict it at either layer, ideally both: add a permitted-IP list to the "
                              "management profile, and/or allow only specific admin sources to this interface "
                              "with a security rule followed by a deny",
        })
    return out


def check_no_login_banner(data: dict, thresholds: dict) -> list[dict]:
    if data.get("management", {}).get("login_banner"):
        return []
    return [{
        "key": "global",
        "message": "No login banner configured",
        "recommendation": "Add a legal warning banner to the management login page",
    }]


def check_no_ntp(data: dict, thresholds: dict) -> list[dict]:
    if data.get("management", {}).get("ntp_primary"):
        return []
    return [{
        "key": "global",
        "message": "NTP not configured",
        "recommendation": "Configure NTP servers to ensure accurate log timestamps",
    }]


# ── Site-to-site VPN ─────────────────────────────────────────────────────

WEAK_CIPHERS = {"des", "3des", "null"}
WEAK_HASHES = {"md5", "sha1"}
NO_AUTH = {"non-auth", "none"}


def _vpn_in_use(data: dict):
    """(active auto-key tunnels, gateways they use, IKE profile -> gateway names,
    IPSec profile -> tunnel names). Disabled tunnels/gateways and GlobalProtect satellite
    tunnels are left out; their crypto isn't negotiated."""
    vpn = data.get("vpn") or {}
    gateways = {g["name"]: g for g in vpn.get("gateways", []) if not g.get("disabled")}
    tunnels = [t for t in vpn.get("tunnels", []) if not t.get("disabled") and t.get("type") == "auto-key"]
    ike_users: dict[str, list[str]] = {}
    ipsec_users: dict[str, list[str]] = {}
    used_gateways: list[dict] = []
    for t in tunnels:
        if t.get("ipsec_profile"):
            ipsec_users.setdefault(t["ipsec_profile"], []).append(t["name"])
        for gname in t.get("gateways", []):
            g = gateways.get(gname)
            if g is None or g in used_gateways:
                continue
            used_gateways.append(g)
            for prof in g.get("ike_profiles", []):
                ike_users.setdefault(prof, []).append(gname)
    return tunnels, used_gateways, ike_users, ipsec_users


def _vpn_profiles(data: dict, kind: str) -> dict[str, dict]:
    return {p["name"]: p for p in (data.get("vpn") or {}).get(f"{kind}_profiles", [])}


def _used_by(kind: str, names: list[str]) -> str:
    label = "gateway" if kind == "ike" else "tunnel"
    return f"used by {label}{'s' if len(names) > 1 else ''} {', '.join(names)}"


def _all_gcm(ciphers: list[str]) -> bool:
    return bool(ciphers) and all(c.endswith("-gcm") for c in ciphers)


def check_vpn_weak_encryption(data: dict, thresholds: dict) -> list[dict]:
    tunnels, _, ike_users, ipsec_users = _vpn_in_use(data)
    out = []
    for kind, users in (("ike", ike_users), ("ipsec", ipsec_users)):
        profiles = _vpn_profiles(data, kind)
        for name, used in sorted(users.items()):
            p = profiles.get(name)
            if p is None:
                continue
            weak = [c for c in p.get("encryption", []) if c in WEAK_CIPHERS]
            if kind == "ipsec" and p.get("protocol") == "ah":
                out.append({"key": f"ipsec:{name}",
                            "message": f"IPSec profile '{name}' uses AH, which doesn't encrypt ({_used_by(kind, used)})",
                            "recommendation": "Use ESP with AES-GCM (or AES-CBC with SHA-256 or higher)"})
            elif weak:
                out.append({"key": f"{kind}:{name}",
                            "message": f"{kind.upper() if kind == 'ike' else 'IPSec'} profile '{name}' allows "
                                       f"{', '.join(c.upper() for c in weak)} ({_used_by(kind, used)})",
                            "recommendation": "Remove DES, 3DES and null; use AES-256-GCM or AES-128-GCM where "
                                              "the peer supports it"})
    return out


def check_vpn_weak_authentication(data: dict, thresholds: dict) -> list[dict]:
    _, _, ike_users, ipsec_users = _vpn_in_use(data)
    out = []
    for kind, field, users in (("ike", "hash", ike_users), ("ipsec", "authentication", ipsec_users)):
        profiles = _vpn_profiles(data, kind)
        for name, used in sorted(users.items()):
            p = profiles.get(name)
            if p is None:
                continue
            algs = p.get(field, [])
            weak = [a.upper().replace("SHA1", "SHA-1") for a in algs if a in WEAK_HASHES]
            if any(a in NO_AUTH for a in algs) and not _all_gcm(p.get("encryption", [])):
                weak.append("no authentication")
            if weak:
                out.append({"key": f"{kind}:{name}",
                            "message": f"{'IKE' if kind == 'ike' else 'IPSec'} profile '{name}' allows "
                                       f"{', '.join(weak)} ({_used_by(kind, used)})",
                            "recommendation": "Use SHA-256 or higher (SHA-384 for long-lived tunnels), or AES-GCM "
                                              "with non-auth/none"})
    return out


def _group_num(g: str) -> int:
    return int(g[5:]) if g.startswith("group") and g[5:].isdigit() else 0


def check_vpn_weak_dh_group(data: dict, thresholds: dict) -> list[dict]:
    minimum = thresholds.get("min_group", 14)
    _, _, ike_users, ipsec_users = _vpn_in_use(data)
    out = []
    ike = _vpn_profiles(data, "ike")
    for name, used in sorted(ike_users.items()):
        weak = [g for g in (ike.get(name) or {}).get("dh_groups", []) if _group_num(g) < minimum]
        if weak:
            out.append({"key": f"ike:{name}",
                        "message": f"IKE profile '{name}' allows DH {', '.join(weak)} ({_used_by('ike', used)})",
                        "recommendation": "Use DH group 19 or 20 (group 14 at minimum)"})
    ipsec = _vpn_profiles(data, "ipsec")
    for name, used in sorted(ipsec_users.items()):
        g = (ipsec.get(name) or {}).get("dh_group")
        if g == "no-pfs":
            out.append({"key": f"ipsec:{name}",
                        "message": f"IPSec profile '{name}' has Perfect Forward Secrecy off ({_used_by('ipsec', used)})",
                        "recommendation": "Set the PFS DH group to 19 or 20 (group 14 at minimum) on both peers"})
        elif g and _group_num(g) < minimum:
            out.append({"key": f"ipsec:{name}",
                        "message": f"IPSec profile '{name}' uses PFS DH {g} ({_used_by('ipsec', used)})",
                        "recommendation": "Set the PFS DH group to 19 or 20 (group 14 at minimum) on both peers"})
    return out


def check_ike_aggressive_mode(data: dict, thresholds: dict) -> list[dict]:
    _, gateways, _, _ = _vpn_in_use(data)
    return [{"key": g["name"],
             "message": f"IKE gateway '{g['name']}' uses IKEv1 aggressive mode",
             "recommendation": "Set the exchange mode to main (or move the peer to IKEv2)"}
            for g in gateways if g.get("version") != "ikev2" and g.get("exchange_mode") == "aggressive"]


def check_ike_v1_only(data: dict, thresholds: dict) -> list[dict]:
    _, gateways, _, _ = _vpn_in_use(data)
    return [{"key": g["name"],
             "message": f"IKE gateway '{g['name']}' only negotiates IKEv1",
             "recommendation": "Use IKEv2, or IKEv2 preferred while the peer is migrated"}
            for g in gateways if g.get("version", "ikev1") == "ikev1"]


def check_vpn_manual_key(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": t["name"],
             "message": f"IPSec tunnel '{t['name']}' uses manually configured static keys",
             "recommendation": "Rebuild the tunnel with auto-key (IKE) so keys are negotiated and rotated"}
            for t in (data.get("vpn") or {}).get("tunnels", [])
            if t.get("type") == "manual-key" and not t.get("disabled")]


def check_vpn_lifetime_long(data: dict, thresholds: dict) -> list[dict]:
    _, _, ike_users, ipsec_users = _vpn_in_use(data)
    out = []
    for kind, users, limit in (("ike", ike_users, thresholds.get("ike_max_hours", 24)),
                               ("ipsec", ipsec_users, thresholds.get("ipsec_max_hours", 8))):
        profiles = _vpn_profiles(data, kind)
        for name, used in sorted(users.items()):
            hours = (profiles.get(name) or {}).get("lifetime_hours")
            if hours is not None and hours > limit:
                out.append({"key": f"{kind}:{name}",
                            "message": f"{'IKE' if kind == 'ike' else 'IPSec'} profile '{name}' key lifetime is "
                                       f"{hours:g} hours ({_used_by(kind, used)})",
                            "recommendation": f"Keep the lifetime at or below {limit} hours"})
    return out


def check_vpn_anti_replay_disabled(data: dict, thresholds: dict) -> list[dict]:
    tunnels, _, _, _ = _vpn_in_use(data)
    return [{"key": t["name"],
             "message": f"IPSec tunnel '{t['name']}' has anti-replay turned off",
             "recommendation": "Enable Replay Protection on the tunnel"}
            for t in tunnels if t.get("anti_replay") is False]


def check_vpn_no_tunnel_monitor(data: dict, thresholds: dict) -> list[dict]:
    tunnels, _, _, _ = _vpn_in_use(data)
    return [{"key": t["name"],
             "message": f"IPSec tunnel '{t['name']}' has no tunnel monitor",
             "recommendation": "Enable Tunnel Monitor with a destination IP across the tunnel and a monitor "
                               "profile (wait-recover, or fail-over where there's a backup path)"}
            for t in tunnels if not t.get("monitor")]


def check_vpn_stale_config(data: dict, thresholds: dict) -> list[dict]:
    vpn = data.get("vpn") or {}
    tunnels = vpn.get("tunnels", [])
    referenced = {g for t in tunnels for g in t.get("gateways", [])}
    out = []
    for t in tunnels:
        if t.get("disabled"):
            out.append({"key": f"tunnel:{t['name']}", "message": f"IPSec tunnel '{t['name']}' is disabled",
                        "recommendation": "Delete it if the VPN is no longer needed"})
    for g in vpn.get("gateways", []):
        if g.get("disabled"):
            out.append({"key": f"gateway:{g['name']}", "message": f"IKE gateway '{g['name']}' is disabled",
                        "recommendation": "Delete it if the VPN is no longer needed"})
        elif g["name"] not in referenced:
            out.append({"key": f"gateway:{g['name']}",
                        "message": f"IKE gateway '{g['name']}' isn't used by any IPSec tunnel",
                        "recommendation": "Delete it along with its stored pre-shared key"})
    return out


# ── DoS & session protection ────────────────────────────────────────────

FLOOD_LABEL = {"tcp-syn": "SYN", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6", "other-ip": "Other IP"}
PACKET_BASED_LABEL = {
    "discard-ip-spoof": "spoofed IP", "discard-strict-source-routing": "strict source routing",
    "discard-loose-source-routing": "loose source routing", "discard-malformed-option": "malformed IP options",
    "discard-unknown-option": "unknown IP options",
    "discard-overlapping-tcp-segment-mismatch": "mismatched overlapping TCP segments",
    "discard-tcp-split-handshake": "TCP split handshake", "remove-tcp-timestamp": "strip TCP timestamp",
}


def _dos(data: dict) -> dict | None:
    return data.get("dos")


def check_dos_no_protection(data: dict, thresholds: dict) -> list[dict]:
    dos = _dos(data)
    if dos is None or any(r["action"] == "protect" and not r["disabled"]
                          and (r["aggregate_profile"] or r["classified_profile"]) for r in dos["rules"]):
        return []
    return [{"key": "global",
             "message": "No enabled DoS Protection rule applies a DoS Protection profile",
             "recommendation": "Add classified DoS Protection rules (action Protect) for critical internet-facing "
                               "servers, with thresholds based on their measured connection rates"}]


def check_dos_rule_not_protect(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for r in (_dos(data) or {}).get("rules", []):
        if r["disabled"]:
            continue
        if r["action"] != "protect":
            problem = f"action is {r['action'].capitalize()}"
        elif not (r["aggregate_profile"] or r["classified_profile"]):
            problem = "has no DoS Protection profile attached"
        else:
            continue
        out.append({"key": r["name"], "message": f"DoS Protection rule '{r['name']}' {problem}",
                    "recommendation": "Set the action to Protect and attach a classified or aggregate profile",
                    "scm_object": {"type": "dos_protection_rule", "name": r["name"]}})
    return out


def check_dos_profile_flood_incomplete(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for p in (_dos(data) or {}).get("profiles", []):
        off = [FLOOD_LABEL[t] for t, on in p["flood"].items() if not on]
        if off:
            out.append({"key": p["name"],
                        "message": f"DoS Protection profile '{p['name']}' has no {', '.join(off)} flood protection",
                        "recommendation": "Enable flood protection for SYN, UDP, ICMP, ICMPv6 and Other IP",
                        "scm_object": {"type": "dos_protection_profile", "name": p["name"]}})
    return out


def check_dos_profile_default_thresholds(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for p in (_dos(data) or {}).get("profiles", []):
        rates = [r for r in p.get("rates", {}).values() if r]
        if rates and all(r["default"] for r in rates):
            out.append({"key": p["name"],
                        "message": f"DoS Protection profile '{p['name']}' still uses the pre-filled flood rates",
                        "recommendation": "Measure the protected servers' normal and peak connections per second "
                                          "over a business week and set the activate rate just above the peak",
                        "scm_object": {"type": "dos_protection_profile", "name": p["name"]}})
    return out


def check_zone_protection_packet_based_off(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile, zones in _assigned_zone_protection_profiles(data):
        options = profile.get("packet_based")
        if options is None:
            continue
        off = [PACKET_BASED_LABEL[o] for o, on in options.items() if not on]
        if off:
            out.append({"key": profile["name"],
                        "message": f"Zone Protection Profile '{profile['name']}' ({_zones_text(zones)}) "
                                   f"doesn't drop {', '.join(off)}",
                        "recommendation": "Under Packet Based Attack Protection, enable the IP Drop and TCP Drop "
                                          "options Palo Alto's best practices list",
                        "scm_object": {"type": "zone_protection_profile", "name": profile["name"]}})
    return out


def check_zone_packet_buffer_protection_off(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": z["name"], "message": f"Packet Buffer Protection is turned off on zone '{z['name']}'",
             "recommendation": "Re-enable Packet Buffer Protection on the zone"}
            for z in data.get("zones", []) if z.get("packet_buffer_protection") is False]


def check_session_rematch_disabled(data: dict, thresholds: dict) -> list[dict]:
    session = data.get("session_settings")
    if session is None or session.get("rematch", True):
        return []
    return [{"key": "global", "message": "Rematch Sessions is turned off",
             "recommendation": "Enable Rematch Sessions under Device > Setup > Session"}]


def check_tcp_forward_oo_queue(data: dict, thresholds: dict) -> list[dict]:
    session = data.get("session_settings")
    if not (session or {}).get("tcp_forward_oo_queue"):
        return []
    return [{"key": "global", "message": "The firewall forwards TCP segments that exceed the out-of-order queue",
             "recommendation": "Clear 'Forward segments exceeding TCP out-of-order queue' under Device > Setup > "
                               "Session > TCP Settings"}]


# ── Device & session settings (ported from Palo Alto SCM checks) ───────

TIMEOUT_LABEL = {
    "timeout-default": "Default", "timeout-discard-default": "Discard Default", "timeout-discard-tcp": "Discard TCP",
    "timeout-discard-udp": "Discard UDP", "timeout-icmp": "ICMP", "timeout-scan": "Scan", "timeout-tcp": "TCP",
    "timeout-tcphandshake": "TCP Handshake", "timeout-tcpinit": "TCP Init", "timeout-tcp-half-closed": "TCP Half Closed",
    "timeout-tcp-time-wait": "TCP Time Wait", "timeout-tcp-unverified-rst": "Unverified RST", "timeout-udp": "UDP",
}


def _one(condition: bool, message: str, recommendation: str) -> list[dict]:
    return [{"key": "global", "message": message, "recommendation": recommendation}] if condition else []


def check_session_timeout_changed(data: dict, thresholds: dict) -> list[dict]:
    from ..parser import SESSION_TIMEOUT_DEFAULTS
    out = []
    for tag, value in (data.get("session_settings") or {}).get("timeouts", {}).items():
        default = SESSION_TIMEOUT_DEFAULTS.get(tag)
        if default is not None and value != default:
            out.append({"key": tag,
                        "message": f"{TIMEOUT_LABEL.get(tag, tag)} session timeout is {value}s (default {default}s)",
                        "recommendation": f"Set it back to {default}s unless an application needs otherwise"})
    return out


def check_session_accelerated_aging_off(data: dict, thresholds: dict) -> list[dict]:
    s = data.get("session_settings") or {}
    return _one(s.get("accelerated_aging") is False, "Accelerated aging is turned off",
                "Enable Accelerated Aging under Device > Setup > Session")


def check_packet_buffer_protection_global_off(data: dict, thresholds: dict) -> list[dict]:
    s = data.get("session_settings") or {}
    return _one(s.get("packet_buffer_protection") is False, "Global Packet Buffer Protection is turned off",
                "Enable Packet Buffer Protection under Device > Setup > Session")


def check_cert_expiration_check_off(data: dict, thresholds: dict) -> list[dict]:
    d = data.get("device_settings")
    return _one(d is not None and not d.get("cert_expiration_check"), "Certificate expiration checking is off",
                "Enable Certificate Expiration Check under Device > Setup > Management > General Settings")


def check_log_high_dp_load_off(data: dict, thresholds: dict) -> list[dict]:
    d = data.get("device_settings")
    return _one(d is not None and not d.get("log_high_dp_load"),
                "No System log is written when the dataplane reaches 100% load",
                "Enable Log on High DP Load under Device > Setup > Management > Logging and Reporting Settings")


def check_telemetry_disabled(data: dict, thresholds: dict) -> list[dict]:
    off = (data.get("device_settings") or {}).get("telemetry_off") or []
    return _one(bool(off), f"Telemetry sharing is off for {', '.join(off)}",
                "Enable telemetry under Device > Setup > Telemetry if your data-sharing policy allows")


def check_update_server_verification_off(data: dict, thresholds: dict) -> list[dict]:
    d = data.get("device_settings")
    return _one(d is not None and d.get("server_verification") is False,
                "Verify Update Server Identity is turned off",
                "Enable Verify Update Server Identity under Device > Setup > Services")


def check_mgmt_interface_cleartext(data: dict, thresholds: dict) -> list[dict]:
    d = data.get("device_settings") or {}
    on = [p for p, key in (("HTTP", "mgmt_http"), ("Telnet", "mgmt_telnet")) if d.get(key)]
    return _one(bool(on), f"The management interface allows {' and '.join(on)}",
                "Disable HTTP and Telnet on the management interface; use HTTPS and SSH")


def check_ha_timers_not_recommended(data: dict, thresholds: dict) -> list[dict]:
    ha = data.get("ha_config") or {}
    timers = ha.get("timers")
    return _one(bool(ha.get("enabled")) and timers not in (None, "recommended"),
                f"HA timers are set to {str(timers).capitalize()}",
                "Use the Recommended HA timer profile unless faster failover was a deliberate choice")


def check_gre_keepalive_off(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": t["name"], "message": f"GRE tunnel '{t['name']}' has keep-alive off",
             "recommendation": "Enable Keep Alive on the GRE tunnel",
             "scm_object": {"type": "gre_tunnel", "name": t["name"]}}
            for t in (data.get("misc_policy") or {}).get("gre_tunnels", [])
            if not t["disabled"] and not t["keep_alive"]]


def check_pbf_no_monitor(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": r["name"], "message": f"Policy-based forwarding rule '{r['name']}' doesn't monitor its next hop",
             "recommendation": "Add a monitor profile (fail-over) and a monitored IP on the forwarding rule",
             "scm_object": {"type": "policy_based_forwarding_rule", "name": r["name"]}}
            for r in (data.get("misc_policy") or {}).get("pbf_rules", [])
            if not r["disabled"] and r["action"] == "forward" and not r["monitor_profile"]]


def check_app_override_rule(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for r in (data.get("misc_policy") or {}).get("app_override_rules", []):
        if r["disabled"]:
            continue
        match = f"{r['protocol']}/{r['port']}" if r["protocol"] and r["port"] else "its traffic"
        out.append({"key": r["name"],
                    "message": f"Application Override rule '{r['name']}' sends {match} to "
                               f"'{r['application'] or 'a custom app'}' without App-ID or threat inspection",
                    "recommendation": "Replace the override with a custom application signature so the traffic "
                                      "is still inspected",
                    "scm_object": {"type": "app_override", "name": r["name"]}})
    return out


# ── WildFire (ported from Palo Alto SCM checks) ─────────────────────────

# PAN-OS 9.0+ default forwarding limits, in each type's own unit: "Increased WildFire File Forwarding
# Capacity" (pe..linux) and the Advanced WildFire best-practice table (script, eml).
WILDFIRE_DEFAULT_LIMITS = {
    "pe": (16, "MB"), "apk": (10, "MB"), "pdf": (3072, "KB"), "ms-office": (16384, "KB"), "jar": (5, "MB"),
    "flash": (5, "MB"), "macosx": (10, "MB"), "archive": (50, "MB"), "linux": (50, "MB"), "script": (20, "KB"),
    "eml": (20, "MB"),
}


def _license_active(data: dict, *needles: str) -> str:
    """ "yes" / "no" / "unknown": is any active license's feature name contains one of `needles`."""
    lic = data.get("licenses", {})
    if not lic.get("available"):
        return "unknown"
    for e in lic.get("licenses", []):
        feature = e.get("feature", "").strip().lower()
        if any(n in feature for n in needles) and e.get("expired", "no").lower() != "yes":
            return "yes"
    return "no"


def _version_at_least(data: dict, minimum: tuple[int, ...]) -> bool | None:
    import re
    v = (data.get("system_info") or {}).get("sw_version") or ""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    return None if not m else tuple(int(x) for x in m.groups()) >= minimum


def check_wildfire_size_limit_below_default(data: dict, thresholds: dict) -> list[dict]:
    limits = ((data.get("device_settings") or {}).get("wildfire") or {}).get("size_limits", {})
    out = []
    for name, size in sorted(limits.items()):
        default = WILDFIRE_DEFAULT_LIMITS.get(name.lower())
        if default and size < default[0]:
            out.append({"key": name.lower(),
                        "message": f"WildFire forwards {name} files only up to {size:,} {default[1]} "
                                   f"(default {default[0]:,} {default[1]})",
                        "recommendation": f"Set the {name} size limit back to the default {default[0]:,} {default[1]}"})
    return out


def check_wildfire_grayware_not_reported(data: dict, thresholds: dict) -> list[dict]:
    wf = (data.get("device_settings") or {}).get("wildfire")
    return _one(wf is not None and not wf.get("report_grayware"), "Report Grayware Files is off",
                "Enable Report Grayware Files under Device > Setup > WildFire > General Settings")


def check_wildfire_inline_cloud_analysis_disabled(data: dict, thresholds: dict) -> list[dict]:
    lic = _license_active(data, "advanced wildfire")
    if lic == "no":
        return []
    note = _license_note(lic, "Advanced WildFire")
    return [{"key": p["name"],
             "message": f"WildFire Analysis profile '{p['name']}' has Inline Cloud Analysis off{note}",
             "recommendation": "Enable Inline Cloud Analysis in the profile",
             "scm_object": {"type": "wildfire_analysis_profile", "name": p["name"]}}
            for p in _profiles_of(data, "wildfire_analysis")
            if "inline_cloud_analysis" in p["settings"] and not p["settings"]["inline_cloud_analysis"]]


def check_wildfire_realtime_hold_off(data: dict, thresholds: dict) -> list[dict]:
    lic = _license_active(data, "wildfire")
    if lic == "no" or _version_at_least(data, (11, 0, 2)) is False:
        return []
    # Every profile, used or not, as Palo Alto SCM grades them.
    profiles = [p for p in _profiles_of(data, "antivirus") if "wfrt_hold_mode" in p["settings"]]
    off = [p["name"] for p in profiles if not p["settings"]["wfrt_hold_mode"]]
    if not profiles:
        # No Antivirus profile at all (profiles stored before settings were parsed are skipped): nothing
        # holds files, which Palo Alto SCM fails on the rulebase.
        if data.get("security_profiles", {}).get("antivirus") or not _enabled_allow_rules(data):
            return []
        return _one(True, f"No Antivirus profile holds files for WildFire real-time signature lookup: none is "
                          f"defined{_license_note(lic, 'WildFire')}",
                    "Create an Antivirus profile with Hold for WildFire Real Time Signature Look Up enabled, attach it "
                    "to allow rules, and enable hold mode globally (Device > Setup > Content-ID) with the timeout "
                    "action set to Reset-Both")
    return _one(bool(off), f"Antivirus profile(s) {', '.join(off)} don't hold files for WildFire real-time "
                           f"signature lookup{_license_note(lic, 'WildFire')}",
                "Enable Hold for WildFire Real Time Signature Look Up globally (Device > Setup > Content-ID) and "
                "in each Antivirus profile, with the timeout action set to Reset-Both")


# ── Security profile hygiene (ported from Palo Alto SCM checks) ─────────

SCM_PROFILE_TYPE = {"antivirus": "antivirus_profile", "spyware": "anti_spyware_profile",
                    "vulnerability": "vulnerability_protection_profile", "url_filtering": "url_filtering_profile"}
PROFILE_LABEL = {"antivirus": "Antivirus", "spyware": "Anti-Spyware", "vulnerability": "Vulnerability Protection",
                 "url_filtering": "URL Filtering"}


def _profile_finding(ptype: str, profile: dict, message: str, recommendation: str, key: str | None = None) -> dict:
    return {"key": key or profile["name"],
            "message": f"{PROFILE_LABEL[ptype]} profile '{profile['name']}' {message}",
            "recommendation": recommendation,
            "scm_object": {"type": SCM_PROFILE_TYPE[ptype], "name": profile["name"]}}


def check_profile_threat_exceptions(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for ptype in ("antivirus", "spyware", "vulnerability"):
        for p in _profiles_of(data, ptype):
            threats = [e["id"] if isinstance(e, dict) else e for e in p["settings"].get("threat_exceptions", [])]
            apps = p["settings"].get("app_exceptions", [])
            parts = ([f"{len(threats)} threat exception{'s' if len(threats) != 1 else ''} ({', '.join(threats[:5])}"
                      f"{', …' if len(threats) > 5 else ''})"] if threats else []) + \
                    ([f"application exceptions for {', '.join(apps)}"] if apps else [])
            if parts:
                out.append(_profile_finding(ptype, p, f"has {' and '.join(parts)}",
                                            "Remove exceptions once Palo Alto TAC has corrected the false positive",
                                            key=f"{ptype}:{p['name']}"))
    return out


def check_av_packet_capture(data: dict, thresholds: dict) -> list[dict]:
    return [_profile_finding("antivirus", p, "has packet capture on",
                             "Turn packet capture off, or use it only on a dedicated profile for a few rules")
            for p in _profiles_of(data, "antivirus") if p["settings"].get("packet_capture")]


def check_url_log_container_page_only(data: dict, thresholds: dict) -> list[dict]:
    return [_profile_finding("url_filtering", p, "logs only container pages",
                             "Turn off Log Container Page Only so the URL log shows the full session")
            for p in _profiles_of(data, "url_filtering") if p["settings"].get("log_container_page_only")]


def check_url_categories_allowed_unlogged(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for p in _profiles_of(data, "url_filtering"):
        allowed = p["settings"].get("allow_categories") or []
        if allowed:
            out.append(_profile_finding(
                "url_filtering", p,
                f"allows {len(allowed)} categor{'y' if len(allowed) == 1 else 'ies'} without logging "
                f"({', '.join(allowed[:5])}{', …' if len(allowed) > 5 else ''})",
                "Set allowed categories to Alert so access is logged"))
    return out


def check_url_credential_detection_not_domain(data: dict, thresholds: dict) -> list[dict]:
    return [_profile_finding("url_filtering", p, f"detects credential submissions by {p['settings']['credential_enforcement_mode']}",
                             "Use Domain Credential Filter mode (requires the User-ID agent's credential detection)")
            for p in _profiles_of(data, "url_filtering")
            if p["settings"].get("credential_enforcement_mode") not in (None, "disabled", "domain-credentials")]


def check_url_credential_submissions_unlogged(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for p in _profiles_of(data, "url_filtering"):
        allowed = p["settings"].get("credential_allow_categories") or []
        if allowed:
            out.append(_profile_finding(
                "url_filtering", p,
                f"allows credential submission without logging for {len(allowed)} "
                f"categor{'y' if len(allowed) == 1 else 'ies'}",
                "Set the user credential submission action to Alert (or Block) for those categories"))
    return out


def check_url_inline_categorization_off(data: dict, thresholds: dict) -> list[dict]:
    lic = _license_active(data, "advanced url filtering")
    if lic == "no":
        return []
    return [_profile_finding("url_filtering", p,
                             f"has cloud inline categorization off{_license_note(lic, 'Advanced URL Filtering')}",
                             "Enable Cloud Inline Categorization")
            for p in _profiles_of(data, "url_filtering")
            if "cloud_inline_cat" in p["settings"] and not p["settings"]["cloud_inline_cat"]]


INBOUND_CHECK_LABEL = {"block-unsupported-version": "unsupported versions", "block-unsupported-cipher": "unsupported ciphers",
                       "block-if-no-resource": "sessions without resources", "block-if-hsm-unavailable": "HSM unavailable",
                       "block-tls13-downgrade-no-resource": "TLS 1.3 downgrade without resources"}
SSH_CHECK_LABEL = {"block-unsupported-version": "unsupported versions", "block-unsupported-alg": "unsupported algorithms",
                   "block-ssh-errors": "SSH errors", "block-if-no-resource": "sessions without resources"}


def _decryption_profiles_for(data: dict, rule_type: str | None) -> list[tuple[dict, list[str]]]:
    """Every decryption profile, with the active rules (of `rule_type`, if given) that use it. Unused
    profiles are graded too, as Palo Alto SCM does: an unused weak profile is one attach away from use."""
    decryption = data.get("decryption")
    if decryption is None:
        return []
    rules = [r for r in _active_decrypt_rules(decryption) if rule_type is None or r["type"] == rule_type]
    used = dict((p["name"], names) for p, names in _profiles_used_by(decryption, rules))
    return [(p, used.get(p["name"], [])) for p in decryption.get("profiles", [])]


def _decrypt_usage(rules: list[str]) -> str:
    return f"used by {', '.join(rules)}" if rules else "not used by any decryption rule"


def _mode_checks_off(data: dict, rule_type: str, field: str, labels: dict, what: str, fix: str) -> list[dict]:
    out = []
    for profile, rules in _decryption_profiles_for(data, rule_type):
        checks_ = profile.get(field)
        if checks_ is None:
            continue
        off = [labels[k] for k, on in checks_.items() if not on]
        if off:
            out.append({"key": profile["name"],
                        "message": f"Decryption profile '{profile['name']}' ({_decrypt_usage(rules)}) doesn't block "
                                   f"{what}: {', '.join(off)}",
                        "recommendation": fix,
                        "scm_object": {"type": "decryption_profile", "name": profile["name"]}})
    return out


def check_decryption_inbound_checks_off(data: dict, thresholds: dict) -> list[dict]:
    return _mode_checks_off(data, "ssl-inbound-inspection", "inbound_checks", INBOUND_CHECK_LABEL,
                            "inbound sessions with", "Enable every SSL Inbound Inspection block option in the profile")


def check_decryption_ssh_checks_off(data: dict, thresholds: dict) -> list[dict]:
    return _mode_checks_off(data, "ssh-proxy", "ssh_checks", SSH_CHECK_LABEL,
                            "SSH sessions with", "Enable every SSH Proxy block option in the profile")


def check_decryption_weak_hmac(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile, rules in _decryption_profiles_for(data, None):
        weak = [label for key, label in (("auth_algo_md5", "MD5"), ("auth_algo_sha1", "SHA-1")) if profile.get(key)]
        if weak:
            out.append({"key": profile["name"],
                        "message": f"Decryption profile '{profile['name']}' ({_decrypt_usage(rules)}) allows "
                                   f"{' and '.join(weak)} message authentication",
                        "recommendation": "Allow only SHA-256 and SHA-384 authentication algorithms",
                        "scm_object": {"type": "decryption_profile", "name": profile["name"]}})
    return out


SECURITY_LOG_TYPES = {"threat": "Threat", "wildfire": "WildFire", "url": "URL", "auth": "Authentication"}


def _used_log_forwarding_profiles(data: dict) -> list[tuple[dict, list[str]]]:
    profiles = data.get("log_forwarding_profiles")
    if profiles is None:
        return []
    used: dict[str, list[str]] = {}
    for r in data.get("security_rules", []):
        if r.get("log_setting") and r.get("disabled") != "yes":
            used.setdefault(r["log_setting"], []).append(r["name"])
    return [(p, used[p["name"]]) for p in profiles if p["name"] in used]


def check_log_forwarding_profile_no_destination(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for p, rules in _used_log_forwarding_profiles(data):
        if not any(m["destinations"] for m in p["lists"]):
            out.append({"key": p["name"],
                        "message": f"Log Forwarding profile '{p['name']}' (used by {len(rules)} rule"
                                   f"{'s' if len(rules) != 1 else ''}) has no destination",
                        "recommendation": "Forward to Panorama, Strata Logging Service or a syslog server",
                        "scm_object": {"type": "log_forwarding_profile", "name": p["name"]}})
    return out


def check_log_forwarding_profile_missing_types(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for p, rules in _used_log_forwarding_profiles(data):
        forwarded = {m["log_type"] for m in p["lists"] if m["destinations"]}
        if not forwarded:
            continue  # log_forwarding_profile_no_destination covers it
        missing = [label for t, label in SECURITY_LOG_TYPES.items() if t not in forwarded]
        if missing:
            out.append({"key": p["name"],
                        "message": f"Log Forwarding profile '{p['name']}' doesn't forward {', '.join(missing)} logs",
                        "recommendation": "Add a match list with an external destination for each missing log type",
                        "scm_object": {"type": "log_forwarding_profile", "name": p["name"]}})
    return out


# ── Security rule hygiene (ported from Palo Alto SCM checks) ───────────

SPECIAL_USERS = {"any", "known-user", "unknown", "pre-logon"}


def _enabled_allow_rules(data: dict) -> list[dict]:
    return [r for r in data.get("security_rules", []) if r.get("action") == "allow" and r.get("disabled") != "yes"]


def check_security_rule_log_at_start(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": r["name"], "message": f"Rule '{r['name']}' logs at session start",
             "recommendation": "Turn off Log at Session Start (keep Log at Session End) unless troubleshooting",
             "scm_object": {"type": "security_rule", "name": r["name"]}}
            for r in data.get("security_rules", []) if r.get("disabled") != "yes" and r.get("log_start") == "yes"]


def check_security_rule_server_response_inspection_off(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": r["name"], "message": f"Allow rule '{r['name']}' disables server response inspection",
             "recommendation": "Clear Disable Server Response Inspection unless the server is trusted and "
                               "performance requires it",
             "scm_object": {"type": "security_rule", "name": r["name"]}}
            for r in _enabled_allow_rules(data) if r.get("disable_server_response_inspection")]


def check_default_rule_not_logged(data: dict, thresholds: dict) -> list[dict]:
    logging = data.get("default_rule_logging")
    if logging is None:
        return []
    return [{"key": name, "message": f"The predefined {name} rule doesn't log at session end",
             "recommendation": f"Override {name} and enable Log at Session End (with a Log Forwarding profile)"}
            for name, logged in logging.items() if not logged]


def check_user_id_zone_disabled(data: dict, thresholds: dict) -> list[dict]:
    zones = {z["name"]: z for z in data.get("zones", []) if "user_id" in z}
    if not zones:
        return []
    rules_by_zone: dict[str, list[str]] = {}
    for r in _enabled_allow_rules(data):
        if not [u for u in r.get("source_users", []) if u.lower() not in SPECIAL_USERS]:
            continue
        for z in r.get("from_zones", []):
            if z in zones and not zones[z]["user_id"]:
                rules_by_zone.setdefault(z, []).append(r["name"])
    return [{"key": z, "message": f"Zone '{z}' has User-ID off but rules match users from it ({', '.join(rules[:5])}"
                                f"{', …' if len(rules) > 5 else ''})",
             "recommendation": "Enable User Identification on the zone",
             "scm_object": {"type": "zone", "name": z}}
            for z, rules in sorted(rules_by_zone.items())]


def check_no_new_appid_rule(data: dict, thresholds: dict) -> list[dict]:
    objs = data.get("policy_objects")
    if objs is None or "new_appid_filters" not in objs:
        return []
    filters = set(objs["new_appid_filters"])
    if any(filters & set(r.get("applications", [])) for r in _enabled_allow_rules(data)):
        return []
    return _one(True, "No allow rule uses an application filter for new App-IDs",
                "Create an application filter with New App-ID selected and an allow rule for it, so new content "
                "releases don't block previously allowed traffic")


ADVANCED_SERVICES = (
    ("advanced url filtering", "url_filtering", "Advanced URL Filtering", lambda s: s.get("cloud_inline_cat")),
    ("advanced threat prevention", "vulnerability", "Advanced Threat Prevention (vulnerability)",
     lambda s: (s.get("inline_cloud_analysis") or {}).get("enabled")),
    ("advanced threat prevention", "spyware", "Advanced Threat Prevention (anti-spyware)",
     lambda s: (s.get("inline_cloud_analysis") or {}).get("enabled")),
    ("advanced wildfire", "wildfire_analysis", "Advanced WildFire", lambda s: s.get("inline_cloud_analysis")),
)


def check_advanced_profile_not_applied(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for license_name, ptype, label, uses_service in ADVANCED_SERVICES:
        if _license_active(data, license_name) != "yes":
            continue
        captured = (data.get("security_profiles") or {}).get(ptype)
        if captured is None or any("settings" not in p for p in captured):
            continue  # profile settings weren't captured for this assessment
        profiles = _profiles_of(data, ptype)
        if not any(p.get("rule_count", 0) > 0 and uses_service(p["settings"]) for p in profiles):
            out.append({"key": ptype,
                        "message": f"The firewall is licensed for {label}, but no rule uses a profile with it on",
                        "recommendation": "Enable the service's cloud analysis in a profile and attach it to your "
                                          "allow rules"})
    return out


# ── Authentication, User-ID & services (ported from Palo Alto SCM checks) ─

STRONG_TLS = ("tls1-2", "tls1-3")


def _identity(data: dict) -> dict | None:
    return data.get("identity")


def check_ssl_tls_profile_weak(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for p in (_identity(data) or {}).get("tls_profiles", []):
        problems = ([f"minimum {p['min_version']}"] if p["min_version"] not in STRONG_TLS else []) + \
                   ([f"maximum {p['max_version']}"] if p["max_version"] != "max" else [])
        if problems:
            out.append({"key": p["name"], "message": f"SSL/TLS service profile '{p['name']}' has {' and '.join(problems)}",
                        "recommendation": "Set the minimum version to TLSv1.2 and the maximum to Max",
                        "scm_object": {"type": "ssl_tls_service_profile", "name": p["name"]}})
    return out


def check_admin_no_custom_roles(data: dict, thresholds: dict) -> list[dict]:
    ident = _identity(data)
    return _one(ident is not None and not ident.get("admin_roles"), "No custom admin roles are defined",
                "Create admin roles that grant only what each administrator needs, instead of superuser")


def check_auth_profile_local_only(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": p["name"], "message": f"Authentication profile '{p['name']}' uses "
                                          f"{'only the local database' if p['method'] == 'local-database' else 'no method'}",
             "recommendation": "Authenticate against LDAP, RADIUS, TACACS+, SAML or Kerberos instead",
             "scm_object": {"type": "authentication_profile", "name": p["name"]}}
            for p in (_identity(data) or {}).get("auth_profiles", []) if p["method"] in ("local-database", "none")]


def check_auth_sequence_single_profile(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": q["name"], "message": f"Authentication sequence '{q['name']}' has only "
                                          f"{len(q['profiles'])} profile{'s' if len(q['profiles']) != 1 else ''}",
             "recommendation": "Add a second authentication profile as a fallback",
             "scm_object": {"type": "authentication_sequence", "name": q["name"]}}
            for q in (_identity(data) or {}).get("auth_sequences", []) if len(q["profiles"]) < 2]


def check_user_id_client_probing(data: dict, thresholds: dict) -> list[dict]:
    uid = (_identity(data) or {}).get("user_id") or {}
    return _one(bool(uid.get("probing")), "User-ID client probing is enabled",
                "Disable client probing and collect mappings from domain controllers, syslog or GlobalProtect")


def check_user_id_timeout_disabled(data: dict, thresholds: dict) -> list[dict]:
    uid = (_identity(data) or {}).get("user_id") or {}
    return _one(uid.get("mapping_timeout") is False, "The User-ID mapping timeout is disabled",
                "Enable the User-ID timeout so stale IP-to-user mappings expire")


def _portal(data: dict) -> dict | None:
    return (_identity(data) or {}).get("captive_portal")


def check_auth_portal_transparent(data: dict, thresholds: dict) -> list[dict]:
    p = _portal(data)
    return _one(p is not None and p["mode"] == "transparent", "The Authentication Portal uses Transparent mode",
                "Switch the Authentication Portal to Redirect mode")


def check_auth_portal_long_session(data: dict, thresholds: dict) -> list[dict]:
    p = _portal(data)
    if p is None:
        return []
    long_ = [f"{label} {v} minutes" for label, v in (("timer", p["timer"]), ("session cookie", p["cookie_timeout"]))
             if v is not None and v > 480]
    return _one(bool(long_), f"The Authentication Portal {' and '.join(long_)} exceed 480 minutes",
                "Keep the Authentication Portal timer and session cookie at 480 minutes or less")


def check_auth_portal_weak_tls(data: dict, thresholds: dict) -> list[dict]:
    p = _portal(data)
    if p is None:
        return []
    if not p["tls_profile"]:
        return _one(True, "The Authentication Portal has no SSL/TLS service profile",
                    "Assign an SSL/TLS service profile with minimum TLSv1.2 and maximum Max")
    prof = next((t for t in _identity(data).get("tls_profiles", []) if t["name"] == p["tls_profile"]), None)
    weak = prof is not None and prof["min_version"] not in STRONG_TLS
    return _one(weak, f"The Authentication Portal's SSL/TLS profile '{p['tls_profile']}' allows "
                      f"{prof['min_version'] if prof else ''}",
                "Set the profile's minimum version to TLSv1.2 and maximum to Max")


def check_system_logs_high_severity_only(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    if mp is None:
        return []
    lists = [m for m in mp["log_forwarding"].get("system", []) if m["destinations"]]
    if not lists:
        return []  # system_logs_not_forwarded covers it
    def all_severities(f: str) -> bool:
        f = (f or "").lower()
        return f in ("", "all logs") or "informational" in f or "severity geq informational" in f
    return _one(not any(all_severities(m["filter"]) for m in lists),
                "System logs are forwarded only with filter " + ", ".join(sorted({m["filter"] for m in lists})),
                "Add a System log match list with filter All Logs (every severity) to an external destination")


def check_content_updates_gp_not_hourly(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    gp = data.get("globalprotect") or {}
    if mp is None or not (gp.get("portals") or gp.get("gateways")):
        return []
    out = []
    for utype, label in (("global-protect-datafile", "GlobalProtect Data File"),
                         ("global-protect-clientless-vpn", "GlobalProtect Clientless VPN")):
        sched = mp["update_schedule"].get(utype)
        if sched is None or sched["frequency"] != "hourly" or sched["action"] != "download-and-install":
            got = "have no schedule" if sched is None else f"run {sched['frequency']} ({sched['action'] or 'no action'})"
            out.append({"key": utype, "message": f"{label} updates {got}",
                        "recommendation": f"Schedule {label} updates to download-and-install hourly"})
    return out


def check_ldap_single_server(data: dict, thresholds: dict) -> list[dict]:
    mp = _mp(data)
    return [{"key": l["name"], "message": f"LDAP server profile '{l['name']}' has only one server",
             "recommendation": "Add a second LDAP server for redundancy",
             "scm_object": {"type": "ldap_server_profile", "name": l["name"]}}
            for l in (mp or {}).get("ldap", []) if l.get("servers") == 1]


def check_secure_client_cert_predefined(data: dict, thresholds: dict) -> list[dict]:
    d = data.get("device_settings") or {}
    return _one("secure_conn_cert_type" in d and d["secure_conn_cert_type"] not in ("local", "scep"),
                "Secure client communication uses the predefined certificate",
                "Configure Secure Client Communication with a local or SCEP certificate from your PKI")


# ── Advanced IP Defense (license-gated), Gen AI, liability & post-quantum ─

def _aipd(data: dict) -> dict[str, dict] | None:
    if not data.get("security_rules") or _license_active(data, "advanced ip defense") != "yes":
        return None
    return {e["id"]: e for e in threat_intel.coverage(data).get("aipd_lists", [])}


def _aipd_unblocked(data: dict, list_ids: tuple[str, ...], directions: tuple[str, ...]) -> list[dict]:
    lists = _aipd(data)
    if lists is None:
        return []
    out = []
    for lid in list_ids:
        entry = lists[lid]
        for direction in directions:
            if entry[direction]:
                continue
            where, effect = _DIRECTION_TEXT[direction]
            out.append({"key": f"{lid}:{direction}" if len(list_ids) > 1 else direction,
                        "message": f"No enabled deny rule uses '{entry['label']}' ({lid}) {where} — {effect}",
                        "recommendation": f"Add a deny rule with {lid} {where.lower()} address, log at session end, "
                                          "and place it above the rules that allow traffic"})
    return out


def check_aipd_c2_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    return _aipd_unblocked(data, ("panw-aipd-c2-infra-ip-list",), threat_intel.DIRECTIONS)


def check_aipd_malware_ip_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    return _aipd_unblocked(data, ("panw-aipd-in-malware-ip-list",), threat_intel.DIRECTIONS)


def check_aipd_inbound_list_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    return _aipd_unblocked(data, ("panw-aipd-vpn-ip-list", "panw-aipd-proxies-ip-list", "panw-aipd-scanning-ip-list",
                                  "panw-aipd-vuln-svcs-ip-list"), ("inbound",))


def check_aipd_rule_missing_pair(data: dict, thresholds: dict) -> list[dict]:
    lists = _aipd(data)
    if lists is None:
        return []
    c2 = set(lists["panw-aipd-c2-infra-ip-list"]["inbound"] + lists["panw-aipd-c2-infra-ip-list"]["outbound"])
    mw = set(lists["panw-aipd-in-malware-ip-list"]["inbound"] + lists["panw-aipd-in-malware-ip-list"]["outbound"])
    out = []
    for name in sorted(c2 ^ mw):
        has, missing = ("C2 infrastructure", "hardcoded-in-malware") if name in c2 else ("hardcoded-in-malware", "C2 infrastructure")
        out.append({"key": name, "message": f"Deny rule '{name}' uses the Advanced IP Defense {has} list but not {missing}",
                    "recommendation": "Use both panw-aipd-c2-infra-ip-list and panw-aipd-in-malware-ip-list in the rule",
                    "scm_object": {"type": "security_rule", "name": name}})
    return out


LIABILITY_CATEGORIES = ("abused-drugs", "adult", "copyright-infringement", "extremism", "gambling", "peer-to-peer",
                        "questionable", "weapons")
GENAI_CATEGORIES = ("ai-code-assistant", "ai-conversational-assistant", "ai-data-and-workflow-optimizer",
                    "ai-meeting-assistant", "ai-platform-service", "ai-writing-assistant")


def _url_missing_blocks(data: dict, field: str, wanted: tuple[str, ...], what: str, fix: str) -> list[dict]:
    out = []
    for p in _profiles_of(data, "url_filtering"):
        blocked = {c.lower() for c in p["settings"].get(field) or []}
        missing = [c for c in wanted if c not in blocked]
        if missing:
            out.append(_profile_finding("url_filtering", p, f"doesn't block {what}: {', '.join(missing)}", fix))
    return out


def check_url_liability_categories_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    return _url_missing_blocks(data, "block_categories", LIABILITY_CATEGORIES, "liability-risk categories",
                               "Set these categories to Block")


def check_url_liability_credentials_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    return _url_missing_blocks(data, "credential_enforcement_block_categories", LIABILITY_CATEGORIES,
                               "credential submission to liability-risk categories",
                               "Set User Credential Submission to Block for these categories")


def check_url_genai_categories_not_blocked(data: dict, thresholds: dict) -> list[dict]:
    return _url_missing_blocks(data, "block_categories", GENAI_CATEGORIES, "generative AI categories",
                               "Block these categories and allow only sanctioned AI tools by exception")


GENAI_FILTERS = {"gen ai apps", "sanctioned gen ai apps", "tolerated gen ai apps"}


def _genai_filters_in(rule: dict) -> set[str]:
    return {a.lower() for a in rule.get("applications", [])} & GENAI_FILTERS


def check_genai_no_block_rule(data: dict, thresholds: dict) -> list[dict]:
    if not data.get("security_rules"):
        return []
    blocking = [r for r in data["security_rules"] if r.get("disabled") != "yes"
                and r.get("action") in threat_intel.BLOCK_ACTIONS and "gen ai apps" in _genai_filters_in(r)]
    return _one(not blocking, "No enabled deny rule uses the \"Gen AI Apps\" application filter",
                "Add a deny rule for the Gen AI Apps filter below the rule allowing sanctioned Gen AI apps")


def check_genai_tolerated_no_users(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": r["name"], "message": f"Rule '{r['name']}' allows Tolerated Gen AI apps for any user",
             "recommendation": "Limit the rule to the users or groups with a business need",
             "scm_object": {"type": "security_rule", "name": r["name"]}}
            for r in _enabled_allow_rules(data)
            if "tolerated gen ai apps" in _genai_filters_in(r)
            and not [u for u in r.get("source_users", []) if u.lower() not in SPECIAL_USERS]]


def _has_data_filtering(rule: dict, data: dict) -> bool:
    if rule.get("indiv_profiles", {}).get("data-filtering"):
        return True
    group = next((g for g in data.get("profile_groups", []) if g["name"] == rule.get("profile_group")), None)
    return bool(group and group.get("data_filtering"))


def check_genai_allow_no_dlp(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": r["name"], "message": f"Rule '{r['name']}' allows Gen AI apps without a Data Filtering profile",
             "recommendation": "Attach a Data Filtering (DLP) profile to the rule",
             "scm_object": {"type": "security_rule", "name": r["name"]}}
            for r in _enabled_allow_rules(data) if _genai_filters_in(r) and not _has_data_filtering(r, data)]


def check_decryption_not_quantum_safe_ciphers(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for profile, rules in _decryption_profiles_for(data, None):
        legacy = profile.get("legacy_ciphers")
        if legacy:
            out.append({"key": profile["name"],
                        "message": f"Decryption profile '{profile['name']}' ({_decrypt_usage(rules)}) allows "
                                   f"{', '.join(a.upper() for a in legacy)}",
                        "recommendation": "Allow only AES-256-GCM and ChaCha20-Poly1305",
                        "scm_object": {"type": "decryption_profile", "name": profile["name"]}})
    return out


def check_decryption_no_pqc_key_exchange(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": profile["name"],
             "message": f"Decryption profile '{profile['name']}' ({_decrypt_usage(rules)}) has no PQC key exchange",
             "recommendation": "Enable PQC Standard (and optionally PQC Experimental) key exchange in the profile",
             "scm_object": {"type": "decryption_profile", "name": profile["name"]}}
            for profile, rules in _decryption_profiles_for(data, None) if profile.get("pqc_key_exchange") is False]



# ── Known vulnerabilities (Palo Alto Networks security advisories) ─────────
# The advisory feed isn't part of the parsed config: compute_findings adds the cached copy
# as data["_advisories"]. Matching needs the exact version and hotfix, which only a tech
# support file or live connection gives.

def advisory_hits(data: dict) -> tuple[list[dict], str | None]:
    info = data.get("system_info") or {}
    feed = data.get("_advisories")
    version = info.get("sw_version") if info.get("available") else None
    if not feed or not version or advisories.parse_version(version) is None:
        return [], version
    return advisories.affecting(feed, version), version


def _advisory_each(severities: tuple[str, ...]):
    def check(data: dict, thresholds: dict) -> list[dict]:
        hits, version = advisory_hits(data)
        return [{
            "key": h["id"],
            "message": f"{h['id']}: {h['title']}" + (f" (CVSS {h['score']})" if h.get("score") else "")
                       + f" — affects the installed PAN-OS {version}",
            "recommendation": f"{h['fix']}. Check the advisory for the configurations it applies to and any "
                              f"workaround: {h['url']}",
        } for h in hits if h["severity"] in severities]
    return check


def _advisory_rollup(severities: tuple[str, ...], label: str):
    def check(data: dict, thresholds: dict) -> list[dict]:
        hits, version = advisory_hits(data)
        hits = [h for h in hits if h["severity"] in severities]
        if not hits:
            return []
        ids = [h["id"] for h in hits]
        shown = ", ".join(ids[:6]) + (f" and {len(ids) - 6} more" if len(ids) > 6 else "")
        target = advisories.recommended_upgrade(data["_advisories"], version)
        return [{
            "key": "global",
            "message": f"{len(hits)} {label} security advisor{'y' if len(hits) == 1 else 'ies'} affect"
                       f"{'s' if len(hits) == 1 else ''} the installed PAN-OS {version}: {shown}",
            "recommendation": (f"Upgrade to PAN-OS {target} or a later build that fixes these. {target} is the "
                               f"earliest build in this release that no critical or high advisory affects" if target else
                               "Upgrade to a PAN-OS release that fixes them; each advisory's fix is in the "
                               "Known vulnerabilities table"),
        }]
    return check


# ── Certificates ────────────────────────────────────────────────────────

def _certs(data: dict) -> list[dict]:
    return (data.get("certificates") or {}).get("certificates") or []


def _days_left(cert: dict) -> float | None:
    if not cert.get("not_after"):
        return None
    return (datetime.fromisoformat(cert["not_after"]) - datetime.now(timezone.utc)).total_seconds() / 86400


def _cert_label(c: dict) -> str:
    return f"Certificate '{c['name']}'" + (f" (CN {c['common_name']})" if c.get("common_name") else "")


def _uses(c: dict) -> str:
    return "; ".join(c["used_by"])


def _expiry_date(c: dict) -> str:
    return datetime.fromisoformat(c["not_after"]).strftime("%b %-d, %Y")


def check_cert_expired(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": c["name"],
        "message": f"{_cert_label(c)} expired on {_expiry_date(c)} and is used by {_uses(c)}",
        "recommendation": "Renew or replace the certificate and update everything that uses it",
    } for c in _certs(data) if c["used_by"] and (d := _days_left(c)) is not None and d < 0]


def check_cert_expiring_soon(data: dict, thresholds: dict) -> list[dict]:
    limit = thresholds["expiry_warning_days"]
    return [{
        "key": c["name"],
        "message": f"{_cert_label(c)} expires on {_expiry_date(c)} ({int(d)} days) and is used by {_uses(c)}",
        "recommendation": "Renew the certificate before it expires and update everything that uses it",
    } for c in _certs(data) if c["used_by"] and (d := _days_left(c)) is not None and 0 <= d < limit]


def check_cert_expired_unused(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": c["name"],
        "message": f"{_cert_label(c)} expired on {_expiry_date(c)} and nothing in the configuration uses it",
        "recommendation": "Delete the certificate",
    } for c in _certs(data) if not c["used_by"] and (d := _days_left(c)) is not None and d < 0]


def check_cert_weak_key(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for c in _certs(data):
        bits, algo = c.get("key_bits"), c.get("key_algorithm")
        if not bits or not (c["has_private_key"] or c["used_by"]):
            continue
        minimum = {"RSA": thresholds["min_rsa_bits"], "DSA": thresholds["min_rsa_bits"],
                   "EC": thresholds["min_ec_bits"]}.get(algo)
        if minimum and bits < minimum:
            out.append({
                "key": c["name"],
                "message": f"{_cert_label(c)} has a {bits}-bit {algo} key",
                "recommendation": f"Replace it with a certificate that has at least a {minimum}-bit {algo} key "
                                  f"(or an ECDSA P-256 key)",
            })
    return out


def check_cert_weak_signature(data: dict, thresholds: dict) -> list[dict]:
    return [{
        "key": c["name"],
        "message": f"{_cert_label(c)} is signed with {c['signature_hash']}",
        "recommendation": "Reissue the certificate with a SHA-256 (or stronger) signature",
    } for c in _certs(data)
        if c.get("signature_hash") in ("SHA-1", "MD5") and not c["self_signed"]
        and (c["has_private_key"] or c["used_by"])]


def check_cert_self_signed_service(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for c in _certs(data):
        services = [s for s in c["services"] if s.startswith(USER_FACING)]
        if c["self_signed"] and services:
            out.append({
                "key": c["name"],
                "message": f"{_cert_label(c)} is self-signed and presented by {', '.join(services)}",
                "recommendation": "Use a certificate issued by a public CA, or by an enterprise CA that users' "
                                  "devices trust",
            })
    return out


# ── Rulebase analysis: shadowed and redundant rules ─────────────────────

def _shadow_msg(s: dict) -> dict:
    rule, by = f"'{s['rule']}' (#{s['position']}, {s['action']})", f"'{s['by']}' (#{s['by_position']}, {s['by_action']})"
    if s["kind"] == "block_allowed":
        return {"message": f"Rule {rule} never matches: rule {by} above it matches all of its traffic, so the "
                           f"traffic it's meant to block is allowed",
                "recommendation": f"Move '{s['rule']}' above '{s['by']}', or narrow '{s['by']}' so it no longer "
                                  f"covers this traffic"}
    if s["kind"] == "allow_blocked":
        return {"message": f"Rule {rule} never matches: rule {by} above it blocks all of its traffic",
                "recommendation": f"Remove '{s['rule']}' if the traffic should stay blocked, or move it above "
                                  f"'{s['by']}'"}
    return {"message": f"Rule {rule} never matches: rule {by} above it already matches all of its traffic "
                       f"with the same outcome",
            "recommendation": f"Remove '{s['rule']}', or move it above '{s['by']}' if its own profiles or "
                              f"logging were meant to apply"}


def check_security_rule_shadowed_block(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": s["rule"], **_shadow_msg(s)}
            for s in rulebase.analyze(data)["shadowed"] if s["kind"] == "block_allowed"]


def check_security_rule_shadowed(data: dict, thresholds: dict) -> list[dict]:
    return [{"key": s["rule"], **_shadow_msg(s)}
            for s in rulebase.analyze(data)["shadowed"] if s["kind"] != "block_allowed"]


# ── Rulebase analysis: unused and duplicate objects ─────────────────────

def _count_label(n: int, plural: str) -> str:
    one = plural[:-3] + "y" if plural.endswith("ies") else plural[:-1]
    return f"{n} {one if n == 1 else plural}"


def _listing(names: list[str], limit: int = 8) -> str:
    shown = ", ".join(f"'{n}'" for n in names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def check_unused_objects(data: dict, thresholds: dict) -> list[dict]:
    usage = data.get("object_usage") or {}
    if not usage.get("available"):
        return []
    note = (" Objects pushed from Panorama are deleted there, or stop being pushed when Panorama's "
            "\"Share Unused Address and Service Objects with Devices\" is off." if data.get("panorama_managed") else "")
    out = []
    for kind, names in usage.get("unused", {}).items():
        label = OBJECT_KINDS.get(kind, ([], kind.replace("_", " ")))[1]
        verb = "isn't" if len(names) == 1 else "aren't"
        out.append({
            "key": kind,
            "message": f"{_count_label(len(names), label)} {verb} used anywhere in the configuration: {_listing(names)}",
            "recommendation": "Delete them to keep the configuration readable, after confirming nothing outside the "
                              "firewall (a script or another management tool) relies on them." + note,
        })
    return out


def check_duplicate_objects(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for kind in ("addresses", "services"):
        sets = [d for d in find_duplicates(data.get("policy_objects") or {}) if d["kind"] == kind]
        if not sets:
            continue
        shown = "; ".join(f"{' = '.join(repr(n) for n in d['names'])} ({d['value']})" for d in sets[:5])
        more = f"; and {len(sets) - 5} more" if len(sets) > 5 else ""
        out.append({
            "key": kind,
            "message": f"{_count_label(len(sets), 'sets')} of {OBJECT_KINDS[kind][1]} "
                       f"{'shares' if len(sets) == 1 else 'share'} the same value: {shown}{more}",
            "recommendation": "Keep one object per value and point rules and groups at it, so a change to the "
                              "value is made in one place",
        })
    return out



# ── NAT policy ──────────────────────────────────────────────────────────

def _nat_rules(data: dict) -> list[dict]:
    return [r for r in data.get("nat_rules") or [] if not r.get("disabled")]


def _nat_target(r: dict) -> str:
    dt = r["destination_translation"]
    return (dt.get("address") or "the translated address") + (f" port {dt['port']}" if dt.get("port") else "")


def check_nat_rule_shadowed(data: dict, thresholds: dict) -> list[dict]:
    analysis = nat.analyze(data)
    out = []
    for s in (analysis or {}).get("shadowed", []):
        effect = ("with the same translation, so it's redundant" if s["same_translation"]
                  else "and translates it differently, so this rule's translation never applies")
        out.append({
            "key": s["rule"],
            "message": f"NAT rule '{s['rule']}' (#{s['position']}) never matches: NAT rule '{s['by']}' "
                       f"(#{s['by_position']}) above it matches all of its traffic {effect}",
            "recommendation": f"Remove '{s['rule']}', or move it above '{s['by']}' if its translation is the one "
                              f"that should apply",
        })
    return out


def check_nat_dnat_no_allow_rule(data: dict, thresholds: dict) -> list[dict]:
    analysis = nat.analyze(data)
    by_name = {r["name"]: r for r in _nat_rules(data)}
    return [{
        "key": name,
        "message": f"Destination NAT rule '{name}' translates to {_nat_target(by_name[name])}, but no enabled allow "
                   f"rule in the security policy could match its traffic, so the translation is never used",
        "recommendation": "Delete the NAT rule if the service was retired; otherwise add a security rule from the "
                          "NAT rule's source zone to the post-NAT zone, with the pre-NAT (public) destination "
                          "address",
    } for name in (analysis or {}).get("unpermitted_dnat", []) if name in by_name]


def check_nat_dnat_all_ports(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for r in _nat_rules(data):
        dt = r.get("destination_translation")
        zones = r.get("from_zones") or ["any"]
        if not dt or dt.get("port") or (r.get("service") or "any") != "any":
            continue
        if "any" in zones or any(nat.is_external(z) for z in zones):
            out.append({
                "key": r["name"],
                "message": f"Destination NAT rule '{r['name']}' forwards every port from "
                           f"{', '.join(zones)} to {_nat_target(r)}",
                "recommendation": "Set the rule's service to only the ports the published server needs, so a "
                                  "broad security rule can't expose the rest of the host",
            })
    return out


def check_nat_bidirectional_static(data: dict, thresholds: dict) -> list[dict]:
    out = []
    for r in _nat_rules(data):
        st = r.get("source_translation") or {}
        if st.get("type") == "static-ip" and st.get("bidirectional"):
            translated = ", ".join(st.get("translated") or []) or "its translated address"
            out.append({
                "key": r["name"],
                "message": f"NAT rule '{r['name']}' is bi-directional static NAT, which also translates inbound "
                           f"connections to {translated} from any zone, on every port",
                "recommendation": "Turn off Bi-directional and add a separate destination NAT rule from the "
                                  "outside zone for only the ports that need to reach the host",
            })
    return out

CHECKS = {
    "eol_pan_os_version": check_eol_pan_os_version,
    "license_expired": check_license_expired,
    "license_expiring_soon": check_license_expiring_soon,
    "default_admin_account": check_default_admin_account,
    "admin_local_auth_no_mfa": check_admin_local_auth_no_mfa,
    "zone_missing_protection_profile": check_zone_missing_protection_profile,
    "zone_protection_no_recon": check_zone_protection_no_recon,
    "zone_protection_recon_alert_only": check_zone_protection_recon_alert_only,
    "zone_protection_flood_disabled": check_zone_protection_flood_disabled,
    "security_rule_any_any_any": check_security_rule_any_any_any,
    "security_rule_missing_profile_non_infra": check_security_rule_missing_profile_non_infra,
    "security_rule_missing_profile_infra": check_security_rule_missing_profile_infra,
    "security_rule_inbound_untrust_any_source": check_security_rule_inbound_untrust_any_source,
    "security_rule_app_any_service_any": check_security_rule_app_any_service_any,
    "security_rule_service_any": check_security_rule_service_any,
    "security_rule_no_description": check_security_rule_no_description,
    "security_rule_temp_test_name": check_security_rule_temp_test_name,
    "security_rule_no_logging_allow": check_security_rule_no_logging_allow,
    "security_rule_deny_no_logging": check_security_rule_deny_no_logging,
    "security_rule_no_log_forwarding": check_security_rule_no_log_forwarding,
    "security_policy_no_deny_remaining": check_security_policy_no_deny_remaining,
    "threat_profile_missing_antivirus": check_threat_profile_missing_antivirus,
    "threat_profile_missing_vulnerability": check_threat_profile_missing_vulnerability,
    "threat_profile_missing_spyware": check_threat_profile_missing_spyware,
    "threat_profile_missing_url_filtering": check_threat_profile_missing_url_filtering,
    "threat_profile_missing_file_blocking": check_threat_profile_missing_file_blocking,
    "wildfire_profile_missing": check_wildfire_profile_missing,
    "av_decoder_below_baseline": check_av_decoder_below_baseline,
    "av_inline_ml_disabled": check_av_inline_ml_disabled,
    "spyware_severity_below_baseline": check_spyware_severity_below_baseline,
    "spyware_dns_category_mismatch": check_spyware_dns_category_mismatch,
    "vulnerability_severity_below_baseline": check_vulnerability_severity_below_baseline,
    "spyware_inline_cloud_analysis_disabled": check_spyware_inline_cloud_analysis_disabled,
    "vulnerability_inline_cloud_analysis_disabled": check_vulnerability_inline_cloud_analysis_disabled,
    "spyware_inline_cloud_model_not_reset": check_spyware_inline_cloud_model_not_reset,
    "vulnerability_inline_cloud_model_not_reset": check_vulnerability_inline_cloud_model_not_reset,
    "url_mandatory_category_not_blocked": check_url_mandatory_category_not_blocked,
    "url_elevated_risk_category_not_blocked": check_url_elevated_risk_category_not_blocked,
    "url_credential_enforcement_disabled": check_url_credential_enforcement_disabled,
    "file_blocking_nothing_blocked": check_file_blocking_nothing_blocked,
    "wildfire_missing_recommended_filetype": check_wildfire_missing_recommended_filetype,
    "decryption_no_outbound": check_decryption_no_outbound,
    "decryption_no_best_practice_profile": check_decryption_no_best_practice_profile,
    "decryption_profile_weak_tls": check_decryption_profile_weak_tls,
    "decryption_profile_cert_checks_disabled": check_decryption_profile_cert_checks_disabled,
    "decryption_no_decrypt_cert_checks": check_decryption_no_decrypt_cert_checks,
    "mgmt_profile_cleartext": check_mgmt_profile_cleartext,
    "mgmt_interface_open_to_any_source": check_mgmt_interface_open_to_any_source,
    "no_syslog_profile": check_no_syslog_profile,
    "ha_not_synced": check_ha_not_synced,
    "aipd_c2_not_blocked": check_aipd_c2_not_blocked,
    "aipd_malware_ip_not_blocked": check_aipd_malware_ip_not_blocked,
    "aipd_inbound_list_not_blocked": check_aipd_inbound_list_not_blocked,
    "aipd_rule_missing_pair": check_aipd_rule_missing_pair,
    "url_liability_categories_not_blocked": check_url_liability_categories_not_blocked,
    "url_liability_credentials_not_blocked": check_url_liability_credentials_not_blocked,
    "url_genai_categories_not_blocked": check_url_genai_categories_not_blocked,
    "genai_no_block_rule": check_genai_no_block_rule,
    "genai_tolerated_no_users": check_genai_tolerated_no_users,
    "genai_allow_no_dlp": check_genai_allow_no_dlp,
    "decryption_not_quantum_safe_ciphers": check_decryption_not_quantum_safe_ciphers,
    "decryption_no_pqc_key_exchange": check_decryption_no_pqc_key_exchange,
    "ssl_tls_profile_weak": check_ssl_tls_profile_weak,
    "admin_no_custom_roles": check_admin_no_custom_roles,
    "auth_profile_local_only": check_auth_profile_local_only,
    "auth_sequence_single_profile": check_auth_sequence_single_profile,
    "user_id_client_probing": check_user_id_client_probing,
    "user_id_timeout_disabled": check_user_id_timeout_disabled,
    "auth_portal_transparent": check_auth_portal_transparent,
    "auth_portal_long_session": check_auth_portal_long_session,
    "auth_portal_weak_tls": check_auth_portal_weak_tls,
    "system_logs_high_severity_only": check_system_logs_high_severity_only,
    "content_updates_gp_not_hourly": check_content_updates_gp_not_hourly,
    "ldap_single_server": check_ldap_single_server,
    "secure_client_cert_predefined": check_secure_client_cert_predefined,
    "security_rule_log_at_start": check_security_rule_log_at_start,
    "security_rule_server_response_inspection_off": check_security_rule_server_response_inspection_off,
    "default_rule_not_logged": check_default_rule_not_logged,
    "user_id_zone_disabled": check_user_id_zone_disabled,
    "no_new_appid_rule": check_no_new_appid_rule,
    "advanced_profile_not_applied": check_advanced_profile_not_applied,
    "profile_threat_exceptions": check_profile_threat_exceptions,
    "av_packet_capture": check_av_packet_capture,
    "url_log_container_page_only": check_url_log_container_page_only,
    "url_categories_allowed_unlogged": check_url_categories_allowed_unlogged,
    "url_credential_detection_not_domain": check_url_credential_detection_not_domain,
    "url_credential_submissions_unlogged": check_url_credential_submissions_unlogged,
    "url_inline_categorization_off": check_url_inline_categorization_off,
    "decryption_inbound_checks_off": check_decryption_inbound_checks_off,
    "decryption_ssh_checks_off": check_decryption_ssh_checks_off,
    "decryption_weak_hmac": check_decryption_weak_hmac,
    "log_forwarding_profile_no_destination": check_log_forwarding_profile_no_destination,
    "log_forwarding_profile_missing_types": check_log_forwarding_profile_missing_types,
    "wildfire_size_limit_below_default": check_wildfire_size_limit_below_default,
    "wildfire_grayware_not_reported": check_wildfire_grayware_not_reported,
    "wildfire_inline_cloud_analysis_disabled": check_wildfire_inline_cloud_analysis_disabled,
    "wildfire_realtime_hold_off": check_wildfire_realtime_hold_off,
    "session_timeout_changed": check_session_timeout_changed,
    "session_accelerated_aging_off": check_session_accelerated_aging_off,
    "packet_buffer_protection_global_off": check_packet_buffer_protection_global_off,
    "cert_expiration_check_off": check_cert_expiration_check_off,
    "log_high_dp_load_off": check_log_high_dp_load_off,
    "telemetry_disabled": check_telemetry_disabled,
    "update_server_verification_off": check_update_server_verification_off,
    "mgmt_interface_cleartext": check_mgmt_interface_cleartext,
    "ha_timers_not_recommended": check_ha_timers_not_recommended,
    "gre_keepalive_off": check_gre_keepalive_off,
    "pbf_no_monitor": check_pbf_no_monitor,
    "app_override_rule": check_app_override_rule,
    "dos_no_protection": check_dos_no_protection,
    "dos_rule_not_protect": check_dos_rule_not_protect,
    "dos_profile_flood_incomplete": check_dos_profile_flood_incomplete,
    "dos_profile_default_thresholds": check_dos_profile_default_thresholds,
    "zone_protection_packet_based_off": check_zone_protection_packet_based_off,
    "zone_packet_buffer_protection_off": check_zone_packet_buffer_protection_off,
    "session_rematch_disabled": check_session_rematch_disabled,
    "tcp_forward_oo_queue": check_tcp_forward_oo_queue,
    "vpn_weak_encryption": check_vpn_weak_encryption,
    "vpn_weak_authentication": check_vpn_weak_authentication,
    "vpn_weak_dh_group": check_vpn_weak_dh_group,
    "ike_aggressive_mode": check_ike_aggressive_mode,
    "ike_v1_only": check_ike_v1_only,
    "vpn_manual_key": check_vpn_manual_key,
    "vpn_lifetime_long": check_vpn_lifetime_long,
    "vpn_anti_replay_disabled": check_vpn_anti_replay_disabled,
    "vpn_no_tunnel_monitor": check_vpn_no_tunnel_monitor,
    "vpn_stale_config": check_vpn_stale_config,
    "ha_config_sync_disabled": check_ha_config_sync_disabled,
    "ha_session_sync_disabled": check_ha_session_sync_disabled,
    "ha2_keepalive_disabled": check_ha2_keepalive_disabled,
    "ha1_encryption_disabled": check_ha1_encryption_disabled,
    "ha1_no_backup": check_ha1_no_backup,
    "ha_heartbeat_backup_off": check_ha_heartbeat_backup_off,
    "ha_passive_link_state_shutdown": check_ha_passive_link_state_shutdown,
    "ha_no_monitoring": check_ha_no_monitoring,
    "ha_active_active_incomplete": check_ha_active_active_incomplete,
    "mgmt_no_acl": check_mgmt_no_acl,
    "no_login_banner": check_no_login_banner,
    "no_ntp": check_no_ntp,
    "admin_lockout_weak": check_admin_lockout_weak,
    "admin_idle_timeout_long": check_admin_idle_timeout_long,
    "api_key_no_lifetime": check_api_key_no_lifetime,
    "password_complexity_weak": check_password_complexity_weak,
    "mgmt_tls_below_1_2": check_mgmt_tls_below_1_2,
    "snmp_v2c": check_snmp_v2c,
    "ldap_profile_no_tls": check_ldap_profile_no_tls,
    "radius_weak_protocol": check_radius_weak_protocol,
    "tacacs_pap": check_tacacs_pap,
    "syslog_not_tls": check_syslog_not_tls,
    "system_logs_not_forwarded": check_system_logs_not_forwarded,
    "config_logs_not_forwarded": check_config_logs_not_forwarded,
    "content_updates_not_timely": check_content_updates_not_timely,
    "edl_known_malicious_not_blocked": check_edl_known_malicious_not_blocked,
    "edl_high_risk_not_blocked": check_edl_high_risk_not_blocked,
    "edl_bulletproof_not_blocked": check_edl_bulletproof_not_blocked,
    "edl_tor_exit_not_blocked": check_edl_tor_exit_not_blocked,
    "quic_not_blocked": check_quic_not_blocked,
    "gp_tls_below_1_2": check_gp_tls_below_1_2,
    "gp_tls_weak_ciphers": check_gp_tls_weak_ciphers,
    "gp_single_factor_auth": check_gp_single_factor_auth,
    "gp_auth_no_lockout": check_gp_auth_no_lockout,
    "gp_cert_profile_no_revocation": check_gp_cert_profile_no_revocation,
    "gp_no_trusted_root_ca": check_gp_no_trusted_root_ca,
    "gp_connect_on_demand": check_gp_connect_on_demand,
    "gp_not_enforced": check_gp_not_enforced,
    "gp_user_can_disable": check_gp_user_can_disable,
    "gp_hip_collection_disabled": check_gp_hip_collection_disabled,
    "gp_no_internal_host_detection": check_gp_no_internal_host_detection,
    "gp_split_tunnel": check_gp_split_tunnel,
    "gp_long_cookie_lifetime": check_gp_long_cookie_lifetime,
    "gp_satellite_no_root_ca": check_gp_satellite_no_root_ca,
    "panos_advisory_critical": _advisory_each(("CRITICAL",)),
    "panos_advisory_high": _advisory_each(("HIGH",)),
    "panos_advisory_medium": _advisory_rollup(("MEDIUM",), "medium-severity"),
    "panos_advisory_low": _advisory_rollup(("LOW", "INFORMATIONAL"), "low-severity"),
    "cert_expired": check_cert_expired,
    "cert_expiring_soon": check_cert_expiring_soon,
    "cert_expired_unused": check_cert_expired_unused,
    "cert_weak_key": check_cert_weak_key,
    "cert_weak_signature": check_cert_weak_signature,
    "cert_self_signed_service": check_cert_self_signed_service,
    "security_rule_shadowed_block": check_security_rule_shadowed_block,
    "security_rule_shadowed": check_security_rule_shadowed,
    "unused_objects": check_unused_objects,
    "duplicate_objects": check_duplicate_objects,
    "nat_rule_shadowed": check_nat_rule_shadowed,
    "nat_dnat_no_allow_rule": check_nat_dnat_no_allow_rule,
    "nat_dnat_all_ports": check_nat_dnat_all_ports,
    "nat_bidirectional_static": check_nat_bidirectional_static,
}

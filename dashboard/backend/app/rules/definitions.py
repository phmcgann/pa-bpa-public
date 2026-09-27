"""
Declarative registry of the core rules — the dashboard's own checks,
implemented here and run locally against the parsed config.

Every core rule carries an honest `source_type` saying what it's *based on*:

  source_type="cis"       -> a real, verified CIS Palo Alto Firewall Benchmark
                             control number (checked against public benchmark
                             excerpts at build time). source_ref names it.
  source_type="pan_docs"  -> a real, verified recommendation from Palo Alto
                             Networks' own publicly available documentation — the
                             Best Practices library (docs.paloaltonetworks.com/best-practices)
                             or a product administrator's guide. source_ref names the
                             specific guidance and links the page.
  source_type="custom"    -> a house heuristic with no external standard behind
                             it (this was true of ~all checks in the original
                             collect_data.py script). source_ref is None.

Do not add a "cis" or "pan_docs" tag without a citation you actually verified —
fabricated citations are worse than an honest "custom" label. A check whose
*detection logic* is only a loose proxy for a real recommendation (e.g.
keyword-matching a rule name to guess it's stale, versus Palo Alto's actual
"periodically review and remove unused rules" guidance) stays "custom" too —
being about the same general topic isn't the same as implementing the
documented check.

`scm_check_ids` links a rule to the Palo Alto Strata Cloud Manager (SCM) BPA checks
(see scm_catalog.py) that evaluate the same setting. It only records overlap — the
core rule keeps its own logic and citation. When SCM results are loaded for an
assessment, an SCM finding for a linked check isn't scored a second time.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal, Optional


@dataclass(frozen=True)
class RuleDef:
    id: str
    title: str
    category: str
    default_severity: Literal["CRITICAL", "WARNING", "LOW", "INFORMATIONAL"]
    source_type: Literal["cis", "pan_docs", "custom"]
    source_ref: Optional[str]
    description: str
    thresholds: dict = field(default_factory=dict)
    scm_check_ids: tuple[int, ...] = ()
    # Rules that start switched off (turn them on in Settings), with the reason shown there.
    enabled_by_default: bool = True
    default_off_reason: Optional[str] = None


PAN_BPA_ADMIN = (
    "Palo Alto Networks Best Practices — Administrative Access Best Practices "
    "(docs.paloaltonetworks.com/best-practices/administrative-access-best-practices)"
)
PAN_BPA_ZONE_PROTECTION = (
    "Palo Alto Networks Best Practices — DoS and Zone Protection Best Practices "
    "(docs.paloaltonetworks.com/best-practices/dos-and-zone-protection-best-practices)"
)
PAN_BPA_RULE = (
    "Palo Alto Networks Best Practices — Security Policy Rule Best Practices "
    "(docs.paloaltonetworks.com/best-practices/security-policy-best-practices/.../security-policy-rule-best-practices)"
)
PAN_BPA_DECRYPTION = (
    "Palo Alto Networks Best Practices — Decryption Best Practices "
    "(docs.paloaltonetworks.com/best-practices/10-2/decryption-best-practices)"
)
IGW_DOCS = ("docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/"
            "best-practice-internet-gateway-security-policy/define-the-initial-internet-gateway-security-policy")
PAN_BPA_IGW_STEP1 = (
    "Palo Alto Networks Best Practices — Internet Gateway Best Practice Security Policy, Step 1: Create Rules "
    "Based on Trusted Threat Intelligence Sources: set the built-in list \"as the Destination address for the "
    "outbound traffic rule, and as the Source address for the inbound traffic rule. Deny traffic that matches "
    f"these rules\" ({IGW_DOCS}/step-1-create-rules-based-on-trusted-threat-intelligence-sources)"
)
PAN_BPA_IGW_QUIC = (
    "Palo Alto Networks Best Practices — Internet Gateway Best Practice Security Policy, Step 3: Create the "
    "Application Block Rules: \"Block Quick UDP Internet Connections (QUIC) protocol ... Blocking QUIC forces the "
    "browser to fall back to TLS and enables the firewall to decrypt the traffic\" "
    f"({IGW_DOCS}/step-3-create-the-application-block-rules)"
)
AA_DEPLOY = ("docs.paloaltonetworks.com/best-practices/10-1/administrative-access-best-practices/"
             "administrative-access-best-practices/deploy-administrative-access-best-practices")
PAN_BPA_AA_DEPLOY = f"Palo Alto Networks Best Practices — Deploy Administrative Access Best Practices ({AA_DEPLOY})"
HA_CONFIGURE = "docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/high-availability/set-up-activepassive-ha/configure-activepassive-ha"
PAN_HA_CONFIGURE = f"Palo Alto Networks PAN-OS Admin Guide — Configure Active/Passive HA ({HA_CONFIGURE})"
DOS_BP = ("docs.paloaltonetworks.com/best-practices/dos-and-zone-protection-best-practices/"
          "dos-and-zone-protection-best-practices")
PAN_BPA_DOS_DEPLOY = (f"Palo Alto Networks Best Practices — Deploy DoS and Zone Protection Using Best Practices "
                      f"({DOS_BP}/deploy-dos-and-zone-protection-using-best-practices)")
PAN_BPA_DOS_PLAN = (f"Palo Alto Networks Best Practices — Plan DoS and Zone Protection Best Practice Deployment "
                    f"({DOS_BP}/plan-dos-and-zone-protection-best-practice-deployment)")
PAN_DOS_CONFIGURE = ("Palo Alto Networks NGFW Administration — Configure DoS Protection Against Flooding of New "
                     "Sessions (docs.paloaltonetworks.com/ngfw/administration/zone-protection-and-dos-protection/"
                     "dos-protection-against-flooding-of-new-sessions/configure-dos-protection-against-flooding-of-"
                     "new-sessions)")
PAN_HELP_TCP = ("Palo Alto Networks PAN-OS Web Interface Help — Device > Setup > Session > TCP Settings "
                "(docs.paloaltonetworks.com/ngfw/help/11-1/device/device-setup-session/tcp-settings)")
PAN_WF_90_LIMITS = ("Palo Alto Networks WildFire — Increased WildFire File Forwarding Capacity (PAN-OS 9.0): "
                    "\"the new default capacities protect against the majority of threats, and is a best practice "
                    "to use the new default values\" (docs.paloaltonetworks.com/wildfire/u-v/wildfire-whats-new/"
                    "wildfire-features-in-panos-90/increased-wildfire-file-forwarding-capacity)")
PAN_WF_FORWARD = ("Palo Alto Networks Advanced WildFire — Forward Files for Advanced WildFire Analysis: \"Select "
                  "Report Grayware Files to allow logging for files that receive a verdict of grayware.\" "
                  "(docs.paloaltonetworks.com/advanced-wildfire/administration/configure-advanced-wildfire-analysis/"
                  "forward-files-for-advanced-wildfire-analysis)")
PAN_ADVISORIES = "Palo Alto Networks Security Advisories (security.paloaltonetworks.com)"
VPN_DOCS = "docs.paloaltonetworks.com/network-security/ipsec-vpn/administration"
PAN_VPN_IKE_CRYPTO = (f"Palo Alto Networks IPSec VPN Administration — Define IKE Crypto Profiles "
                      f"({VPN_DOCS}/set-up-site-to-site-vpn/define-cryptographic-profiles/define-ike-crypto-profiles)")
PAN_VPN_IPSEC_CRYPTO = (f"Palo Alto Networks IPSec VPN Administration — Define IPSec Crypto Profiles "
                        f"({VPN_DOCS}/set-up-site-to-site-vpn/define-cryptographic-profiles/define-ipsec-crypto-profiles)")
PAN_VPN_IKE_GATEWAY = (f"Palo Alto Networks IPSec VPN Administration — IKE Gateway "
                       f"({VPN_DOCS}/ipsec-vpn-basics/internet-key-exchange-ike-for-vpn/ike-gateway)")
GP_DOCS = "docs.paloaltonetworks.com/globalprotect/administration"
PAN_GP_2FA = (
    "Palo Alto Networks GlobalProtect Administration — Set Up Two-Factor Authentication: \"configure "
    "GlobalProtect to use an authentication service that uses a two-factor authentication scheme\" "
    f"({GP_DOCS}/globalprotect-user-authentication/set-up-two-factor-authentication)"
)
PAN_GP_AGENT_CONFIG = (
    "Palo Alto Networks GlobalProtect Administration — Define the GlobalProtect Agent Configurations "
    f"({GP_DOCS}/globalprotect-portals/define-the-globalprotect-app-configurations)"
)
PAN_GP_CUSTOMIZE_APP = (
    "Palo Alto Networks GlobalProtect Administration — Customize the GlobalProtect App "
    f"({GP_DOCS}/globalprotect-portals/customize-the-globalprotect-app)"
)
PAN_GP_ALWAYS_ON = (
    "Palo Alto Networks GlobalProtect Administration — Captive Portal and Enforce GlobalProtect for Network "
    "Access: \"To ensure that the GlobalProtect connection is always on, set the Connect Method to "
    "User-logon (Always On)\"; Customize the GlobalProtect App: On-demand is for \"external gateways only\" "
    f"({GP_DOCS}/globalprotect-quick-configs/captive-portal-and-enforce-globalprotect-for-network-access)"
)
PAN_BPA_PROFILES = (
    "Palo Alto Networks Best Practices — Create Best Practice Security Profiles for the Internet Gateway "
    "(docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/"
    "best-practice-internet-gateway-security-policy/create-best-practice-security-profiles)"
)

RULES: list[RuleDef] = [
    RuleDef(
        id="eol_pan_os_version",
        title="PAN-OS version is EOL or nearing EOL",
        category="Software",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Flags PAN-OS major versions below a configurable cutoff. "
                    "Only available in live mode (requires 'show system info').",
        thresholds={"eol_major_version": 10},
    ),
    RuleDef(
        id="license_expired",
        title="License expired",
        category="Licensing",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Only available in live mode (requires 'request license info').",
    ),
    RuleDef(
        id="license_expiring_soon",
        title="License expiring soon",
        category="Licensing",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Only available in live mode (requires 'request license info').",
        thresholds={"expiry_warning_days": 90},
    ),
    RuleDef(
        id="default_admin_account",
        title="Default 'admin' account exists",
        category="Access Control",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_ADMIN + ' — "replace the default account with a new local account '
                   'because the username admin is well known"',
        description="Flags presence of the factory-default 'admin' username.",
    ),
    RuleDef(
        id="admin_local_auth_no_mfa",
        title="Admin account uses local authentication (no MFA)",
        category="Access Control",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_ADMIN + " — configure Multi-Factor Authentication for all management access "
                   "other than the default local administrator account",
        description="Flags admin accounts with no authentication profile (RADIUS/SAML/LDAP) attached.",
    ),
    RuleDef(
        id="zone_missing_protection_profile",
        title="Zone has no Zone Protection Profile assigned",
        category="Network Security",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_ZONE_PROTECTION + " — apply Zone Protection Profiles as a layer of "
                   "broad, aggregate protection against flood/reconnaissance/packet-based attacks",
        description="A CIS PAN-OS benchmark also references Zone Protection Profile coverage, but a "
                    "specific control number couldn't be independently verified, so this cites the "
                    "vendor's own documented guidance instead.",
    ),
    RuleDef(
        id="zone_protection_no_recon",
        title="Zone Protection Profile has no reconnaissance protection",
        category="Network Security",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_ZONE_PROTECTION + ' — "enable Reconnaissance Protection on all zones to block '
                   'host sweeps, different types of scans, and other reconnaissance activities"',
        description="Flags a profile assigned to at least one zone that has no scan-detection entries, "
                    "or whose entries are all set to allow (detect but take no action).",
    ),
    RuleDef(
        id="zone_protection_recon_alert_only",
        title="Zone Protection Profile only alerts on reconnaissance scans",
        category="Network Security",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_ZONE_PROTECTION + " — set the Reconnaissance Protection action for TCP port scans, "
                   "host sweeps and UDP port scans to block-ip, not the default alert",
        description="Flags a profile assigned to at least one zone where any enabled scan type's action is "
                    "alert: the scan is logged, but the scanning host isn't blocked.",
    ),
    RuleDef(
        id="zone_protection_flood_disabled",
        title="Zone Protection Profile has a flood type explicitly disabled",
        category="Network Security",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_ZONE_PROTECTION + " — set alarm/activate/maximum thresholds to protect against "
                   "TCP SYN, UDP, ICMP, ICMPv6, and Other IP new-session floods",
        description="Only flags a flood type whose enable flag is explicitly 'no' in the config — Palo "
                    "Alto's schema declares no default for it, so an absent setting isn't assumed either way.",
    ),
    RuleDef(
        id="security_rule_any_any_any",
        title="Rule allows ANY source, ANY destination, ANY application",
        category="Security Policy",
        default_severity="CRITICAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "specify zones/addresses as narrowly as possible" and '
                   '"specify the exact functional applications you want"',
        description="The broadest possible allow rule shape — the direct opposite of PAN-OS BPA's "
                    "narrow-scoping guidance.",
    ),
    RuleDef(
        id="security_rule_missing_profile_non_infra",
        title="Non-infrastructure allow rule has no security profile group",
        category="Security Policy",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "attach a best practices profile to all allow rules '
                   '(Antivirus, Anti-Spyware, Vulnerability Protection, File Blocking, WildFire)"',
        description="Allow rules without AV/IPS/Anti-Spyware/URL profiles, excluding recognized "
                    "infrastructure protocols (BGP, IPSec, NTP, health probes, etc).",
    ),
    RuleDef(
        id="security_rule_missing_profile_infra",
        title="Infrastructure allow rule has no security profile group",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — same "attach a best practices profile to all allow rules" guidance, '
                   "lower severity here since these are recognized infra protocols",
        description="Lower severity than the non-infra version — often an intentional, documented exception.",
    ),
    RuleDef(
        id="security_rule_inbound_untrust_any_source",
        title="Inbound rule from untrust allows ANY source",
        category="Security Policy",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "specify addresses as narrowly as possible to prevent '
                   'unnecessary access"',
        description="Rule takes traffic from the untrust zone with source=any — exposed to the whole internet.",
    ),
    RuleDef(
        id="security_rule_app_any_service_any",
        title="Application=any and Service=any on a scoped rule",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "specify the exact functional applications you want"',
        description="Rule has specific source/destination but leaves application and service wide open.",
    ),
    RuleDef(
        id="security_rule_service_any",
        title="Service=any used instead of application-default",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "set the Service to application-default in most cases" '
                   "to prevent port-based evasion",
        description="Rule specifies applications but leaves the service/port field unrestricted.",
    ),
    RuleDef(
        id="security_rule_no_description",
        title="Allow rule has no description",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "Description: describes the purpose of the rule so that anyone '
                   'examining the rulebase can understand why it was created"',
        description="Documentation hygiene check for auditability.",
    ),
    RuleDef(
        id="security_rule_temp_test_name",
        title="Rule name suggests a temporary/test rule",
        category="Security Policy",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Keyword match on the rule name (temp, test, tmp, debug, old, backup). PAN-OS BPA's "
                    "actual guidance here is process-based (\"disable or remove rules when you no longer "
                    "need them\", reviewed periodically) rather than name-pattern detection, so this stays "
                    "tagged custom — it's a proxy for that goal, not an implementation of a documented check.",
    ),
    RuleDef(
        id="security_rule_no_logging_allow",
        title="Allow rule has logging disabled",
        category="Security Policy",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + " — log at session end to avoid logging transient applications",
        description="No audit trail for traffic matching this rule.",
    ),
    RuleDef(
        id="security_rule_no_log_forwarding",
        title="Rule has no Log Forwarding profile",
        category="Logging",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "ensure that every Security policy rule has a Log Forwarding '
                   'profile attached"',
        description="Without a Log Forwarding profile, the rule's traffic and threat logs stay on the "
                    "firewall's local disk and never reach Panorama, syslog, or a SIEM. Checks allow and "
                    "deny rules alike.",
    ),
    RuleDef(
        id="security_rule_deny_no_logging",
        title="Deny/drop rule has logging disabled",
        category="Logging",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="PAN-OS BPA documents logging the *implicit default* intrazone-allow/interzone-deny "
                    "rules specifically — this check instead targets admin-authored deny/drop rules, which "
                    "is a related but distinct target, so it stays custom rather than citing that guidance.",
    ),
    RuleDef(
        id="security_policy_no_deny_remaining",
        title="No enabled catch-all deny/drop-all rule at the bottom of the rulebase",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="PAN-OS already applies an implicit interzone-deny by default, and Palo Alto's own "
                    "guidance notes an explicit deny-all rule can have side effects on intrazone traffic — "
                    "so this is a defensible but not vendor-mandated hardening preference, kept custom "
                    "rather than cited as an official recommendation.",
    ),
    RuleDef(
        id="threat_profile_missing_antivirus",
        title="No Antivirus profiles defined",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — "attach a best practices profile to all allow rules '
                   '(Antivirus, Anti-Spyware, Vulnerability Protection, File Blocking, WildFire)"',
        description="No antivirus profile objects exist anywhere in the configuration.",
    ),
    RuleDef(
        id="threat_profile_missing_vulnerability",
        title="No Vulnerability Protection profiles defined",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — same "best practices profile" guidance',
        description="No vulnerability protection profile objects exist anywhere in the configuration.",
    ),
    RuleDef(
        id="threat_profile_missing_spyware",
        title="No Anti-Spyware profiles defined",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — same "best practices profile" guidance',
        description="No anti-spyware profile objects exist anywhere in the configuration.",
    ),
    RuleDef(
        id="threat_profile_missing_url_filtering",
        title="No URL Filtering profiles defined",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — same "best practices profile" guidance',
        description="No URL filtering profile objects exist anywhere in the configuration.",
    ),
    RuleDef(
        id="threat_profile_missing_file_blocking",
        title="No File Blocking profiles defined",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_RULE + ' — same "best practices profile" guidance',
        description="No File Blocking profile objects exist anywhere in the configuration.",
    ),
    RuleDef(
        id="wildfire_profile_missing",
        title="No WildFire analysis profiles configured",
        category="Security Profiles",
        default_severity="LOW",
        source_type="cis",
        source_ref="CIS Palo Alto Firewall Benchmark 5.3 — Ensure WildFire Analysis profile "
                   "is enabled for all security policies",
        description="Verified against public CIS PAN-OS benchmark section listings.",
    ),
    RuleDef(
        id="av_decoder_below_baseline",
        title="Antivirus decoder isn't set to reset-both",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends setting the action, WildFire action, and Machine "
                   "Learning action for the FTP/HTTP/HTTP2/IMAP/POP3/SMB/SMTP decoders to Reset Both",
        description="Flags any of the seven protocol decoders in an Antivirus profile where action, "
                    "WildFire action, or ML action isn't reset-both.",
    ),
    RuleDef(
        id="av_inline_ml_disabled",
        title="Antivirus Inline ML disabled for a file type",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends actively setting an enforcing action for Inline ML "
                   "across protocols/file types rather than leaving it off",
        description="Flags Inline ML file-type policies left at 'disable' in an Antivirus profile.",
    ),
    RuleDef(
        id="spyware_severity_below_baseline",
        title="Anti-Spyware critical/high/medium rule isn't set to reset",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends Reset Both with single-packet capture for "
                   "critical, high, and medium severity rules",
        description="Flags Anti-Spyware severity rules covering critical/high/medium severity whose "
                    "action isn't a reset variant.",
    ),
    RuleDef(
        id="spyware_dns_category_mismatch",
        title="DNS Security category doesn't match the BPA sinkhole baseline",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — documents a per-category table where malicious/suspicious "
                   "DNS Security categories should be set to Sinkhole",
        description="Checks each of Palo Alto's predefined DNS Security categories present in the "
                    "profile against the documented per-category sinkhole recommendation.",
    ),
    RuleDef(
        id="vulnerability_severity_below_baseline",
        title="Vulnerability Protection critical/high/medium rule isn't set to reset",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends Reset Both with single-packet capture for "
                   "critical, high, and medium severity rules (client and server)",
        description="Flags Vulnerability Protection severity rules covering critical/high/medium "
                    "severity whose action isn't a reset variant.",
    ),
    RuleDef(
        id="spyware_inline_cloud_analysis_disabled",
        title="Anti-Spyware Inline Cloud Analysis disabled (licensed firewall)",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — enable Inline Cloud Analysis in Anti-Spyware profiles (requires "
                   "an active Advanced Threat Prevention license)",
        description="Only runs when the firewall has an active Advanced Threat Prevention license — license "
                    "status comes from a tech support file or live connection, not a config export.",
    ),
    RuleDef(
        id="vulnerability_inline_cloud_analysis_disabled",
        title="Vulnerability Protection Inline Cloud Analysis disabled (licensed firewall)",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — enable Inline Cloud Analysis in Vulnerability Protection "
                   "profiles to block SQL and command injection (requires an active Advanced Threat "
                   "Prevention license)",
        description="Only runs when the firewall has an active Advanced Threat Prevention license — license "
                    "status comes from a tech support file or live connection, not a config export.",
    ),
    RuleDef(
        id="spyware_inline_cloud_model_not_reset",
        title="Anti-Spyware Inline Cloud Analysis model isn't set to reset-both",
        category="Security Profiles",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends setting all analysis model actions to Reset Both",
        description="Checks each analysis model in a profile with Inline Cloud Analysis enabled. An unset "
                    "action counts as alert, PAN-OS's schema default. Licensed firewalls only.",
    ),
    RuleDef(
        id="vulnerability_inline_cloud_model_not_reset",
        title="Vulnerability Protection Inline Cloud Analysis model isn't set to reset-both",
        category="Security Profiles",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends setting the Inline Cloud Analysis action to Reset Both",
        description="Checks each analysis model in a profile with Inline Cloud Analysis enabled. An unset "
                    "action counts as alert, PAN-OS's schema default. Licensed firewalls only.",
    ),
    RuleDef(
        id="url_mandatory_category_not_blocked",
        title="URL Filtering profile doesn't block a mandatory category",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — lists command-and-control, compromised-website, grayware, "
                   "malware, phishing, ransomware, and scanning-activity as categories to block site "
                   "access and credential submission",
        description="Flags any of these seven categories missing from the profile's block list.",
    ),
    RuleDef(
        id="url_elevated_risk_category_not_blocked",
        title="URL Filtering profile doesn't block an elevated-risk category",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — treats the elevated-risk tier (dynamic-dns, encrypted-dns, "
                   "hacking, insufficient-content, newly-registered-domain, not-resolved, parked, "
                   "unknown, proxy-avoidance-and-anonymizers) as block, not alert",
        description="Flags any of these nine categories missing from the profile's block list.",
    ),
    RuleDef(
        id="url_credential_enforcement_disabled",
        title="URL Filtering credential-submission enforcement is disabled",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends enabling credential-submission enforcement, "
                   "scoped to malicious categories",
        description="Flags a profile whose credential-enforcement mode is disabled.",
    ),
    RuleDef(
        id="file_blocking_nothing_blocked",
        title="File Blocking profile has no rule set to block",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — the predefined 'strict' File Blocking profile blocks batch, "
                   "DLL, .lnk, .rar/.tar, encrypted-zip, multilevel-encoded, .hta, and PE files",
        description="Flags a File Blocking profile where every rule's action is alert or continue — "
                    "the profile exists but nothing is actually blocked.",
    ),
    RuleDef(
        id="wildfire_missing_recommended_filetype",
        title="WildFire profile doesn't submit a commonly-recommended file type",
        category="Security Profiles",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_PROFILES + " — recommends covering PE, Flash, PDF, Office, Java/.class, "
                   "and APK file types",
        description="Flags a WildFire profile missing pdf or ms-office from its file-type list. Worded "
                    "as a prompt to confirm rather than a hard violation — excluding these is sometimes "
                    "a deliberate call to avoid sending sensitive documents to a public cloud sandbox.",
    ),
    RuleDef(
        id="decryption_no_outbound",
        title="Outbound traffic isn't decrypted",
        category="Decryption",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_DECRYPTION + ' — "decrypt as much traffic as local regulations and business '
                   'requirements allow so you can inspect the traffic and block threats"',
        description="Flags a config with no enabled SSL Forward Proxy decrypt rule — the rule type that "
                    "decrypts users' outbound traffic. Inbound-inspection rules (traffic to your own servers) "
                    "don't count. Dismiss it on a firewall with no users behind it, such as a pure data-center "
                    "edge.",
    ),
    RuleDef(
        id="decryption_no_best_practice_profile",
        title="Outbound decryption doesn't use a best-practice profile",
        category="Decryption",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_DECRYPTION,
        description="Flags a config whose enabled SSL Forward Proxy decrypt rules all use a weak decryption "
                    "profile, or none: one that allows TLS below 1.2, or doesn't block expired certificates and "
                    "untrusted issuers. Follows Palo Alto SCM check #350.",
    ),
    RuleDef(
        id="decryption_profile_weak_tls",
        title="Decryption profile allows TLS versions below 1.2",
        category="Decryption",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_DECRYPTION + " — for SSL Forward Proxy, set the minimum protocol version to "
                   "TLSv1.2 and the maximum version to Max to block weak protocols",
        description="Checks decryption profiles used by an enabled decrypt rule. An unset minimum version "
                    "counts as TLSv1.0 — that's PAN-OS's own schema default.",
    ),
    RuleDef(
        id="decryption_profile_cert_checks_disabled",
        title="Decryption profile doesn't block bad server certificates",
        category="Decryption",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_DECRYPTION + " — block sessions with expired certificates and untrusted "
                   "issuers; untrusted issuers may indicate meddler-in-the-middle or other attacks",
        description="Checks the SSL Forward Proxy settings of profiles used by an enabled forward-proxy "
                    "decrypt rule. Only flags an explicit 'no' — the schema declares no default.",
    ),
    RuleDef(
        id="decryption_no_decrypt_cert_checks",
        title="Traffic excluded from decryption isn't checked for bad server certificates",
        category="Decryption",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_BPA_DECRYPTION + " — apply a No Decryption profile that blocks sessions with expired "
                   "certificates and untrusted issuers, even for traffic you don't decrypt",
        description="For each enabled no-decrypt rule: flags a rule with no decryption profile, and a "
                    "profile whose No Decryption settings explicitly don't block expired certificates or "
                    "untrusted issuers. Palo Alto notes the certificate isn't visible in TLS 1.3, so these "
                    "blocks only apply to TLS 1.2 and earlier sessions.",
    ),
    RuleDef(
        id="mgmt_profile_cleartext",
        title="Interface management profile allows Telnet or HTTP",
        category="Device Hardening",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_ADMIN + ' — "never enable HTTP or Telnet access because those protocols '
                   'transmit in cleartext"',
        description="Flags an Interface Management profile attached to at least one data-plane interface "
                    "that enables Telnet or HTTP — admin credentials cross the network unencrypted.",
    ),
    RuleDef(
        id="mgmt_interface_open_to_any_source",
        title="Management services on a data interface reachable from any source",
        category="Device Hardening",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_ADMIN + ' — "do not enable management access (HTTP, HTTPS, SSH, or Telnet) from the '
                   'internet or from other untrusted zones"; specify the IP addresses allowed to access the '
                   'firewall rather than leaving the list empty',
        description="Checks both layers that gate management access to an interface: the management "
                    "profile's permitted-IP list, and security policy from each zone to the interface's own "
                    "zone, walked top-down first-match (a catch-all deny ends the walk; the implicit "
                    "intrazone/interzone defaults only decide if nothing else matched). Flags only when there "
                    "is no permitted-IP list AND policy definitely allows any source. Results that depend on "
                    "objects that can't be resolved (dynamic groups, FQDNs, app filters) are shown as "
                    "uncertain on the dashboard, not flagged.",
    ),
    RuleDef(
        id="no_syslog_profile",
        title="No syslog server profiles configured",
        category="Logging",
        default_severity="WARNING",
        source_type="cis",
        source_ref="CIS Palo Alto Firewall Benchmark 1.1.1.1 — Syslog logging should be configured",
        description="Verified against public CIS PAN-OS benchmark section listings.",
    ),
    RuleDef(
        id="ha_not_synced",
        title="HA sync status is not synchronized",
        category="High Availability",
        default_severity="WARNING",
        source_type="cis",
        source_ref="CIS Palo Alto Firewall Benchmark 3.1 — Ensure fully-synchronized "
                   "High Availability peer is configured",
        description="Only available in live mode (requires 'show high-availability state').",
    ),
    RuleDef(
        id="ha_config_sync_disabled",
        title="HA configuration synchronization is off",
        category="High Availability",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_HA_CONFIGURE + ": \"Select Enable Config Sync. This setting enables the synchronization of "
                   "the configuration settings between the active and the passive firewall.\"",
        description="With config sync off the HA peers drift apart, so a failover can land on a firewall running "
                    "different policy.",
    ),
    RuleDef(
        id="ha_session_sync_disabled",
        title="HA session synchronization is off",
        category="High Availability",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_HA_CONFIGURE + ": \"Verify that Enable Session Synchronization is selected.\"",
        description="Without session sync the peer has no session table, so every connection drops on failover.",
    ),
    RuleDef(
        id="ha2_keepalive_disabled",
        title="HA2 keep-alive is off",
        category="High Availability",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_HA_CONFIGURE + ": \"(Best Practices) Enable and configure HA2 Keep-alive to monitor the "
                   "health of the HA2 data link between the HA peers.\"",
        description="Without keep-alives a failed HA2 data link goes unnoticed and session sync silently stops.",
    ),
    RuleDef(
        id="ha1_encryption_disabled",
        title="HA1 control link isn't encrypted",
        category="High Availability",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_HA_CONFIGURE + ": \"Select Encryption Enabled.\"",
        description="HA1 carries configuration and state between the peers, including secrets, in clear text "
                    "unless encryption is on.",
    ),
    RuleDef(
        id="ha1_no_backup",
        title="No HA1 backup control link",
        category="High Availability",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_HA_CONFIGURE + ": \"edit Control Link (HA1 Backup). Select the HA1 backup interface and "
                   "set the IPv4/IPv6 Address and Netmask.\"",
        description="No backup peer address is set for HA1, so losing the one control link leaves both peers "
                    "believing they are active (split brain).",
    ),
    RuleDef(
        id="ha_heartbeat_backup_off",
        title="HA heartbeat backup is off",
        category="High Availability",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_HA_CONFIGURE + ": \"Select Heartbeat Backup. To allow the heartbeats to be transmitted "
                   "between the firewalls, you must verify that the management port across both peers can route "
                   "to each other.\"",
        description="HA1 runs on a dedicated or dataplane port, so heartbeats have no path over the management "
                    "port if that link fails. Not flagged when HA1 already uses the management port.",
    ),
    RuleDef(
        id="ha_passive_link_state_shutdown",
        title="Passive link state is Shutdown, not Auto",
        category="High Availability",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_HA_CONFIGURE + ": \"Setting the link state to Auto allows for reducing the amount of time "
                   "it takes for the passive firewall to take over when a failover occurs.\"",
        description="Active/passive only. With Shutdown the passive firewall's links are down, so neighbours "
                    "must bring them up and re-learn before traffic moves on failover.",
    ),
    RuleDef(
        id="ha_no_monitoring",
        title="HA doesn't monitor any links or paths",
        category="High Availability",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="No link group with interfaces and no path group is configured, so the firewall won't fail "
                    "over when a data interface or upstream path goes down. Follows Palo Alto SCM checks #149, "
                    "#150 and #151.",
    ),
    RuleDef(
        id="ha_active_active_incomplete",
        title="Active/active HA is missing HA3 or first-packet session ownership",
        category="High Availability",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Active/active peers need an HA3 link to forward packets for asymmetric sessions, and "
                    "session owner selection should be First Packet. Follows Palo Alto SCM checks #147 and #148.",
    ),
    RuleDef(
        id="mgmt_no_acl",
        title="Management interface has no permitted-ip restriction",
        category="Device Hardening",
        default_severity="WARNING",
        source_type="cis",
        source_ref="CIS Palo Alto Firewall Benchmark 1.2.1 — Ensure 'Permitted IP Addresses' "
                   "is set for device management",
        description="Verified against public CIS PAN-OS benchmark section listings.",
    ),
    # ── Management plane ──────────────────────────────────────────────────
    RuleDef(
        id="admin_lockout_weak",
        title="Administrator lockout is weak or off",
        category="Access Control",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_AA_DEPLOY + ": \"specify a number of Failed Attempts to prevent brute force attempts to "
                   "log in, and specify a Lockout Time to prevent further immediate access attempts\"",
        description="Device > Setup > Management > Authentication Settings: Failed Attempts is 0 (never locks) or "
                    "above the threshold, or Lockout Time is shorter than the threshold (0 = until an admin "
                    "unlocks it, which is fine). Thresholds follow Palo Alto's SCM checks #95 and #96.",
        thresholds={"max_failed_attempts": 5, "min_lockout_minutes": 30},
    ),
    RuleDef(
        id="admin_idle_timeout_long",
        title="Administrator idle timeout is too long",
        category="Access Control",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_AA_DEPLOY + ": \"Configure a login timeout (Idle Timeout) to prevent administrators "
                   "from leaving idle sessions open too long\"",
        description="Idle admin sessions stay open longer than the threshold (PAN-OS default 60 minutes; 0 = never).",
        thresholds={"max_idle_timeout_minutes": 15},
    ),
    RuleDef(
        id="api_key_no_lifetime",
        title="API keys never expire",
        category="Access Control",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_AA_DEPLOY + ": \"If you allow API access, Configure API Key Lifetime ... to enforce "
                   "regular key rotation\"",
        description="API Key Lifetime is unset or 0, so a leaked API key works forever.",
    ),
    RuleDef(
        id="password_complexity_weak",
        title="Minimum password complexity is off or short",
        category="Access Control",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Device > Setup > Management > Minimum Password Complexity isn't enabled, or its minimum "
                    "length is below the threshold (Palo Alto SCM check #103 asks for it to be enabled).",
        thresholds={"min_length": 12},
    ),
    RuleDef(
        id="mgmt_tls_below_1_2",
        title="Management web interface accepts TLS below 1.2",
        category="Access Control",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_AA_DEPLOY + ": for the management SSL/TLS Service Profile \"Set the Min Version to "
                   "TLSv1.2 and the Max Version to Max\"",
        description="The SSL/TLS service profile on the management interface allows TLS 1.0 or 1.1.",
    ),
    RuleDef(
        id="snmp_v2c",
        title="SNMPv2c in use instead of SNMPv3",
        category="Access Control",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_AA_DEPLOY + ": \"For SNMP access, if your infrastructure supports it, use SNMPv3 "
                   "instead of SNMPv2c\"",
        description="SNMP polling or an SNMP trap profile uses v2c (cleartext community strings, no per-user "
                    "access control); flagged louder when the community is the default 'public'.",
    ),
    RuleDef(
        id="ldap_profile_no_tls",
        title="LDAP server profile doesn't use or verify TLS",
        category="Access Control",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="\"Require SSL/TLS secured connection\" is off, so bind credentials and lookups cross the "
                    "network in cleartext, or the server certificate isn't verified (Palo Alto SCM #186, #187).",
    ),
    RuleDef(
        id="radius_weak_protocol",
        title="RADIUS server profile uses PAP or CHAP",
        category="Access Control",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="RADIUS authentication uses PAP or CHAP instead of an EAP method (EAP-TTLS with PAP, "
                    "PEAP-MSCHAPv2 or PEAP with GTC) that tunnels the credentials (Palo Alto SCM #233).",
    ),
    RuleDef(
        id="tacacs_pap",
        title="TACACS+ server profile uses PAP",
        category="Access Control",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="TACACS+ authentication uses PAP instead of CHAP (Palo Alto SCM #234).",
    ),
    RuleDef(
        id="syslog_not_tls",
        title="Syslog is sent without TLS",
        category="Logging",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A syslog server profile sends logs over UDP or TCP, so they can be read or altered in "
                    "transit (Palo Alto SCM #185 asks for SSL transport).",
    ),
    RuleDef(
        id="system_logs_not_forwarded",
        title="System logs aren't forwarded",
        category="Logging",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_AA_DEPLOY + ": \"Configure System logs and use Log Forwarding to send them to an "
                   "external server for auditing and monitoring\"",
        description="No System log setting forwards anywhere (syslog, SNMP trap, email, HTTP or Panorama).",
    ),
    RuleDef(
        id="config_logs_not_forwarded",
        title="Configuration logs aren't forwarded",
        category="Logging",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_AA_DEPLOY + ": \"Configure Administrator Activity Tracking and send the logs to an "
                   "external server for auditing and monitoring\"",
        description="No Configuration log setting forwards anywhere, so admin changes are only recorded on the "
                    "firewall itself.",
    ),
    RuleDef(
        id="content_updates_not_timely",
        title="Content updates aren't installed automatically and often",
        category="Software",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Antivirus should download-and-install hourly, Applications and Threats at least daily, and "
                    "WildFire in real time (or every minute), following Palo Alto SCM checks #188, #189 and #190.",
    ),
    # ── DoS & session protection ─────────────────────────────────────────
    RuleDef(
        id="dos_no_protection",
        title="No DoS Protection policy protects anything",
        category="DoS Protection",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_DOS_PLAN + ": \"Apply classified DoS Protection profiles and policies to protect "
                   "individual or small groups of high-value targets\"",
        description="There's no enabled DoS Protection rule with the Protect action and a profile, so critical "
                    "servers rely on zone-wide flood thresholds alone.",
    ),
    RuleDef(
        id="dos_rule_not_protect",
        title="DoS Protection rule doesn't apply protection",
        category="DoS Protection",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_DOS_DEPLOY + ": \"Select Protect to apply the rule's DoS Protection profile(s) to the "
                   "specified devices. Protect is the only Action that applies DoS Protection.\"",
        description="The rule's action is Allow or Deny, or it's Protect with no DoS Protection profile attached.",
    ),
    RuleDef(
        id="dos_profile_flood_incomplete",
        title="DoS Protection profile doesn't cover every flood type",
        category="DoS Protection",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_DOS_CONFIGURE + ": \"Because flood attacks can occur over multiple protocols, as a best "
                   "practice, activate protection for all of the flood types in the DoS Protection profile.\"",
        description="Checks SYN, UDP, ICMP, ICMPv6 and Other IP flood protection.",
    ),
    RuleDef(
        id="dos_profile_default_thresholds",
        title="DoS Protection flood thresholds were never tuned",
        category="DoS Protection",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Every enabled flood type still has the pre-filled alarm, activate and maximum rates, which "
                    "suggests no one measured the protected servers' normal connection rate. Follows Palo Alto "
                    "SCM check #50.",
    ),
    RuleDef(
        id="zone_protection_packet_based_off",
        title="Zone Protection Profile leaves packet-based attack protection off",
        category="Network Security",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_DOS_DEPLOY + ": \"IP Drop—Drop Unknown and Malformed packets. Drop Strict Source "
                   "Routing and Loose Source Routing packets\" ... \"drop Spoofed IP address packets\" ... "
                   "\"TCP Drop—...select Mismatched overlapping TCP segment and Split Handshake, and enable the "
                   "strip option TCP Timestamp.\"",
        description="Flags a profile assigned to at least one zone that leaves any of these off: spoofed IP, "
                    "strict/loose source routing, malformed and unknown IP options, mismatched overlapping TCP "
                    "segments, TCP split handshake, and stripping the TCP timestamp.",
    ),
    RuleDef(
        id="zone_packet_buffer_protection_off",
        title="Packet Buffer Protection is turned off on a zone",
        category="DoS Protection",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Packet Buffer Protection stops a single session or source from filling the firewall's "
                    "packet buffers. It's on for every zone by default since PAN-OS 10.0; this flags zones where "
                    "it was turned off.",
    ),
    RuleDef(
        id="session_rematch_disabled",
        title="Existing sessions aren't re-checked after policy changes",
        category="Device Hardening",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="With Rematch Sessions off, a connection that a new or tightened rule should block keeps "
                    "running until it closes. It's on by default.",
    ),
    RuleDef(
        id="tcp_forward_oo_queue",
        title="Firewall forwards TCP segments past the out-of-order queue",
        category="Device Hardening",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_HELP_TCP + ": Forward segments exceeding TCP out-of-order queue — \"This option is "
                   "disabled by default and should remain this way for the most secure deployment.\"",
        description="Segments beyond the 64-segment out-of-order queue are forwarded without inspection, which "
                    "attackers can use to slip content past App-ID and threat prevention.",
    ),
    # ── Device & session settings (ported from Palo Alto SCM checks) ──────
    RuleDef(
        id="session_timeout_changed",
        title="A session timeout differs from the PAN-OS default",
        category="Device Hardening",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Longer timeouts keep idle sessions in the table and give attackers longer to reuse them; "
                    "shorter ones can break applications. Change them only for a documented application need. "
                    "Follows Palo Alto SCM checks #122–#134.",
    ),
    RuleDef(
        id="session_accelerated_aging_off",
        title="Accelerated aging is turned off",
        category="DoS Protection",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Accelerated aging ages out idle sessions faster as the session table fills, keeping room "
                    "for new sessions under load. It's on by default. Follows Palo Alto SCM check #121.",
    ),
    RuleDef(
        id="packet_buffer_protection_global_off",
        title="Global Packet Buffer Protection is turned off",
        category="DoS Protection",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Global Packet Buffer Protection stops a single session or source from exhausting the "
                    "firewall's packet buffers; zone-level protection depends on it. It's on by default since "
                    "PAN-OS 10.0. Follows Palo Alto SCM check #213.",
    ),
    RuleDef(
        id="cert_expiration_check_off",
        title="Certificate expiration checking is off",
        category="Device Hardening",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="With the check off, the firewall doesn't warn before its certificates (decryption CA, "
                    "GlobalProtect, management) expire, so expiry shows up as an outage. Follows Palo Alto SCM "
                    "check #89.",
    ),
    RuleDef(
        id="log_high_dp_load_off",
        title="No System log entry when the dataplane is overloaded",
        category="Logging",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Enable Log on High DP Load writes a System log when packet processing reaches 100%, so "
                    "overload (including a DoS in progress) is visible. Follows Palo Alto SCM check #97.",
    ),
    RuleDef(
        id="telemetry_disabled",
        title="Telemetry sharing with Palo Alto Networks is off",
        category="Device Hardening",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Device health, product usage and threat prevention telemetry feed Palo Alto's health "
                    "reporting and threat research. Turning it off is a privacy choice; noted for visibility. "
                    "Follows Palo Alto SCM check #197.",
    ),
    RuleDef(
        id="update_server_verification_off",
        title="Update server identity isn't verified",
        category="Software",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Without Verify Update Server Identity the firewall accepts content and software updates "
                    "from a server whose certificate it hasn't checked, allowing a spoofed update source. On by "
                    "default. Follows Palo Alto SCM check #104.",
    ),
    RuleDef(
        id="mgmt_interface_cleartext",
        title="Management interface allows HTTP or Telnet",
        category="Device Hardening",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_ADMIN + ' — "never enable HTTP or Telnet access because those protocols '
                   'transmit in cleartext"',
        description="The dedicated management interface's services enable HTTP or Telnet, so admin credentials "
                    "and sessions cross the network unencrypted.",
    ),
    RuleDef(
        id="ha_timers_not_recommended",
        title="HA timers aren't set to Recommended",
        category="High Availability",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Aggressive or Advanced timers change failover detection. That can be deliberate, so "
                    "this is informational; Recommended is the PAN-OS default. Follows Palo Alto SCM check #142.",
    ),
    RuleDef(
        id="gre_keepalive_off",
        title="GRE tunnel has keep-alive off",
        category="VPN",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Without keep-alives the firewall doesn't notice the peer is down and keeps routing "
                    "traffic into a dead tunnel. Follows Palo Alto SCM check #246.",
    ),
    RuleDef(
        id="pbf_no_monitor",
        title="Policy-based forwarding rule doesn't monitor its next hop",
        category="Network Security",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A forwarding rule with no monitor profile keeps sending traffic to a failed next hop "
                    "instead of failing over. Follows Palo Alto SCM check #17.",
    ),
    RuleDef(
        id="app_override_rule",
        title="Application Override rule bypasses App-ID and threat inspection",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Traffic matching an Application Override rule skips App-ID and Content-ID, so threat "
                    "prevention, file blocking and URL filtering don't inspect it. Prefer a custom App-ID "
                    "signature. Follows Palo Alto SCM check #21.",
    ),
    # ── WildFire (ported from Palo Alto SCM checks) ─────────────────────────
    RuleDef(
        id="wildfire_size_limit_below_default",
        title="WildFire forwards only small files of some types",
        category="Security Profiles",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_WF_90_LIMITS,
        description="A file type's WildFire forwarding size limit is set below the PAN-OS default, so larger "
                    "files of that type are never analysed. Limits above the default are allowed and not flagged.",
    ),
    RuleDef(
        id="wildfire_grayware_not_reported",
        title="WildFire doesn't report grayware",
        category="Logging",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_WF_FORWARD,
        description="Without Report Grayware Files, adware and other grayware verdicts leave no WildFire "
                    "Submissions log entry to investigate.",
    ),
    RuleDef(
        id="wildfire_inline_cloud_analysis_disabled",
        title="WildFire profile has Inline Cloud Analysis off",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Inline Cloud Analysis sends suspicious files to Advanced WildFire's real-time engines and "
                    "blocks them in line instead of after a verdict. Only checked when the firewall has an "
                    "Advanced WildFire license (upload a tech support file so the license is known). Follows "
                    "Palo Alto SCM check #363.",
    ),
    RuleDef(
        id="wildfire_realtime_hold_off",
        title="Antivirus doesn't hold files for WildFire real-time signature lookup",
        category="Security Profiles",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Without hold mode a file is delivered while the firewall is still asking WildFire's "
                    "real-time signature cloud about it, so a brand-new malware signature arrives too late. "
                    "PAN-OS 11.0.2+ with a WildFire or Advanced WildFire license; hold mode must also be enabled "
                    "globally (Device > Setup > Content-ID). Follows Palo Alto SCM check #347.",
    ),
    # ── Security profile hygiene (ported from Palo Alto SCM checks) ─────────
    RuleDef(
        id="profile_threat_exceptions",
        title="Security profile has threat or application exceptions",
        category="Security Profiles",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="An exception stops the profile acting on a signature (or, in Antivirus, on an application). They're meant as a temporary fix for a false positive while Palo Alto TAC corrects the signature, then removed. Follows Palo Alto SCM checks #31, #32, #36 and #41.",
    ),
    RuleDef(
        id="av_packet_capture",
        title="Antivirus profile captures packets",
        category="Security Profiles",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Packet capture on a widely used profile costs firewall resources; enable it on a dedicated profile for the few rules you're investigating. Follows Palo Alto SCM check #35.",
    ),
    RuleDef(
        id="url_log_container_page_only",
        title="URL Filtering logs only container pages",
        category="Logging",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description='With Log Container Page Only, the URL log skips everything after the page itself (uploads, posts, downloads), which hides what users actually did. Follows Palo Alto SCM check #44.',
    ),
    RuleDef(
        id="url_categories_allowed_unlogged",
        title="URL Filtering allows categories without logging",
        category="Logging",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Categories set to Allow leave no URL log entry, so there's nothing to investigate later. Alert allows the traffic and logs it. Follows Palo Alto SCM check #196.",
    ),
    RuleDef(
        id="url_credential_detection_not_domain",
        title="Credential phishing detection doesn't use the domain credential filter",
        category="Security Profiles",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description='User Credential Detection is on but uses IP-user or group mapping rather than the domain credential filter, which checks submitted passwords against real corporate credentials via the User-ID agent. Follows Palo Alto SCM check #227.',
    ),
    RuleDef(
        id="url_credential_submissions_unlogged",
        title="Credential submissions are allowed without logging",
        category="Logging",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description='Categories whose user-credential submission action is Allow leave no log when a user enters corporate credentials on a site. Alert allows and logs it. Follows Palo Alto SCM check #346.',
    ),
    RuleDef(
        id="url_inline_categorization_off",
        title="URL Filtering has cloud inline categorization off",
        category="Security Profiles",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Cloud inline categorization analyses pages in real time to catch new phishing and malicious sites before they're categorized. Only checked with an active Advanced URL Filtering license (upload a tech support file). Follows Palo Alto SCM check #273.",
    ),
    RuleDef(
        id="decryption_inbound_checks_off",
        title="Inbound decryption profile lets unsupported or failed sessions through",
        category="Decryption",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A profile used by an SSL Inbound Inspection rule doesn't block sessions with unsupported versions or ciphers, or sessions that fail for lack of resources or HSM. Those sessions pass uninspected. Follows Palo Alto SCM check #56.",
    ),
    RuleDef(
        id="decryption_ssh_checks_off",
        title="SSH Proxy profile lets unsupported or failed sessions through",
        category="Decryption",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A profile used by an SSH Proxy rule doesn't block unsupported SSH versions or algorithms, SSH errors, or sessions the firewall can't decrypt for lack of resources. Follows Palo Alto SCM check #59.",
    ),
    RuleDef(
        id="decryption_weak_hmac",
        title="Decryption profile allows SHA-1 or MD5 message authentication",
        category="Decryption",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description='A profile used by a decryption rule still allows HMAC-SHA1 or MD5 cipher suites. Allow only SHA-256 and SHA-384. SHA-1 is allowed by default. Follows Palo Alto SCM check #372.',
    ),
    RuleDef(
        id="log_forwarding_profile_no_destination",
        title="Log Forwarding profile forwards nowhere",
        category="Logging",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='A Log Forwarding profile that security rules use has no Panorama, syslog, email, SNMP or HTTP destination, so logs stay on the firewall and roll over. Follows Palo Alto SCM check #51.',
    ),
    RuleDef(
        id="log_forwarding_profile_missing_types",
        title="Log Forwarding profile skips threat, WildFire, URL or authentication logs",
        category="Logging",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A Log Forwarding profile that security rules use doesn't forward every security-relevant log type to an external destination. Follows Palo Alto SCM checks #52, #53, #259 and #260.",
    ),
    # ── Security rule hygiene (ported from Palo Alto SCM checks) ───────────
    RuleDef(
        id="security_rule_log_at_start",
        title="Security rule logs at session start",
        category="Logging",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Logging at session start records the application before App-ID has settled on it and costs extra firewall resources. Log at session end unless you're troubleshooting. Follows Palo Alto SCM check #6.",
    ),
    RuleDef(
        id="security_rule_server_response_inspection_off",
        title="Allow rule skips server response inspection",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='Disable Server Response Inspection stops the firewall inspecting server-to-client traffic, so threats in responses go unseen. Only for a trusted server where performance requires it. Follows Palo Alto SCM check #9.',
    ),
    RuleDef(
        id="default_rule_not_logged",
        title="Default intrazone or interzone rule doesn't log",
        category="Logging",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="The predefined intrazone-default (allow) and interzone-default (deny) rules don't log at session end unless overridden, so traffic they handle is invisible. Follows Palo Alto SCM checks #12 and #13.",
    ),
    RuleDef(
        id="user_id_zone_disabled",
        title="Rules match users in a zone without User-ID",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="An allow rule matches specific users or groups, but its source zone doesn't have User-ID enabled, so the firewall can't map traffic from that zone to users and the rule doesn't match as intended. Follows Palo Alto SCM check #16.",
    ),
    RuleDef(
        id="no_new_appid_rule",
        title="No rule handles App-IDs from new content updates",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description='No enabled allow rule uses an application filter with New App-ID set. Without one, traffic that a new content release reclassifies to a new App-ID can suddenly be blocked. Follows Palo Alto SCM check #249.',
    ),
    RuleDef(
        id="advanced_profile_not_applied",
        title="A licensed advanced security service isn't applied to any rule",
        category="Security Profiles",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="The firewall is licensed for Advanced URL Filtering, Advanced Threat Prevention or Advanced WildFire, but no rule uses a profile with that service's cloud analysis on. Only checked when the licenses are known (tech support file). Follows Palo Alto SCM checks #366, #367, #368 and #370.",
    ),
    # ── Authentication, User-ID & services (ported from Palo Alto SCM checks) ─
    RuleDef(
        id="ssl_tls_profile_weak",
        title="SSL/TLS service profile allows TLS below 1.2",
        category="Device Hardening",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="An SSL/TLS service profile's minimum version is below TLSv1.2, or its maximum isn't Max, so services using it (web UI, GlobalProtect, Authentication Portal, User-ID) can negotiate weak or outdated TLS. Follows Palo Alto SCM check #63.",
    ),
    RuleDef(
        id="admin_no_custom_roles",
        title="No custom admin roles are defined",
        category="Access Control",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description='Without custom admin roles every administrator gets a built-in dynamic role such as superuser, with more access than most need. Follows Palo Alto SCM check #154.',
    ),
    RuleDef(
        id="auth_profile_local_only",
        title="Authentication profile uses only the local database",
        category="Access Control",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Local-database authentication isn't centrally managed or logged; use LDAP, RADIUS, TACACS+, SAML or Kerberos. Follows Palo Alto SCM check #155.",
    ),
    RuleDef(
        id="auth_sequence_single_profile",
        title="Authentication sequence has no fallback profile",
        category="Access Control",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description='An authentication sequence with a single profile gives no fallback when that authentication server is unreachable. Follows Palo Alto SCM check #159.',
    ),
    RuleDef(
        id="user_id_client_probing",
        title="User-ID client probing is on",
        category="Access Control",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='Client probing sends WMI/NetBIOS probes, which can leak credential hashes if misconfigured to reach untrusted networks. Use server monitoring or other sources instead. Follows Palo Alto SCM check #164.',
    ),
    RuleDef(
        id="user_id_timeout_disabled",
        title="User-ID mapping timeout is off",
        category="Access Control",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Without a timeout, stale IP-to-user mappings never expire, so a new user of that IP inherits the previous user's policy. Follows Palo Alto SCM check #165.",
    ),
    RuleDef(
        id="auth_portal_transparent",
        title="Authentication Portal uses Transparent mode",
        category="Access Control",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description='Transparent mode impersonates the destination site, so users see certificate errors; Redirect mode avoids them and supports session cookies. Follows Palo Alto SCM check #172.',
    ),
    RuleDef(
        id="auth_portal_long_session",
        title="Authentication Portal sessions last longer than 8 hours",
        category="Access Control",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="An Authentication Portal timer or session cookie longer than 480 minutes keeps a user authenticated on a device long after they've left it. Follows Palo Alto SCM check #173.",
    ),
    RuleDef(
        id="auth_portal_weak_tls",
        title="Authentication Portal has no strong SSL/TLS service profile",
        category="Access Control",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='The Authentication Portal has no SSL/TLS service profile, or its profile allows TLS below 1.2. Follows Palo Alto SCM check #174.',
    ),
    RuleDef(
        id="system_logs_high_severity_only",
        title="Only high-severity System logs are forwarded",
        category="Logging",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description='System logs are forwarded, but every match list filters out low and informational events, which are useful for health history and investigations. Follows Palo Alto SCM check #177.',
    ),
    RuleDef(
        id="content_updates_gp_not_hourly",
        title="GlobalProtect content updates aren't installed hourly",
        category="Software",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description='With GlobalProtect in use, the GlobalProtect Data File (HIP vendor data) and Clientless VPN content should download-and-install hourly. Follows Palo Alto SCM checks #194 and #195.',
    ),
    RuleDef(
        id="ldap_single_server",
        title="LDAP server profile has only one server",
        category="Access Control",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="With one LDAP server, authentication and group mapping stop when it's unreachable. Follows Palo Alto SCM check #199.",
    ),
    RuleDef(
        id="secure_client_cert_predefined",
        title="Secure client communication uses the predefined certificate",
        category="Device Hardening",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="The firewall authenticates to Panorama, log collectors and User-ID agents with Palo Alto's predefined certificate rather than a local or SCEP certificate from your PKI. Follows Palo Alto SCM check #223.",
    ),
    # ── Advanced IP Defense (license-gated), Gen AI, liability & post-quantum ─
    RuleDef(
        id="aipd_c2_not_blocked",
        title="Advanced IP Defense C2 list isn't blocked",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='No enabled deny rule uses the predefined panw-aipd-c2-infra-ip-list (C2 infrastructure) as the source for inbound and as the destination for outbound traffic. Only checked with an active Advanced IP Defense license (upload a tech support file). Follows Palo Alto SCM checks #398 and #399.',
    ),
    RuleDef(
        id="aipd_malware_ip_not_blocked",
        title="Advanced IP Defense malware IP list isn't blocked",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='No enabled deny rule uses the predefined panw-aipd-in-malware-ip-list (IPs hardcoded in malware) inbound and outbound. Only checked with an active Advanced IP Defense license (upload a tech support file). Follows Palo Alto SCM checks #400 and #401.',
    ),
    RuleDef(
        id="aipd_inbound_list_not_blocked",
        title="Advanced IP Defense list isn't blocked inbound",
        category="Security Policy",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description='No enabled deny rule uses one of the predefined Advanced IP Defense lists for commercial VPNs, proxies, scanners and brute-force sources, or exposed vulnerable services as the source of inbound traffic. Only checked with an active Advanced IP Defense license (upload a tech support file). Follows Palo Alto SCM checks #402, #404, #406 and #408.',
    ),
    RuleDef(
        id="aipd_rule_missing_pair",
        title="Deny rule uses only one of the Advanced IP Defense C2 and malware lists",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description='A blocking rule that uses the C2 infrastructure list should also use the hardcoded-in-malware list, and vice versa. Only checked with an active Advanced IP Defense license (upload a tech support file). Follows Palo Alto SCM check #410.',
    ),
    RuleDef(
        id="url_liability_categories_not_blocked",
        title="URL Filtering doesn't block liability-risk categories",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="The profile doesn't block every category Palo Alto lists as a business liability: abused-drugs, adult, copyright-infringement, extremism, gambling, peer-to-peer, questionable and weapons. Follows Palo Alto SCM check #340.",
        enabled_by_default=False,
        default_off_reason='Off by default: blocking these is a business decision. Turn it on for clients whose policy calls for it.',
    ),
    RuleDef(
        id="url_liability_credentials_not_blocked",
        title="Credential submission isn't blocked for liability-risk categories",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="User credential submission isn't blocked for every liability-risk category (abused-drugs, adult, copyright-infringement, extremism, gambling, peer-to-peer, questionable, weapons). Follows Palo Alto SCM check #344.",
        enabled_by_default=False,
        default_off_reason='Off by default: blocking these is a business decision. Turn it on for clients whose policy calls for it.',
    ),
    RuleDef(
        id="url_genai_categories_not_blocked",
        title="URL Filtering doesn't block generative AI categories",
        category="Security Profiles",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="The profile doesn't block every generative AI URL category (ai-code-assistant, ai-conversational-assistant, ai-data-and-workflow-optimizer, ai-meeting-assistant, ai-platform-service, ai-writing-assistant). Allow only sanctioned AI tools. Follows Palo Alto SCM check #357.",
        enabled_by_default=False,
        default_off_reason='Off by default: blocking these is a business decision. Turn it on for clients whose policy calls for it.',
    ),
    RuleDef(
        id="genai_no_block_rule",
        title="No rule blocks unsanctioned Gen AI applications",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='No enabled deny rule uses an application filter named "Gen AI Apps" (placed below the rule allowing sanctioned Gen AI apps). Follows Palo Alto SCM check #348.',
        enabled_by_default=False,
        default_off_reason='Off by default: blocking these is a business decision. Turn it on for clients whose policy calls for it.',
    ),
    RuleDef(
        id="genai_tolerated_no_users",
        title="Tolerated Gen AI apps are allowed for any user",
        category="Security Policy",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description='An allow rule uses the "Tolerated Gen AI apps" application filter without limiting source users. Follows Palo Alto SCM check #353.',
        enabled_by_default=False,
        default_off_reason='Off by default: blocking these is a business decision. Turn it on for clients whose policy calls for it.',
    ),
    RuleDef(
        id="genai_allow_no_dlp",
        title="Gen AI apps are allowed without data filtering",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description='An allow rule uses a Gen AI application filter ("Gen AI Apps", "Sanctioned Gen AI apps" or "Tolerated Gen AI apps") without a Data Filtering (DLP) profile. Follows Palo Alto SCM check #354.',
        enabled_by_default=False,
        default_off_reason='Off by default: blocking these is a business decision. Turn it on for clients whose policy calls for it.',
    ),
    RuleDef(
        id="decryption_not_quantum_safe_ciphers",
        title="Decryption profile allows non-quantum-safe ciphers",
        category="Decryption",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description='A profile used by a decryption rule still allows 3DES, RC4, AES-CBC or AES-128-GCM. Quantum-safe decryption allows only AES-256-GCM and ChaCha20-Poly1305. All are allowed by default. Follows Palo Alto SCM check #371.',
        enabled_by_default=False,
        default_off_reason="Off by default: post-quantum ciphers and key exchange are new, and most clients, servers and peers can't use them yet. Turn it on to report post-quantum readiness.",
    ),
    RuleDef(
        id="decryption_no_pqc_key_exchange",
        title="Decryption profile has no post-quantum key exchange",
        category="Decryption",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A profile used by a decryption rule doesn't enable PQC Standard or PQC Experimental key exchange, so decrypted sessions aren't protected against harvest-now-decrypt-later. Follows Palo Alto SCM check #375.",
        enabled_by_default=False,
        default_off_reason="Off by default: post-quantum ciphers and key exchange are new, and most clients, servers and peers can't use them yet. Turn it on to report post-quantum readiness.",
    ),
    # ── Site-to-site VPN ───────────────────────────────────────────────────
    RuleDef(
        id="vpn_weak_encryption",
        title="VPN allows weak encryption",
        category="VPN",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_VPN_IKE_CRYPTO + ": \"For the encryption algorithm, use AES; DES and 3DES are weak and "
                   "vulnerable.\" " + PAN_VPN_IPSEC_CRYPTO + ": \"select ESP (Encapsulating Security Payload) over "
                   "AH (Authentication Header) because ESP offers both confidentiality and authentication\"",
        description="An IKE or IPSec crypto profile used by an active tunnel lists DES, 3DES or null, or the tunnel "
                    "uses AH, which doesn't encrypt at all. Peers negotiate down to anything in the list, so one "
                    "weak entry is enough.",
    ),
    RuleDef(
        id="vpn_weak_authentication",
        title="VPN allows MD5, SHA-1 or no authentication",
        category="VPN",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_VPN_IPSEC_CRYPTO + ": \"For the authentication algorithm, use SHA-256 or higher (SHA-384 or "
                   "higher preferred for long-lived transactions).\" \"Don't use SHA-1, MD5, or none.\"",
        description="An IKE or IPSec crypto profile used by an active tunnel lists MD5 or SHA-1, or no "
                    "authentication with a non-GCM cipher. With AES-GCM, which authenticates on its own, "
                    "non-auth/none is correct and isn't flagged.",
    ),
    RuleDef(
        id="vpn_weak_dh_group",
        title="VPN uses a weak Diffie-Hellman group or no PFS",
        category="VPN",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_VPN_IKE_CRYPTO + ": \"For the strongest security, select the group with the highest "
                   "number.\"",
        description="An IKE crypto profile allows DH group 1, 2 or 5, or an IPSec crypto profile uses one of them "
                    "or turns Perfect Forward Secrecy off (no-pfs). Groups below 14 are too small for today's "
                    "attackers; without PFS one compromised IKE key exposes every IPSec key derived from it.",
        thresholds={"min_group": 14},
    ),
    RuleDef(
        id="ike_aggressive_mode",
        title="IKEv1 gateway uses aggressive mode",
        category="VPN",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_VPN_IKE_GATEWAY + ": \"Aggressive mode uses fewer packets to set up the VPN tunnel and is "
                   "hence a faster but a less secure option.\" \"Main mode is the recommended mode for IKE "
                   "negotiation if both peers support it.\"",
        description="Aggressive mode sends the peer identity in clear text and exposes a hash of the pre-shared "
                    "key to offline cracking.",
    ),
    RuleDef(
        id="ike_v1_only",
        title="IKE gateway only supports IKEv1",
        category="VPN",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="IKEv2 adds built-in liveness checks, NAT traversal and cookie validation against half-open "
                    "SA floods. Use IKEv2 (or IKEv2 preferred) wherever the peer supports it.",
    ),
    RuleDef(
        id="vpn_manual_key",
        title="IPSec tunnel uses manual keys",
        category="VPN",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Manual-key tunnels use static keys that never rotate and have no IKE authentication or "
                    "forward secrecy. Replace them with auto-key (IKE) tunnels.",
    ),
    RuleDef(
        id="vpn_lifetime_long",
        title="VPN key lifetime is unusually long",
        category="VPN",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Long lifetimes mean keys are used for more traffic before rekeying. PAN-OS defaults are 8 "
                    "hours for IKE and 1 hour for IPSec; this flags lifetimes above the thresholds.",
        thresholds={"ike_max_hours": 24, "ipsec_max_hours": 8},
    ),
    RuleDef(
        id="vpn_anti_replay_disabled",
        title="IPSec tunnel has anti-replay turned off",
        category="VPN",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Anti-replay drops re-sent copies of captured ESP packets. It's on by default and should only "
                    "be turned off to work around a specific peer problem.",
    ),
    RuleDef(
        id="vpn_no_tunnel_monitor",
        title="IPSec tunnel isn't monitored",
        category="VPN",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Without tunnel monitoring the firewall can't alert on, or fail over from, a tunnel that is "
                    "up but not passing traffic.",
    ),
    RuleDef(
        id="vpn_stale_config",
        title="Leftover VPN configuration",
        category="VPN",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Disabled tunnels and gateways, and IKE gateways no tunnel uses, are often old VPNs nobody "
                    "removed. They keep stored pre-shared keys and can be re-enabled by mistake.",
    ),
    # ── Threat-intelligence blocking ───────────────────────────────────────
    RuleDef(
        id="edl_known_malicious_not_blocked",
        title="Known malicious IP addresses aren't blocked",
        category="Security Policy",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_IGW_STEP1,
        description="No enabled deny rule uses the built-in \"Known malicious IP addresses\" list in this "
                    "direction — hosts Palo Alto Networks has verified are used to distribute malware, run "
                    "command-and-control and launch attacks.",
    ),
    RuleDef(
        id="edl_high_risk_not_blocked",
        title="High-risk IP addresses aren't blocked",
        category="Security Policy",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_IGW_STEP1,
        description="No enabled deny rule uses the built-in \"High risk IP addresses\" list (addresses from "
                    "trusted threat advisories) in this direction.",
    ),
    RuleDef(
        id="edl_bulletproof_not_blocked",
        title="Bulletproof-hosting IP addresses aren't blocked",
        category="Security Policy",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_IGW_STEP1,
        description="No enabled deny rule uses the built-in \"Bulletproof IP addresses\" list in this direction — "
                    "hosting providers that place few restrictions on content and are favoured for C2.",
    ),
    RuleDef(
        id="edl_tor_exit_not_blocked",
        title="Tor exit nodes aren't blocked",
        category="Security Policy",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_BPA_IGW_STEP1 + "; the same step adds block-and-log rules for the Tor exit IP addresses list",
        description="No enabled deny rule uses the built-in \"Tor exit IP addresses\" list in this direction. Tor "
                    "traffic can be legitimate but is disproportionately associated with malicious activity.",
    ),
    RuleDef(
        id="quic_not_blocked",
        title="QUIC isn't blocked",
        category="Security Policy",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_BPA_IGW_QUIC,
        description="No enabled deny rule blocks the QUIC application, so browsers can use QUIC instead of TLS "
                    "and bypass decryption and threat inspection.",
    ),
    # ── GlobalProtect ──────────────────────────────────────────────────────
    RuleDef(
        id="gp_tls_below_1_2",
        title="GlobalProtect portal or gateway accepts TLS below 1.2",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="The SSL/TLS service profile on an internet-facing portal or gateway allows TLS 1.0 or 1.1 "
                    "(PAN-OS defaults the minimum to TLS 1.0 when it isn't set). Palo Alto's SCM BPA check #76 "
                    "asks for a TLS 1.2 minimum and Max as the maximum.",
    ),
    RuleDef(
        id="gp_tls_weak_ciphers",
        title="GlobalProtect SSL/TLS profile allows 3DES, RC4 or SHA-1",
        category="GlobalProtect",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Legacy algorithms left enabled on the portal or gateway's SSL/TLS service profile.",
    ),
    RuleDef(
        id="gp_single_factor_auth",
        title="GlobalProtect login uses a single factor",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_GP_2FA,
        description="The portal or gateway authenticates users with only a password — no certificate profile, "
                    "no MFA on the authentication profile, and no SAML/RADIUS/Cloud Identity Engine service that "
                    "could enforce a second factor. Stolen VPN credentials are a leading initial-access vector.",
    ),
    RuleDef(
        id="gp_auth_no_lockout",
        title="GlobalProtect authentication profile has no account lockout",
        category="GlobalProtect",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="The firewall checks the password itself (local database, LDAP, Kerberos, RADIUS or TACACS+) "
                    "and never locks an account after failed attempts, so the portal can be password-sprayed.",
    ),
    RuleDef(
        id="gp_cert_profile_no_revocation",
        title="GlobalProtect certificate profile doesn't check revocation",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="Client certificates are accepted without a CRL or OCSP check, so a certificate revoked "
                    "after a device is lost or an employee leaves still logs in.",
    ),
    RuleDef(
        id="gp_no_trusted_root_ca",
        title="GlobalProtect portal pushes no trusted root CA",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_GP_AGENT_CONFIG + ": \"Add the entire certificate chain (trusted root CA and intermediate "
                   "CA certificates) to the portal agent configuration\"",
        description="Without a Trusted Root CA in the portal's agent settings, the app can't verify the "
                    "gateways' server certificates against a CA you control.",
    ),
    RuleDef(
        id="gp_connect_on_demand",
        title="GlobalProtect app connects only on demand",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_GP_ALWAYS_ON,
        description="With the On-demand connect method, remote endpoints browse unprotected until the user "
                    "chooses to connect.",
    ),
    RuleDef(
        id="gp_not_enforced",
        title="GlobalProtect isn't required for network access",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_GP_CUSTOMIZE_APP + ": \"To force all network traffic to traverse a GlobalProtect tunnel, "
                   "set Enforce GlobalProtect Connection for Network Access to Yes. By default, GlobalProtect is "
                   "not required for network access\"",
        description="An always-on agent configuration still lets the endpoint reach the network when "
                    "GlobalProtect is disconnected or disabled.",
    ),
    RuleDef(
        id="gp_user_can_disable",
        title="Users can disable GlobalProtect with no time limit",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_GP_CUSTOMIZE_APP + ": the default is Allow; \"To prevent users with the user-logon "
                   "connect method from disabling GlobalProtect, set Allow User to Disable GlobalProtect App to "
                   "Disallow\", or \"To restrict the amount of time for which the app can be disabled, enter a "
                   "Disable Timeout\"",
        description="Always-on users can switch GlobalProtect off (Allow or Allow with Comment) and it stays off "
                    "indefinitely, with no traffic inspection meanwhile.",
    ),
    RuleDef(
        id="gp_hip_collection_disabled",
        title="GlobalProtect doesn't collect HIP data",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_GP_AGENT_CONFIG + ": \"Enable the GlobalProtect app to Collect HIP Data\"",
        description="Without Host Information Profile data the firewall can't base policy on endpoint posture "
                    "(disk encryption, patch level, endpoint protection).",
    ),
    RuleDef(
        id="gp_no_internal_host_detection",
        title="GlobalProtect has internal and external gateways but no internal host detection",
        category="GlobalProtect",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_GP_AGENT_CONFIG + ": \"If you are adding both internal and external gateways to the same "
                   "configuration, make sure you enable Internal Host Detection\"",
        description="The app can't tell whether it's on the corporate network, so it can pick the wrong gateway.",
    ),
    RuleDef(
        id="gp_split_tunnel",
        title="GlobalProtect gateway split-tunnels traffic",
        category="GlobalProtect",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="The gateway's access routes don't include 0.0.0.0/0, so only some traffic is tunnelled and "
                    "the rest leaves the endpoint uninspected. Palo Alto's SCM BPA check #78 asks for the access "
                    "route to include all destinations.",
    ),
    RuleDef(
        id="gp_long_cookie_lifetime",
        title="GlobalProtect authentication cookies last too long",
        category="GlobalProtect",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Authentication-override cookies let a device reconnect without logging in again for their "
                    "whole lifetime — longer than the threshold means a stolen laptop stays connected for days.",
        thresholds={"max_cookie_lifetime_hours": 24},
    ),
    RuleDef(
        id="gp_satellite_no_root_ca",
        title="GlobalProtect satellites have no trusted root CA",
        category="GlobalProtect",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="The portal configures satellites but gives them no Trusted Root CA to verify gateway "
                    "certificates with (Palo Alto SCM BPA check #74). Only checked when satellites are configured.",
    ),
    RuleDef(
        id="no_login_banner",
        title="No login banner configured",
        category="Device Hardening",
        default_severity="INFORMATIONAL",
        source_type="cis",
        source_ref="CIS Palo Alto Firewall Benchmark 1.1.2 — Ensure 'Login Banner' is set",
        description="Verified against public CIS PAN-OS benchmark section listings.",
    ),
    RuleDef(
        id="no_ntp",
        title="NTP not configured",
        category="Device Hardening",
        default_severity="LOW",
        source_type="cis",
        source_ref="CIS Palo Alto Firewall Benchmark 1.6.2 — Ensure redundant NTP servers are configured "
                   "(this check only validates a primary server is present, not redundancy)",
        description="Accurate log timestamps depend on NTP.",
    ),
    # ── Known vulnerabilities (Palo Alto Networks security advisories) ──
    RuleDef(
        id="panos_advisory_critical",
        title="Critical security advisory affects this PAN-OS version",
        category="Software",
        default_severity="CRITICAL",
        source_type="pan_docs",
        source_ref=PAN_ADVISORIES,
        description="The installed PAN-OS version is listed as affected by a critical Palo Alto Networks security "
                    "advisory. Matched on the exact version and hotfix, so it needs a tech support file or a live "
                    "connection. Some advisories apply only when a feature is configured (GlobalProtect, for "
                    "example); the advisory says which.",
    ),
    RuleDef(
        id="panos_advisory_high",
        title="High-severity security advisory affects this PAN-OS version",
        category="Software",
        default_severity="WARNING",
        source_type="pan_docs",
        source_ref=PAN_ADVISORIES,
        description="The installed PAN-OS version is listed as affected by a high-severity Palo Alto Networks "
                    "security advisory. Needs a tech support file or a live connection for the exact version.",
    ),
    RuleDef(
        id="panos_advisory_medium",
        title="Medium-severity security advisories affect this PAN-OS version",
        category="Software",
        default_severity="LOW",
        source_type="pan_docs",
        source_ref=PAN_ADVISORIES,
        description="One finding for all the medium-severity Palo Alto Networks security advisories that list the "
                    "installed PAN-OS version as affected; each one is in the Known vulnerabilities table.",
    ),
    RuleDef(
        id="panos_advisory_low",
        title="Low-severity security advisories affect this PAN-OS version",
        category="Software",
        default_severity="INFORMATIONAL",
        source_type="pan_docs",
        source_ref=PAN_ADVISORIES,
        description="One finding for all the low-severity and informational Palo Alto Networks security "
                    "advisories that list the installed PAN-OS version as affected.",
        enabled_by_default=False,
        default_off_reason="Off by default: low-severity advisories rarely change an upgrade decision. They're "
                           "still listed in the Known vulnerabilities table.",
    ),
    # ── Certificates ──
    RuleDef(
        id="cert_expired",
        title="Certificate in use has expired",
        category="Certificates",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="A certificate the configuration uses (an SSL/TLS service profile, decryption, a certificate "
                    "profile, a VPN gateway or GlobalProtect) is past its expiry date. Services using it fail or "
                    "show certificate errors.",
    ),
    RuleDef(
        id="cert_expiring_soon",
        title="Certificate in use expires soon",
        category="Certificates",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A certificate the configuration uses expires within the warning window.",
        thresholds={"expiry_warning_days": 60},
    ),
    RuleDef(
        id="cert_expired_unused",
        title="Expired certificate isn't used",
        category="Certificates",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="An expired certificate that nothing in the configuration references. Removing it keeps the "
                    "certificate store clean and avoids it being picked by mistake.",
    ),
    RuleDef(
        id="cert_weak_key",
        title="Certificate uses a weak key",
        category="Certificates",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="An RSA key shorter than 2048 bits or an elliptic-curve key shorter than 256 bits, on a "
                    "certificate the firewall holds the private key for or uses.",
        thresholds={"min_rsa_bits": 2048, "min_ec_bits": 256},
    ),
    RuleDef(
        id="cert_weak_signature",
        title="Certificate is signed with SHA-1 or MD5",
        category="Certificates",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="A certificate issued with a SHA-1 or MD5 signature, which browsers and clients no longer "
                    "trust. Self-signed root CAs are left out: a trust anchor's own signature isn't checked.",
    ),
    RuleDef(
        id="cert_self_signed_service",
        title="User-facing service uses a self-signed certificate",
        category="Certificates",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A GlobalProtect portal or gateway, or the Authentication Portal, presents a self-signed "
                    "certificate, so users can't verify they're talking to the real service and learn to click "
                    "through certificate warnings.",
    ),
    # ── Rulebase analysis ──
    RuleDef(
        id="security_rule_shadowed_block",
        title="Block rule never matches: an earlier rule allows its traffic",
        category="Security Policy",
        default_severity="WARNING",
        source_type="custom",
        source_ref=None,
        description="A deny, drop or reset rule sits below an allow rule that matches all of its traffic, so the "
                    "firewall allows what the rule was written to block. Found by comparing every match field "
                    "(zones, addresses resolved to IP ranges, users, applications, services resolved to ports, "
                    "URL categories, HIP). Only certain coverage by a single earlier rule counts.",
    ),
    RuleDef(
        id="security_rule_shadowed",
        title="Rule never matches: an earlier rule covers all its traffic",
        category="Security Policy",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="An earlier rule matches all of this rule's traffic — with the same action (the rule is "
                    "redundant) or blocking traffic this rule means to allow. Either way the rule, its profiles "
                    "and its logging never apply. Only certain coverage by a single earlier rule counts.",
    ),
    RuleDef(
        id="unused_objects",
        title="Objects that nothing uses",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Address and service objects and groups, application groups and filters, external dynamic "
                    "lists, custom URL categories, security profiles and profile groups that no rule, NAT policy, "
                    "interface, profile or other object references — directly or through a group that's itself in "
                    "use. One finding per kind of object. Not checked on Panorama exports.",
    ),
    RuleDef(
        id="duplicate_objects",
        title="Objects with the same value",
        category="Security Policy",
        default_severity="INFORMATIONAL",
        source_type="custom",
        source_ref=None,
        description="Two or more address objects with the same address, or service objects with the same "
                    "protocol and ports. One finding per kind of object.",
    ),
    # ── NAT policy ──
    RuleDef(
        id="nat_rule_shadowed",
        title="NAT rule never matches: an earlier NAT rule covers its traffic",
        category="NAT",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="NAT rules are first-match too. An earlier rule matching all of this rule's zones, egress "
                    "interface, source, destination and service means this rule — and its translation — never "
                    "applies. Only certain coverage by a single earlier rule counts.",
    ),
    RuleDef(
        id="nat_dnat_no_allow_rule",
        title="Destination NAT that no security rule allows",
        category="NAT",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A destination NAT (port forward) whose traffic no enabled allow rule could match on source "
                    "zone and pre-NAT destination address — left over from a retired service, or a publish that "
                    "doesn't work. Flagged only when every allow rule definitely can't match.",
    ),
    RuleDef(
        id="nat_dnat_all_ports",
        title="Destination NAT forwards every port",
        category="NAT",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="A destination NAT from an internet-facing zone (recognised by name) or any zone with service "
                    "'any' and no port translation forwards every port of the internal host; only the security "
                    "policy stands between the internet and the rest of the host.",
    ),
    RuleDef(
        id="nat_bidirectional_static",
        title="Bi-directional static NAT",
        category="NAT",
        default_severity="LOW",
        source_type="custom",
        source_ref=None,
        description="Bi-directional static NAT also creates an implicit inbound translation to the host from any "
                    "zone on every port. A one-way source NAT plus a destination NAT for only the needed ports "
                    "is narrower.",
    ),
]

# core rule -> the SCM BPA check IDs that evaluate the same setting. Matched by
# reading both definitions side by side; "related" overlap (same topic, different
# test) is deliberately left out so a match means the two really agree on what to check.
SCM_MATCHES: dict[str, tuple[int, ...]] = {
    "admin_local_auth_no_mfa": (92,),
    "zone_missing_protection_profile": (60,),
    "zone_protection_no_recon": (86,),
    "security_rule_any_any_any": (4,),
    "security_rule_inbound_untrust_any_source": (4,),
    "security_rule_app_any_service_any": (5, 208),
    "security_rule_service_any": (5,),
    "security_rule_no_description": (3,),
    "security_rule_no_logging_allow": (10,),
    "security_rule_no_log_forwarding": (7,),
    "av_decoder_below_baseline": (33, 34, 206, 271),
    "av_inline_ml_disabled": (271, 272),
    "spyware_severity_below_baseline": (40,),
    "spyware_dns_category_mismatch": (38, 253),
    "vulnerability_severity_below_baseline": (42,),
    "spyware_inline_cloud_analysis_disabled": (364,),
    "spyware_inline_cloud_model_not_reset": (334,),
    "vulnerability_inline_cloud_analysis_disabled": (365,),
    "vulnerability_inline_cloud_model_not_reset": (360,),
    "url_mandatory_category_not_blocked": (43,),
    "url_elevated_risk_category_not_blocked": (341,),
    "url_credential_enforcement_disabled": (207, 345),
    "file_blocking_nothing_blocked": (45,),
    "wildfire_missing_recommended_filetype": (47,),
    "decryption_no_outbound": (350,),
    "decryption_no_best_practice_profile": (350,),
    "decryption_profile_weak_tls": (57,),
    "decryption_profile_cert_checks_disabled": (55,),
    "decryption_no_decrypt_cert_checks": (19, 58, 373),
    "mgmt_profile_cleartext": (228,),
    "mgmt_no_acl": (100, 101),
    "no_login_banner": (91,),
    "no_ntp": (105,),
    "admin_lockout_weak": (95, 96),
    "admin_idle_timeout_long": (94,),
    "api_key_no_lifetime": (243,),
    "password_complexity_weak": (103,),
    "snmp_v2c": (183, 184),
    "ldap_profile_no_tls": (186, 187),
    "radius_weak_protocol": (233,),
    "tacacs_pap": (234,),
    "syslog_not_tls": (185,),
    "system_logs_not_forwarded": (178,),
    "config_logs_not_forwarded": (182,),
    "content_updates_not_timely": (188, 189, 190),
    "dos_rule_not_protect": (26,),
    "dos_profile_flood_incomplete": (49,),
    "dos_profile_default_thresholds": (50,),
    "zone_protection_packet_based_off": (87,),
    "session_rematch_disabled": (120,),
    "tcp_forward_oo_queue": (214,),
    "session_timeout_changed": tuple(range(122, 135)),
    "session_accelerated_aging_off": (121,),
    "packet_buffer_protection_global_off": (213,),
    "zone_packet_buffer_protection_off": (212,),
    "cert_expiration_check_off": (89,),
    "log_high_dp_load_off": (97,),
    "telemetry_disabled": (197,),
    "update_server_verification_off": (104,),
    "mgmt_interface_cleartext": (102,),
    "ha_timers_not_recommended": (142,),
    "gre_keepalive_off": (246,),
    "pbf_no_monitor": (17,),
    "app_override_rule": (21,),
    "wildfire_size_limit_below_default": (109, 110, 111, 112, 113, 114, 115, 204, 205, 251, 361),
    "wildfire_grayware_not_reported": (117,),
    "wildfire_inline_cloud_analysis_disabled": (363,),
    "wildfire_realtime_hold_off": (347,),
    "profile_threat_exceptions": (31, 32, 36, 41),
    "av_packet_capture": (35,),
    "url_log_container_page_only": (44,),
    "url_categories_allowed_unlogged": (196,),
    "url_credential_detection_not_domain": (227,),
    "url_credential_submissions_unlogged": (346,),
    "url_inline_categorization_off": (273,),
    "decryption_inbound_checks_off": (56,),
    "decryption_ssh_checks_off": (59,),
    "decryption_weak_hmac": (372,),
    "log_forwarding_profile_no_destination": (51,),
    "log_forwarding_profile_missing_types": (52, 53, 259, 260),
    "security_rule_log_at_start": (6,),
    "security_rule_server_response_inspection_off": (9,),
    "default_rule_not_logged": (12, 13),
    "user_id_zone_disabled": (16,),
    "no_new_appid_rule": (249,),
    "advanced_profile_not_applied": (366, 367, 368, 370),
    "ssl_tls_profile_weak": (63,),
    "admin_no_custom_roles": (154,),
    "auth_profile_local_only": (155,),
    "auth_sequence_single_profile": (159,),
    "user_id_client_probing": (164,),
    "user_id_timeout_disabled": (165,),
    "auth_portal_transparent": (172,),
    "auth_portal_long_session": (173,),
    "auth_portal_weak_tls": (174,),
    "system_logs_high_severity_only": (177,),
    "content_updates_gp_not_hourly": (194, 195),
    "ldap_single_server": (199,),
    "secure_client_cert_predefined": (223,),
    "aipd_c2_not_blocked": (398, 399),
    "aipd_malware_ip_not_blocked": (400, 401),
    "aipd_inbound_list_not_blocked": (402, 404, 406, 408),
    "aipd_rule_missing_pair": (410,),
    "url_liability_categories_not_blocked": (340,),
    "url_liability_credentials_not_blocked": (344,),
    "url_genai_categories_not_blocked": (357,),
    "genai_no_block_rule": (348,),
    "genai_tolerated_no_users": (353,),
    "genai_allow_no_dlp": (354,),
    "decryption_not_quantum_safe_ciphers": (371,),
    "decryption_no_pqc_key_exchange": (375,),
    "ha_config_sync_disabled": (136,),
    "ha_session_sync_disabled": (144,),
    "ha2_keepalive_disabled": (145,),
    "ha1_encryption_disabled": (143,),
    "ha1_no_backup": (138,),
    "ha_heartbeat_backup_off": (141,),
    "ha_passive_link_state_shutdown": (139,),
    "ha_no_monitoring": (149, 150, 151),
    "ha_active_active_incomplete": (147, 148),
    "edl_known_malicious_not_blocked": (261, 262),
    "edl_high_risk_not_blocked": (263, 264),
    "quic_not_blocked": (241,),
    "gp_tls_below_1_2": (76,),
    "gp_single_factor_auth": (67, 77),
    "gp_no_trusted_root_ca": (65,),
    "gp_not_enforced": (71,),
    "gp_user_can_disable": (69,),
    "gp_hip_collection_disabled": (72,),
    "gp_no_internal_host_detection": (68,),
    "gp_split_tunnel": (78,),
    "gp_satellite_no_root_ca": (74,),
}
RULES = [replace(r, scm_check_ids=SCM_MATCHES.get(r.id, ())) for r in RULES]

RULES_BY_ID: dict[str, RuleDef] = {r.id: r for r in RULES}

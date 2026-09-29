"""
PAN-OS CLI commands that fix a finding, for the engineer to review and paste in configure mode.

PAN-OS `set` commands walk the configuration XML one element at a time, so each command here is
the same path the parser reads for that setting (see parser.py): a security rule's
`rulebase/security/rules/entry[@name]/log-end` becomes `set rulebase security rules "<rule>"
log-end yes`. Only findings whose fix is mechanical get commands; the rest get none and the
recommendation text stands. Nothing here commits.

Where the fix needs a value the config can't supply — which profile group to attach, which Log
Forwarding profile — the command carries a `{{key}}` slot and a `choices` entry: the matching
objects that already exist in the config for the page to offer, or a placeholder when there are
none (or the value is free text, like a login banner).

Context:
- Standalone firewalls with one vsys use `rulebase …`, `zone …`, `address …`; with several vsys,
  vsys-scoped paths are prefixed `vsys <name>`. Shared objects are `shared …`.
- Panorama exports: rules only, as `device-group "<dg>" pre-rulebase …` or `shared post-rulebase …`
  following each rule's scope. Settings that come from templates get no commands.
"""

from __future__ import annotations

import re
from typing import Optional

from ..parser import panorama_appliance
from . import rulebase

_BARE = re.compile(r"^[A-Za-z0-9._/:-]+$")

PROFILE_TAGS = {"antivirus": "virus", "spyware": "spyware", "vulnerability": "vulnerability",
                "url_filtering": "url-filtering", "file_blocking": "file-blocking", "wildfire_analysis": "wildfire-analysis"}

PANORAMA_RULEBASE = {
    "shared_pre": "shared pre-rulebase", "shared_post": "shared post-rulebase",
    "device_group_pre": "device-group {dg} pre-rulebase", "device_group_post": "device-group {dg} post-rulebase",
}


def q(value: str) -> str:
    """A name as the CLI takes it: bare when it's a plain token, otherwise double-quoted."""
    return value if _BARE.match(value) else '"' + value.replace('"', '\\"') + '"'


def _choice(key: str, label: str, options: list[str], placeholder: str, free: bool = False,
            default: Optional[str] = None) -> dict:
    return {"key": key, "label": label, "options": sorted(set(options)) if not free else list(options),
            "placeholder": placeholder, "free": free, "default": default}


class Context:
    def __init__(self, data: dict) -> None:
        self.data = data
        rules = data.get("security_rules") or []
        self.panorama = any(r.get("rule_scope") for r in rules) or bool(data.get("device_group"))
        self.dg = data.get("device_group") or (data.get("system_info") or {}).get("hostname") or "<DEVICE-GROUP>"
        vsys = {r.get("vsys") for r in rules + (data.get("nat_rules") or []) if r.get("vsys")}
        self.multi_vsys = len(vsys) > 1
        self.rules = {r["name"]: r for r in rules}
        self.profiles = {(ptype, p["name"]): p for ptype, ps in (data.get("security_profiles") or {}).items()
                         for p in ps if "settings" in p}
        self.nat_rules = {r["name"]: r for r in data.get("nat_rules") or []}

    def vsys_prefix(self, vsys: Optional[str]) -> str:
        return f"vsys {q(vsys)} " if self.multi_vsys and vsys else ""

    def profile(self, ptype: str, name: str) -> Optional[str]:
        """`profiles virus "corp-av"` with its scope prefix, or None when the scope wasn't recorded
        (uploads from before scopes were parsed) — guessing it could create a new, half-configured profile."""
        p = self.profiles.get((ptype, name))
        scope = p.get("scope") if p else None
        if not scope:
            return None
        if scope == "shared":
            prefix = "shared "
        elif scope == "device_group":
            prefix = f"device-group {q(p.get('scope_name') or self.dg)} "
        else:
            prefix = self.vsys_prefix(scope)
        return f"{prefix}profiles {PROFILE_TAGS[ptype]} {q(name)}"

    def rulebase(self, rule: dict, kind: str = "security") -> str:
        if rule.get("rule_scope"):
            # A rule from a parent device group is changed in that group, not the firewall's own.
            base = PANORAMA_RULEBASE[rule["rule_scope"]].format(dg=q(rule.get("scope_name") or self.dg))
            return f"{base} {kind} rules {q(rule['name'])}"
        return f"{self.vsys_prefix(rule.get('vsys'))}rulebase {kind} rules {q(rule['name'])}"


# ── Per-rule fixes (finding key = rule name) ─────────────────────────────

def _rule_set(suffix: str):
    def build(ctx: Context, key: str) -> Optional[dict]:
        rule = ctx.rules.get(key)
        return {"commands": [f"set {ctx.rulebase(rule)} {suffix}"]} if rule else None
    return build


def _attach_profile_group(ctx: Context, key: str) -> Optional[dict]:
    rule = ctx.rules.get(key)
    if not rule:
        return None
    groups = [g["name"] for g in ctx.data.get("profile_groups") or []]
    return {"commands": [f"set {ctx.rulebase(rule)} profile-setting group {{{{profile_group}}}}"],
            "choices": [_choice("profile_group", "Security profile group", groups, "<PROFILE-GROUP>")]}


def _log_forwarding(ctx: Context, key: str) -> Optional[dict]:
    rule = ctx.rules.get(key)
    if not rule:
        return None
    profiles = [p["name"] for p in ctx.data.get("log_forwarding_profiles") or []]
    return {"commands": [f"set {ctx.rulebase(rule)} log-setting {{{{log_forwarding}}}}"],
            "choices": [_choice("log_forwarding", "Log Forwarding profile", profiles, "<LOG-FORWARDING-PROFILE>")]}


def _description(ctx: Context, key: str) -> Optional[dict]:
    rule = ctx.rules.get(key)
    if not rule:
        return None
    return {"commands": [f'set {ctx.rulebase(rule)} description "{{{{description:{key}}}}}"'],
            "choices": [_choice(f"description:{key}", f"Description for '{key}'", [], "<WHY THIS RULE EXISTS>", True)]}


def _shadowed_disable(ctx: Context, key: str) -> Optional[dict]:
    rule = ctx.rules.get(key)
    if not rule:
        return None
    return {"commands": [f"set {ctx.rulebase(rule)} disabled yes"],
            "note": "Disables the rule rather than deleting it; delete it once nothing has changed for a while. If the "
                    "earlier rule that covers it is itself being narrowed (an any/any rule, say), fix that first: this "
                    "rule may be needed afterwards."}


def _shadowed_move(ctx: Context, key: str) -> Optional[dict]:
    rule = ctx.rules.get(key)
    hit = next((s for s in rulebase.analyze(ctx.data).get("shadowed", []) if s["rule"] == key), None)
    by = ctx.rules.get(hit["by"]) if hit else None
    if not rule or not by or rule.get("rule_scope") != by.get("rule_scope") or rule.get("vsys") != by.get("vsys"):
        return None  # a rule can only move within its own rulebase
    return {"commands": [f"move {ctx.rulebase(rule)} before {q(by['name'])}"],
            "note": f"Moves '{key}' above '{by['name']}' so it's evaluated first. Check that nothing else between "
                    f"them should still apply first."}


def _nat_disable(ctx: Context, key: str) -> Optional[dict]:
    rule = ctx.nat_rules.get(key)
    if not rule:
        return None
    return {"commands": [f"set {ctx.rulebase(rule, 'nat')} disabled yes"],
            "note": "Disables the NAT rule rather than deleting it."}


# ── Device settings (standalone firewalls; Panorama pushes these from templates) ──

def _device(*commands: str, choices: Optional[list[dict]] = None, note: Optional[str] = None):
    def build(ctx: Context, key: str) -> Optional[dict]:
        if ctx.panorama:
            return None
        out: dict = {"commands": list(commands)}
        if choices:
            out["choices"] = choices
        if note:
            out["note"] = note
        return out
    return build


def _lockout(ctx: Context, key: str) -> Optional[dict]:
    if ctx.panorama:
        return None
    if key == "lockout_time":
        return {"commands": ["set deviceconfig setting management admin-lockout lockout-time 30"]}
    return {"commands": ["set deviceconfig setting management admin-lockout failed-attempts 5",
                         "set deviceconfig setting management admin-lockout lockout-time 30"]}


def _zone_protection(ctx: Context, key: str) -> Optional[dict]:
    if ctx.panorama or ctx.multi_vsys:
        return None  # a zone's vsys isn't recorded; on multi-vsys firewalls the path would be a guess
    zpps = [p["name"] for p in ctx.data.get("zone_protection_profiles") or []]
    return {"commands": [f"set zone {q(key)} network zone-protection-profile {{{{zone_protection}}}}"],
            "choices": [_choice("zone_protection", "Zone Protection profile", zpps, "<ZONE-PROTECTION-PROFILE>")]}


# Groups are deleted before their members: PAN-OS refuses to delete an object a group still lists.
_DELETE_ORDER = ["profile_groups", "address_groups", "service_groups", "application_groups", "security_profiles",
                 "custom_url_categories", "application_filters", "external_lists", "addresses", "services"]


def _unused_objects(ctx: Context, key: str) -> Optional[dict]:
    usage = ctx.data.get("object_usage") or {}
    if ctx.panorama or not usage.get("available") or "unused_detail" not in usage:
        return None
    rows = [d for d in usage["unused_detail"] if d["kind"] == key]
    commands = []
    for d in rows:
        scope = "shared " if d["scope"] == "shared" else ctx.vsys_prefix(d["scope"])
        commands.append(f"delete {scope}{d['path']} {q(d['name'])}")
    return {"commands": commands, "order": 100 + _DELETE_ORDER.index(key)} if commands else None



# ── Security profile settings ────────────────────────────────────────────
#
# Finding keys are "<profile>" or "<profile>:<item>" (a decoder, severity rule, DNS category, URL
# category, model or file type). Paths follow parser.py's profile settings parsers.

def _split(key: str) -> tuple[str, str]:
    name, _, item = key.rpartition(":")
    return (name, item) if name else (key, "")


def _profile_cmds(ptype: str, make, per_item: bool = False):
    """Wraps make(ctx, profile path, profile[, item]) → commands (a list) or a result dict. `per_item`: the
    finding key is "<profile>:<item>" and make gets the item too."""
    def build(ctx: Context, key: str) -> Optional[dict]:
        name, item = _split(key) if per_item else (key, "")
        path = ctx.profile(ptype, name)
        if path is None:
            return None
        profile = ctx.profiles[(ptype, name)]
        out = make(ctx, path, profile, item) if per_item else make(ctx, path, profile)
        if isinstance(out, list):
            out = {"commands": out}
        return out if out and out.get("commands") else None
    return build


def _av_decoder(ctx, path, p, decoder):
    d = p["settings"].get("decoders", {}).get(decoder)
    if d is None:
        return None
    cmds = [f"set {path} decoder {decoder} action reset-both"] if d["action"] != "reset-both" else []
    if d["wildfire_action"] != "reset-both":
        cmds.append(f"set {path} decoder {decoder} wildfire-action reset-both")
    # The ML action exists from PAN-OS 10.0, the same release that added Inline ML to the profile.
    if d["mlav_action"] != "reset-both" and p["settings"].get("inline_ml"):
        cmds.append(f"set {path} decoder {decoder} mlav-action reset-both")
    return cmds


def _av_inline_ml(ctx, path, p, model):
    return [f"set {path} mlav-engine-filebased-enabled {q(model)} mlav-policy-action enable"]


def _severity_rule(ctx, path, p, rule):
    return [f"set {path} rules {q(rule)} action reset-both",
            f"set {path} rules {q(rule)} packet-capture single-packet"]


def _dns_sinkhole(ctx, path, p, category):
    cmds = [f"set {path} botnet-domains dns-security-categories {category} action sinkhole"]
    if not p["settings"].get("dns_sinkhole_enabled"):
        # Sinkholing needs the profile's sinkhole addresses; Palo Alto's default sinkhole FQDN and IPv6 loopback.
        cmds = [f"set {path} botnet-domains sinkhole ipv4-address pan-sinkhole-default-ip",
                f"set {path} botnet-domains sinkhole ipv6-address ::1"] + cmds
    return cmds


def _inline_cloud(engine: str):
    def make(ctx, path, p):
        models = p["settings"].get("inline_cloud_analysis", {}).get("models", {})
        return [f"set {path} cloud-inline-analysis yes"] + \
            [f"set {path} {engine} {q(m)} inline-policy-action reset-both" for m, a in models.items() if a != "reset-both"]
    return make


def _inline_model(engine: str):
    def make(ctx, path, p, model):
        return [f"set {path} {engine} {q(model)} inline-policy-action reset-both"]
    return make


# A URL category can sit in only one action list, so blocking one means taking it out of the others.
_URL_LISTS = {"alert": "alert_categories", "allow": "allow_categories", "continue": "continue_categories",
              "override": "override_categories"}
_CRED_LISTS = {"alert": "credential_alert_categories", "allow": "credential_allow_categories",
               "continue": "credential_continue_categories"}


def _move_categories(path: str, settings: dict, categories: list[str], to: str, lists: dict[str, str],
                     prefix: str = "") -> list[str]:
    cmds = []
    for cat in categories:
        for action, field in lists.items():
            if action != to and cat in (settings.get(field) or []):
                cmds.append(f"delete {path} {prefix}{action} {cat}")
    if categories:
        members = categories[0] if len(categories) == 1 else "[ " + " ".join(categories) + " ]"
        cmds.append(f"set {path} {prefix}{to} {members}")
    return cmds


def _url_block_one(ctx, path, p, category):
    return _move_categories(path, p["settings"], [category], "block", _URL_LISTS)


def _url_block_missing(categories: tuple[str, ...], credentials: bool = False):
    def make(ctx, path, p):
        field = "credential_enforcement_block_categories" if credentials else "block_categories"
        blocked = {c.lower() for c in p["settings"].get(field) or []}
        missing = [c for c in categories if c not in blocked]
        if credentials:
            return _move_categories(path, p["settings"], missing, "block", _CRED_LISTS, "credential-enforcement ")
        return _move_categories(path, p["settings"], missing, "block", _URL_LISTS)
    return make


def _url_alert_allowed(credentials: bool):
    def make(ctx, path, p):
        field = "credential_allow_categories" if credentials else "allow_categories"
        cats = list(p["settings"].get(field) or [])
        if credentials:
            return _move_categories(path, p["settings"], cats, "alert", _CRED_LISTS, "credential-enforcement ")
        return _move_categories(path, p["settings"], cats, "alert", _URL_LISTS)
    return make


def _cred_mode(ctx, path, p):
    return {"commands": [f"set {path} credential-enforcement mode {{{{credential_mode}}}}"],
            "choices": [_choice("credential_mode", "Credential detection method",
                                ["domain-credentials", "ip-user"], "<DETECTION-METHOD>")],
            "note": "Domain Credential Filter needs the User-ID agent's credential detection; IP User works "
                    "with any User-ID source."}


def _cred_domain(ctx, path, p):
    return {"commands": [f"set {path} credential-enforcement mode domain-credentials"],
            "note": "Domain Credential Filter needs the Windows User-ID agent with credential detection enabled."}


# Palo Alto's predefined "strict file blocking" profile blocks these file types in both directions.
STRICT_FILE_TYPES = "7z bat cab chm class cpl dll exe flash hlp hta jar msi Multi-Level-Encoding ocx PE pif rar " \
                    "scr tar torrent vbe wsf"


def _file_blocking(ctx, path, p):
    return {"commands": [f'set {path} rules "block-high-risk-file-types" application any file-type '
                         f'[ {{{{file_types}}}} ] direction both action block'],
            "choices": [_choice("file_types", "File types to block", [], "<FILE-TYPES>", True, STRICT_FILE_TYPES)],
            "note": "Adds a rule blocking the file types in Palo Alto's strict file blocking profile. Remove any "
                    "the business needs (installers from a software portal, for example) before pasting. A new "
                    "rule goes to the bottom of the profile's list, so move it above any rule that alerts on "
                    "the same types."}


def _wildfire_filetype(ctx, path, p, file_type):
    rules = p["settings"].get("rules") or []
    if rules:
        return {"commands": [f"set {path} rules {q(rules[0]['name'])} file-type {file_type}"],
                "note": f"Adds {file_type} to the profile's first rule ('{rules[0]['name']}'), which keeps that "
                        f"rule's applications, direction and analysis location."}
    return [f"set {path} rules all-files application any file-type any direction both analysis public-cloud"]


def _wildfire_size(ctx: Context, key: str) -> Optional[dict]:
    from .checks import WILDFIRE_DEFAULT_LIMITS
    if ctx.panorama:
        return None
    limits = ((ctx.data.get("device_settings") or {}).get("wildfire") or {}).get("size_limits", {})
    name = next((n for n in limits if n.lower() == key), None)
    default = WILDFIRE_DEFAULT_LIMITS.get(key)
    if not name or not default:
        return None
    return {"commands": [f"set deviceconfig setting wildfire file-size-limit {q(name)} size-limit {default[0]}"]}


def _wfrt_hold(ctx: Context, key: str) -> Optional[dict]:
    cmds = []
    for (ptype, name), p in ctx.profiles.items():
        if ptype == "antivirus" and p.get("rule_count", 0) > 0 and p["settings"].get("wfrt_hold_mode") is False:
            path = ctx.profile("antivirus", name)
            if path:
                cmds.append(f"set {path} wfrt-hold-mode yes")
    return {"commands": cmds, "note": "Also turn on Hold for WildFire Real Time Signature Look Up under Device > "
                                      "Setup > Content-ID, with the timeout action set to Reset-Both."} if cmds else None


PROFILE_BUILDERS = {
    "av_decoder_below_baseline": _profile_cmds("antivirus", _av_decoder, per_item=True),
    "av_inline_ml_disabled": _profile_cmds("antivirus", _av_inline_ml, per_item=True),
    "av_packet_capture": _profile_cmds("antivirus", lambda ctx, path, p: [f"set {path} packet-capture no"]),
    "spyware_severity_below_baseline": _profile_cmds("spyware", _severity_rule, per_item=True),
    "vulnerability_severity_below_baseline": _profile_cmds("vulnerability", _severity_rule, per_item=True),
    "spyware_dns_category_mismatch": _profile_cmds("spyware", _dns_sinkhole, per_item=True),
    "spyware_inline_cloud_analysis_disabled": _profile_cmds("spyware", _inline_cloud("mica-engine-spyware-enabled")),
    "vulnerability_inline_cloud_analysis_disabled":
        _profile_cmds("vulnerability", _inline_cloud("mica-engine-vulnerability-enabled")),
    "spyware_inline_cloud_model_not_reset": _profile_cmds("spyware", _inline_model("mica-engine-spyware-enabled"), per_item=True),
    "vulnerability_inline_cloud_model_not_reset":
        _profile_cmds("vulnerability", _inline_model("mica-engine-vulnerability-enabled"), per_item=True),
    "url_mandatory_category_not_blocked": _profile_cmds("url_filtering", _url_block_one, per_item=True),
    "url_elevated_risk_category_not_blocked": _profile_cmds("url_filtering", _url_block_one, per_item=True),
    "url_liability_categories_not_blocked": None,     # filled below (needs the category lists from checks)
    "url_liability_credentials_not_blocked": None,
    "url_genai_categories_not_blocked": None,
    "url_credential_enforcement_disabled": _profile_cmds("url_filtering", _cred_mode),
    "url_credential_detection_not_domain": _profile_cmds("url_filtering", _cred_domain),
    "url_log_container_page_only":
        _profile_cmds("url_filtering", lambda ctx, path, p: [f"set {path} log-container-page-only no"]),
    "url_categories_allowed_unlogged": _profile_cmds("url_filtering", _url_alert_allowed(False)),
    "url_credential_submissions_unlogged": _profile_cmds("url_filtering", _url_alert_allowed(True)),
    "url_inline_categorization_off":
        _profile_cmds("url_filtering", lambda ctx, path, p: [f"set {path} cloud-inline-cat yes"]),
    "file_blocking_nothing_blocked": _profile_cmds("file_blocking", _file_blocking),
    "wildfire_missing_recommended_filetype": _profile_cmds("wildfire_analysis", _wildfire_filetype, per_item=True),
    "wildfire_inline_cloud_analysis_disabled":
        _profile_cmds("wildfire_analysis", lambda ctx, path, p: [f"set {path} cloud-inline-analysis yes"]),
    "wildfire_size_limit_below_default": _wildfire_size,
    "wildfire_realtime_hold_off": _wfrt_hold,
}


def _fill_url_category_builders() -> None:
    from .checks import GENAI_CATEGORIES, LIABILITY_CATEGORIES
    PROFILE_BUILDERS["url_liability_categories_not_blocked"] = \
        _profile_cmds("url_filtering", _url_block_missing(LIABILITY_CATEGORIES))
    PROFILE_BUILDERS["url_liability_credentials_not_blocked"] = \
        _profile_cmds("url_filtering", _url_block_missing(LIABILITY_CATEGORIES, credentials=True))
    PROFILE_BUILDERS["url_genai_categories_not_blocked"] = \
        _profile_cmds("url_filtering", _url_block_missing(GENAI_CATEGORIES))

BUILDERS = {
    "security_rule_missing_profile_non_infra": _attach_profile_group,
    "security_rule_missing_profile_infra": _attach_profile_group,
    "security_rule_no_logging_allow": _rule_set("log-end yes"),
    "security_rule_deny_no_logging": _rule_set("log-end yes"),
    "security_rule_log_at_start": _rule_set("log-start no"),
    "security_rule_no_log_forwarding": _log_forwarding,
    "security_rule_no_description": _description,
    "security_rule_server_response_inspection_off": _rule_set("option disable-server-response-inspection no"),
    "security_rule_service_any": _rule_set("service application-default"),
    "security_rule_shadowed": _shadowed_disable,
    "security_rule_shadowed_block": _shadowed_move,
    "nat_rule_shadowed": _nat_disable,
    "zone_missing_protection_profile": _zone_protection,
    "unused_objects": _unused_objects,
    "admin_idle_timeout_long": _device("set deviceconfig setting management idle-timeout 10"),
    "admin_lockout_weak": _lockout,
    "password_complexity_weak": _device("set mgt-config password-complexity enabled yes",
                                        "set mgt-config password-complexity minimum-length 12"),
    "api_key_no_lifetime": _device(
        "set deviceconfig setting management api key lifetime {{api_key_lifetime}}",
        choices=[_choice("api_key_lifetime", "API key lifetime (minutes)", [], "<MINUTES>", True)],
        note="Existing API keys stop working when they reach the lifetime; rotate the keys scripts use first."),
    "no_login_banner": _device('set deviceconfig system login-banner "{{login_banner}}"',
                               choices=[_choice("login_banner", "Login banner text", [],
                                                "<AUTHORIZED USE ONLY - ACTIVITY IS MONITORED>", True)]),
    "no_ntp": _device(
        "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address {{ntp_primary}}",
        "set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address {{ntp_secondary}}",
        choices=[_choice("ntp_primary", "Primary NTP server", [], "<NTP-SERVER-1>", True),
                 _choice("ntp_secondary", "Secondary NTP server", [], "<NTP-SERVER-2>", True)]),
    "mgmt_interface_cleartext": _device("set deviceconfig system service disable-http yes",
                                        "set deviceconfig system service disable-telnet yes"),
    "session_rematch_disabled": _device("set deviceconfig setting config rematch yes"),
    "tcp_forward_oo_queue": _device("set deviceconfig setting tcp bypass-exceed-oo-queue no"),
    "cert_expiration_check_off": _device("set deviceconfig setting management enable-certificate-expiration-check yes"),
    "log_high_dp_load_off": _device("set deviceconfig setting management enable-log-high-dp-load yes"),
    "update_server_verification_off": _device("set deviceconfig system server-verification yes"),
    "wildfire_grayware_not_reported": _device("set deviceconfig setting wildfire report-grayware-file yes"),
}


_fill_url_category_builders()
BUILDERS.update(PROFILE_BUILDERS)


def for_finding(finding: dict, ctx: Context) -> Optional[dict]:
    """{"commands": [...], "choices": [...], "note": ...} for a core finding with a mechanical fix, else None."""
    if finding.get("program") != "core":
        return None
    build = BUILDERS.get(finding["rule_id"])
    if build is None:
        return None
    key = finding["finding_key"].split(":", 1)[1] if ":" in finding["finding_key"] else ""
    out = build(ctx, key)
    if not out or not out.get("commands"):
        return None
    # `order` sorts a batch: settings and rule changes first, then deletes, groups before their members.
    return {"commands": out["commands"], "choices": out.get("choices", []), "note": out.get("note"),
            "order": out.get("order", 0)}


PANORAMA_MANAGED_NOTE = (
    "Panorama manages this firewall, so CLI commands aren't offered for it. Rules, profiles and settings "
    "Panorama pushes can't be changed at the firewall, and the next push would undo local changes to them. "
    "Make these changes in Panorama, in the firewall's device group and template, then push.")


PANORAMA_APPLIANCE_NOTE = (
    "This assessment is from Panorama's own tech support file, so it mixes every device group and no CLI "
    "commands are offered. Upload the file again and choose a device group: that assessment gets commands "
    "written for Panorama.")


def unavailable_reason(data: dict) -> str | None:
    """Why no commands are offered for this assessment, or None when they are. Assessments made from a
    Panorama export (one device group) do get commands, written for Panorama; a Panorama-managed
    firewall's own export or tech support file doesn't say which settings were pushed, so commands for
    it would target the wrong place."""
    if panorama_appliance(data):
        return PANORAMA_APPLIANCE_NOTE
    if data.get("panorama_managed") and not data.get("device_group"):
        return PANORAMA_MANAGED_NOTE
    return None


def annotate(findings: list[dict], data: dict) -> None:
    """Adds a `cli` entry (or None) to each finding."""
    if unavailable_reason(data):
        for f in findings:
            f["cli"] = None
        return
    ctx = Context(data)
    for f in findings:
        f["cli"] = for_finding(f, ctx)

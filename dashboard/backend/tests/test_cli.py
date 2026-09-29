"""CLI remediation commands: syntax, context (single/multi vsys, Panorama), choices and ordering."""
from app.rules import cli


def rule(name, **kw):
    return {"name": name, "action": "allow", "disabled": "no", "vsys": "vsys1", "rule_scope": None, **kw}


def f(rule_id, key, program="core"):
    return {"rule_id": rule_id, "finding_key": f"{rule_id}:{key}", "program": program}


def cmds(data, rule_id, key):
    out = cli.for_finding(f(rule_id, key), cli.Context(data))
    return out and out["commands"]


def test_quoting():
    assert cli.q("web-01") == "web-01" and cli.q("10.0.0.0/8") == "10.0.0.0/8"
    assert cli.q("Allow Web Out") == '"Allow Web Out"' and cli.q('a"b') == '"a\\"b"'


def test_single_vsys_rule_commands():
    data = {"security_rules": [rule("Allow Web")], "profile_groups": [{"name": "strict"}, {"name": "default"}],
            "log_forwarding_profiles": [{"name": "to-siem"}]}
    assert cmds(data, "security_rule_no_logging_allow", "Allow Web") == \
        ['set rulebase security rules "Allow Web" log-end yes']
    out = cli.for_finding(f("security_rule_missing_profile_non_infra", "Allow Web"), cli.Context(data))
    assert out["commands"] == ['set rulebase security rules "Allow Web" profile-setting group {{profile_group}}']
    assert out["choices"][0]["options"] == ["default", "strict"]
    lf = cli.for_finding(f("security_rule_no_log_forwarding", "Allow Web"), cli.Context(data))
    assert lf["choices"][0]["options"] == ["to-siem"]
    # No existing objects to offer: a placeholder.
    none = cli.for_finding(f("security_rule_missing_profile_non_infra", "Allow Web"),
                           cli.Context({"security_rules": [rule("Allow Web")]}))
    assert none["choices"][0]["options"] == [] and none["choices"][0]["placeholder"] == "<PROFILE-GROUP>"


def test_multi_vsys_prefix():
    data = {"security_rules": [rule("a", vsys="vsys1"), rule("b", vsys="vsys2")]}
    assert cmds(data, "security_rule_log_at_start", "b") == ["set vsys vsys2 rulebase security rules b log-start no"]


def test_panorama_rules_follow_scope_and_skip_device_settings():
    data = {"device_group": "Branch Offices",
            "security_rules": [rule("pre-r", rule_scope="device_group_pre"), rule("sh", rule_scope="shared_post")]}
    assert cmds(data, "security_rule_no_logging_allow", "pre-r") == \
        ['set device-group "Branch Offices" pre-rulebase security rules pre-r log-end yes']
    assert cmds(data, "security_rule_no_logging_allow", "sh") == \
        ["set shared post-rulebase security rules sh log-end yes"]
    assert cmds(data, "admin_idle_timeout_long", "global") is None
    assert cmds(data, "zone_missing_protection_profile", "trust") is None


def test_shadowed_rules_disable_and_block_rules_move():
    base = {"from_zones": ["trust"], "to_zones": ["untrust"], "sources": ["any"], "destinations": ["any"],
            "source_users": ["any"], "applications": ["any"], "services": ["any"], "category": ["any"],
            "source_hip": ["any"], "destination_hip": ["any"], "rule_type": "universal", "negate_source": "no",
            "negate_destination": "no", "schedule": None, "targeted": False}
    data = {"security_rules": [rule("allow-all", **base), rule("block ssh", **{**base, "action": "deny",
                                                                               "applications": ["ssh"]}),
                               rule("allow-web", **{**base, "applications": ["web-browsing"]})],
            "policy_objects": {}}
    assert cmds(data, "security_rule_shadowed_block", "block ssh") == \
        ['move rulebase security rules "block ssh" before allow-all']
    out = cli.for_finding(f("security_rule_shadowed", "allow-web"), cli.Context(data))
    assert out["commands"] == ["set rulebase security rules allow-web disabled yes"] and "narrowed" in out["note"]


def test_move_not_offered_across_rulebases():
    base = {"from_zones": ["any"], "to_zones": ["any"], "sources": ["any"], "destinations": ["any"],
            "source_users": ["any"], "applications": ["any"], "services": ["any"], "category": ["any"],
            "source_hip": ["any"], "destination_hip": ["any"], "rule_type": "universal", "negate_source": "no",
            "negate_destination": "no", "schedule": None, "targeted": False}
    data = {"device_group": "dg", "policy_objects": {},
            "security_rules": [rule("pre-allow", rule_scope="shared_pre", **base),
                               rule("dg-block", rule_scope="device_group_post", **{**base, "action": "deny"})]}
    assert cmds(data, "security_rule_shadowed_block", "dg-block") is None


def test_unused_objects_delete_groups_first_with_scope():
    data = {"security_rules": [rule("a")], "object_usage": {"available": True, "unused": {}, "unused_detail": [
        {"kind": "addresses", "name": "old host", "scope": "shared", "path": "address"},
        {"kind": "addresses", "name": "lab", "scope": "vsys1", "path": "address"},
        {"kind": "security_profiles", "name": "old-av", "scope": "vsys1", "path": "profiles virus"},
    ]}}
    assert cmds(data, "unused_objects", "addresses") == ['delete shared address "old host"', "delete address lab"]
    assert cmds(data, "unused_objects", "security_profiles") == ["delete profiles virus old-av"]


def test_device_settings_and_free_text_choices():
    data = {"security_rules": [rule("a")]}
    assert cmds(data, "password_complexity_weak", "global") == [
        "set mgt-config password-complexity enabled yes", "set mgt-config password-complexity minimum-length 12"]
    banner = cli.for_finding(f("no_login_banner", "global"), cli.Context(data))
    assert banner["commands"] == ['set deviceconfig system login-banner "{{login_banner}}"']
    assert banner["choices"][0]["free"] is True
    assert cmds(data, "admin_lockout_weak", "lockout_time") == \
        ["set deviceconfig setting management admin-lockout lockout-time 30"]


def test_no_commands_for_judgement_calls_or_scm():
    data = {"security_rules": [rule("a")]}
    assert cmds(data, "security_rule_any_any_any", "a") is None
    assert cli.for_finding(f("security_rule_no_logging_allow", "a", program="scm"), cli.Context(data)) is None


def test_builders_only_name_real_rules():
    from app.rules.definitions import RULES_BY_ID
    assert set(cli.BUILDERS) <= set(RULES_BY_ID)


def test_deletes_sort_groups_before_members():
    data = {"security_rules": [rule("a")], "object_usage": {"available": True, "unused": {}, "unused_detail": [
        {"kind": "addresses", "name": "h", "scope": "shared", "path": "address"},
        {"kind": "address_groups", "name": "g", "scope": "shared", "path": "address-group"}]}}
    ctx = cli.Context(data)
    addr = cli.for_finding(f("unused_objects", "addresses"), ctx)
    grp = cli.for_finding(f("unused_objects", "address_groups"), ctx)
    assert grp["order"] < addr["order"]
    assert cli.for_finding(f("security_rule_log_at_start", "a"), ctx)["order"] == 0


# ── Security profile settings ──

def prof(name, scope="vsys1", **settings):
    return {"name": name, "scope": scope, "rule_count": 1, "settings": settings}


def pdata(**profiles):
    return {"security_rules": [rule("a")], "security_profiles": profiles}


def test_profile_path_follows_scope():
    data = pdata(antivirus=[prof("corp av", scope="shared", packet_capture=True), prof("local", packet_capture=True)])
    assert cmds(data, "av_packet_capture", "corp av") == ['set shared profiles virus "corp av" packet-capture no']
    assert cmds(data, "av_packet_capture", "local") == ["set profiles virus local packet-capture no"]
    multi = {**data, "security_rules": [rule("a", vsys="vsys1"), rule("b", vsys="vsys2")]}
    assert cmds(multi, "av_packet_capture", "local") == ["set vsys vsys1 profiles virus local packet-capture no"]
    pano = {**data, "device_group": "DG1", "security_profiles": {"antivirus": [prof("dgp", scope="device_group",
                                                                                    packet_capture=True)]}}
    assert cmds(pano, "av_packet_capture", "dgp") == ["set device-group DG1 profiles virus dgp packet-capture no"]


def test_no_profile_commands_without_a_recorded_scope():
    data = pdata(antivirus=[{"name": "old", "rule_count": 1, "settings": {"packet_capture": True}}])
    assert cmds(data, "av_packet_capture", "old") is None


def test_antivirus_decoder_and_inline_ml():
    data = pdata(antivirus=[prof("av", decoders={"http": {"action": "default", "wildfire_action": "reset-both",
                                                          "mlav_action": "default"}},
                                 inline_ml={"Windows Executables": "disable"})])
    assert cmds(data, "av_decoder_below_baseline", "av:http") == [
        "set profiles virus av decoder http action reset-both", "set profiles virus av decoder http mlav-action reset-both"]
    assert cmds(data, "av_inline_ml_disabled", "av:Windows Executables") == [
        'set profiles virus av mlav-engine-filebased-enabled "Windows Executables" mlav-policy-action enable']


def test_severity_rules_and_dns_sinkhole():
    data = pdata(spyware=[prof("as", dns_sinkhole_enabled=False)], vulnerability=[prof("vp")])
    assert cmds(data, "vulnerability_severity_below_baseline", "vp:critical high") == [
        'set profiles vulnerability vp rules "critical high" action reset-both',
        'set profiles vulnerability vp rules "critical high" packet-capture single-packet']
    assert cmds(data, "spyware_dns_category_mismatch", "as:pan-dns-sec-cc") == [
        "set profiles spyware as botnet-domains sinkhole ipv4-address pan-sinkhole-default-ip",
        "set profiles spyware as botnet-domains sinkhole ipv6-address ::1",
        "set profiles spyware as botnet-domains dns-security-categories pan-dns-sec-cc action sinkhole"]


def test_inline_cloud_analysis():
    data = pdata(spyware=[prof("as", inline_cloud_analysis={"enabled": False, "models": {
        "HTTP Command and Control detector": "alert", "DNS": "reset-both"}})])
    assert cmds(data, "spyware_inline_cloud_analysis_disabled", "as") == [
        "set profiles spyware as cloud-inline-analysis yes",
        'set profiles spyware as mica-engine-spyware-enabled "HTTP Command and Control detector" '
        "inline-policy-action reset-both"]


def test_url_categories_move_between_lists():
    data = pdata(url_filtering=[prof("uf", block_categories=["malware"], alert_categories=["hacking", "gambling"],
                                     allow_categories=["adult"], continue_categories=[], override_categories=[],
                                     credential_allow_categories=["gambling"], credential_alert_categories=[],
                                     credential_continue_categories=[], credential_enforcement_block_categories=[])])
    assert cmds(data, "url_elevated_risk_category_not_blocked", "uf:hacking") == [
        "delete profiles url-filtering uf alert hacking", "set profiles url-filtering uf block hacking"]
    liab = cmds(data, "url_liability_categories_not_blocked", "uf")
    assert liab[:2] == ["delete profiles url-filtering uf allow adult", "delete profiles url-filtering uf alert gambling"]
    assert liab[-1].startswith("set profiles url-filtering uf block [ abused-drugs adult copyright-infringement")
    assert cmds(data, "url_categories_allowed_unlogged", "uf") == [
        "delete profiles url-filtering uf allow adult", "set profiles url-filtering uf alert adult"]
    assert cmds(data, "url_credential_submissions_unlogged", "uf") == [
        "delete profiles url-filtering uf credential-enforcement allow gambling",
        "set profiles url-filtering uf credential-enforcement alert gambling"]


def test_file_blocking_rule_has_editable_default_types():
    data = pdata(file_blocking=[prof("fb", rules=[{"name": "r", "action": "alert"}])])
    out = cli.for_finding(f("file_blocking_nothing_blocked", "fb"), cli.Context(data))
    assert "file-type [ {{file_types}} ] direction both action block" in out["commands"][0]
    assert out["choices"][0]["default"].startswith("7z bat") and out["choices"][0]["free"] is True


def test_wildfire_file_type_and_size_limit():
    data = pdata(wildfire_analysis=[prof("wf", rules=[{"name": "default", "file_types": ["pe"]}])])
    data["device_settings"] = {"wildfire": {"size_limits": {"pdf": 1000}}}
    assert cmds(data, "wildfire_missing_recommended_filetype", "wf:pdf") == [
        "set profiles wildfire-analysis wf rules default file-type pdf"]
    assert cmds(data, "wildfire_size_limit_below_default", "pdf") == [
        "set deviceconfig setting wildfire file-size-limit pdf size-limit 3072"]


# ── Panorama-managed firewalls ───────────────────────────────────────────

def _annotated(data):
    findings = [f("security_rule_no_logging_allow", "Allow Web")]
    cli.annotate(findings, data)
    return findings[0]["cli"]


def test_panorama_managed_firewall_gets_no_commands():
    """A managed firewall's own export or tech support file doesn't say which rules Panorama pushed, so
    commands typed at the firewall would miss or be undone by the next push: none are offered."""
    data = {"panorama_managed": True, "security_rules": [rule("Allow Web")]}
    assert cli.unavailable_reason(data) and "Panorama" in cli.unavailable_reason(data)
    assert _annotated(data) is None


def test_panorama_export_still_gets_panorama_commands():
    data = {"panorama_managed": True, "device_group": "Branch",
            "security_rules": [rule("Allow Web", rule_scope="device_group_pre")]}
    assert cli.unavailable_reason(data) is None
    assert _annotated(data)["commands"] == ["set device-group Branch pre-rulebase security rules \"Allow Web\" log-end yes"]


def test_standalone_firewall_is_unchanged():
    data = {"security_rules": [rule("Allow Web")]}
    assert cli.unavailable_reason(data) is None
    assert _annotated(data)["commands"] == ['set rulebase security rules "Allow Web" log-end yes']

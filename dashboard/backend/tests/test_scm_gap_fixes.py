"""Gaps a real Palo Alto SCM run showed the core rules missing: PAN-OS defaults, profiles graded
whether used or not, the checks SCM links to, and SCM findings that aren't gaps at all."""
import xml.etree.ElementTree as ET

from app import parser
from app.rules import checks, scm_coverage
from app.rules.builtin_profiles import unused_builtins
from app.rules.definitions import SCM_MATCHES
from app.rules.engine import DEFAULT_WEIGHTS


def _config(inner: str) -> dict:
    return parser.parse_config(f"<config><shared>{inner}</shared></config>".encode())


def _run(rule_id: str, data: dict) -> list[dict]:
    return checks.CHECKS[rule_id](data, {})


# ── PAN-OS defaults ──────────────────────────────────────────────────────

def test_url_log_container_page_only_is_on_when_unset():
    """PAN-OS logs only the container page unless told otherwise (SCM #44)."""
    unset = ET.fromstring("<entry name='u'/>")
    assert parser.parse_profile_settings(unset, "url_filtering")["log_container_page_only"] is True
    explicit = ET.fromstring("<entry name='u'><log-container-page-only>no</log-container-page-only></entry>")
    assert parser.parse_profile_settings(explicit, "url_filtering")["log_container_page_only"] is False


def test_radius_profile_without_a_protocol_is_chap():
    """PAN-OS uses CHAP when no protocol is chosen; SCM #233 wants EAP."""
    data = _config("<server-profile><radius><entry name='r1'><server/></entry></radius></server-profile>")
    assert data["mgmt_plane"]["radius"] == [{"name": "r1", "protocol": "CHAP"}]
    assert [f["key"] for f in _run("radius_weak_protocol", data)] == ["r1"]
    eap = _config("<server-profile><radius><entry name='r2'><protocol><EAP-TTLS-with-PAP/></protocol></entry>"
                  "</radius></server-profile>")
    assert _run("radius_weak_protocol", eap) == []


def test_single_ntp_server_is_flagged():
    one = _run("no_ntp", {"management": {"ntp_primary": "192.0.2.1", "ntp_secondary": None}})
    assert [f["key"] for f in one] == ["no-secondary"]
    assert _run("no_ntp", {"management": {"ntp_primary": "192.0.2.1", "ntp_secondary": "192.0.2.2"}}) == []
    assert [f["key"] for f in _run("no_ntp", {"management": {}})] == ["global"]


# ── GlobalProtect TLS maximum (SCM #76) ──────────────────────────────────

def _gp_gateway(min_v: str, max_v: str) -> dict:
    tls = {"name": "gp-tls", "found": True, "min_version": min_v, "max_version": max_v}
    return {"globalprotect": {"portals": [], "gateways": [{"name": "gw", "tls": tls}]}}


def test_gp_tls_maximum_capped_below_max_is_flagged():
    capped = _run("gp_tls_below_1_2", _gp_gateway("tls1-2", "tls1-2"))
    assert len(capped) == 1 and "caps the maximum" in capped[0]["message"]
    assert _run("gp_tls_below_1_2", _gp_gateway("tls1-2", "max")) == []
    both = _run("gp_tls_below_1_2", _gp_gateway("tls1-0", "tls1-1"))[0]["message"]
    assert "allows" in both and "caps the maximum" in both


# ── Decryption: SSL Forward Proxy options (SCM #55) ──────────────────────

FORWARD_ALL_ON = "".join(f"<{o}>yes</{o}>" for o in parser.FORWARD_CHECKS)


def _decryption(profile_xml: str, rules: list[dict] | None = None) -> dict:
    return {"decryption": {"rules": rules or [], "profiles": [parser.parse_decryption_profile_entry(ET.fromstring(profile_xml))]}}


def test_forward_proxy_options_off_are_flagged_on_unused_profiles_too():
    off = _run("decryption_forward_proxy_checks_off", _decryption("<entry name='fp'><ssl-forward-proxy/></entry>"))
    assert len(off) == 1 and "not used by any decryption rule" in off[0]["message"]
    assert off[0]["scm_object"] == {"type": "decryption_profile", "name": "fp"}
    hardened = _decryption(f"<entry name='fp'><ssl-forward-proxy>{FORWARD_ALL_ON}</ssl-forward-proxy></entry>")
    assert _run("decryption_forward_proxy_checks_off", hardened) == []


def test_strip_alpn_is_not_required():
    assert "strip-alpn" not in parser.FORWARD_CHECKS


# ── Links to SCM checks ──────────────────────────────────────────────────

def test_disabled_features_also_answer_the_checks_about_their_settings():
    # Inline cloud analysis off means its per-model actions (SCM #360 / #334) can't be right either.
    assert 360 in SCM_MATCHES["vulnerability_inline_cloud_analysis_disabled"]
    assert 334 in SCM_MATCHES["spyware_inline_cloud_analysis_disabled"]
    # Credential detection off fails "use the domain credential filter" (SCM #227) too.
    assert 227 in SCM_MATCHES["url_credential_enforcement_disabled"]
    assert SCM_MATCHES["decryption_forward_proxy_checks_off"] == (55,)


# ── Coverage: SCM findings that aren't gaps ──────────────────────────────

def _scm(cid: int, object_type: str, name: str, duplicate_of=None) -> dict:
    return {"rule_id": f"scm_{cid}", "finding_key": f"scm_{cid}:{object_type}:{name}", "title": f"check {cid}",
            "category": "Decryption", "severity": "WARNING", "program": "scm", "scm_check_ids": [cid],
            "duplicate_of": duplicate_of or [], "dismissed": False, "not_scored_reason": None}


def _row(cid: int, object_type: str, name: str) -> dict:
    return {"check_id": cid, "object_type": object_type, "object_name": name, "passed": False, "excluded": False,
            "failed_fields": {"x": False}}


def test_unused_builtins_lists_predefined_profiles_nothing_defines_or_uses():
    data = {"security_profiles": {"url_filtering": [{"name": "corp-url", "settings": {}}]},
            "security_rules": [{"name": "r", "disabled": "no", "indiv_profiles": {"vulnerability": ["strict"]}}],
            "decryption": {"rules": [], "profiles": []}}
    skip = unused_builtins(data)
    assert ("decryption_profile", "default") in skip
    assert ("url_filtering_profile", "default") in skip
    assert ("vulnerability_protection_profile", "strict") not in skip  # a rule uses it: it's graded
    assert ("url_filtering_profile", "corp-url") not in skip


def test_unused_builtin_and_standalone_ha_are_not_applicable():
    data = {"decryption": {"rules": [], "profiles": []}, "ha_config": {"enabled": False}}
    findings = [_scm(57, "decryption_profile", "default"), _scm(145, "high_availability", "global")]
    rows = [_row(57, "decryption_profile", "default"), _row(145, "high_availability", None)]
    cov = scm_coverage.build(findings, rows, {}, DEFAULT_WEIGHTS, data)
    assert {c["check_id"]: c["status"] for c in cov["checks"]} == {57: "not_applicable", 145: "not_applicable"}
    text = scm_coverage.as_text(cov)
    assert "[not_applicable] 2 checks" in text and "[core_missed]" not in text


def test_ha_checks_still_count_when_ha_is_enabled():
    data = {"ha_config": {"enabled": True}}
    cov = scm_coverage.build([_scm(145, "high_availability", "global")], [_row(145, "high_availability", None)],
                             {}, DEFAULT_WEIGHTS, data)
    assert cov["checks"][0]["status"] == "core_missed"


def test_mixed_check_is_judged_on_the_objects_the_core_rules_grade():
    """Four custom URL profiles covered by core findings plus the unused built-in 'default': covered."""
    data = {"security_profiles": {"url_filtering": [{"name": f"u{i}", "settings": {}} for i in range(4)]},
            "security_rules": [], "decryption": {"rules": [], "profiles": []}}
    findings = [_scm(273, "url_filtering_profile", f"u{i}", duplicate_of=["url_inline_categorization_off"])
                for i in range(4)] + [_scm(273, "url_filtering_profile", "default")]
    rows = [_row(273, "url_filtering_profile", f"u{i}") for i in range(4)] + [_row(273, "url_filtering_profile", "default")]
    check = scm_coverage.build(findings, rows, {}, DEFAULT_WEIGHTS, data)["checks"][0]
    assert check["status"] == "covered" and check["objects"] == 4 and check["not_applicable_objects"] == 1


def test_without_parsed_data_nothing_is_marked_not_applicable():
    cov = scm_coverage.build([_scm(57, "decryption_profile", "default")], [_row(57, "decryption_profile", "default")],
                             {}, DEFAULT_WEIGHTS)
    assert cov["checks"][0]["status"] == "core_missed"


# ── Second pass on the same SCM run ──────────────────────────────────────

def test_radius_profile_in_a_vsys_is_read():
    data = parser.parse_config(b"<config><devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>"
                               b"<server-profile><radius><entry name='vr'><protocol><PAP/></protocol></entry></radius>"
                               b"</server-profile></entry></vsys></entry></devices></config>")
    assert data["mgmt_plane"]["radius"] == [{"name": "vr", "protocol": "PAP"}]
    assert [f["key"] for f in _run("radius_weak_protocol", data)] == ["vr"]


def _lf(dests: list[str]) -> dict:
    return {"log_forwarding_profiles": [{"name": "lf", "lists": [{"log_type": "traffic", "destinations": dests}]}],
            "security_rules": []}


def test_log_forwarding_needs_somewhere_that_keeps_the_logs():
    only_email = _run("log_forwarding_profile_no_destination", _lf(["email:ops"]))
    assert len(only_email) == 1 and "sends logs only by email" in only_email[0]["message"]
    assert _run("log_forwarding_profile_no_destination", _lf(["panorama"])) == []
    assert _run("log_forwarding_profile_no_destination", _lf(["syslog:siem", "email:ops"])) == []
    assert "has no destination" in _run("log_forwarding_profile_no_destination", _lf([]))[0]["message"]


def test_disabled_pbf_rules_are_not_applicable():
    data = {"misc_policy": {"pbf_rules": [{"name": "old", "disabled": True}, {"name": "live", "disabled": False}]}}
    findings = [_scm(17, "policy_based_forwarding_rule", "old"),
                _scm(17, "policy_based_forwarding_rule", "live", duplicate_of=["pbf_no_monitor"])]
    rows = [_row(17, "policy_based_forwarding_rule", "old"), _row(17, "policy_based_forwarding_rule", "live")]
    check = scm_coverage.build(findings, rows, {}, DEFAULT_WEIGHTS, data)["checks"][0]
    assert check["status"] == "covered" and check["not_applicable_objects"] == 1


# ── Deliberate differences from SCM ──────────────────────────────────────

def test_peap_radius_is_a_deliberate_difference_not_a_gap():
    data = {"mgmt_plane": {"radius": [{"name": "mfa", "protocol": "PEAP-MSCHAPv2"}]}}
    assert _run("radius_weak_protocol", data) == []
    cov = scm_coverage.build([_scm(233, "radius_server_profile", "mfa")], [_row(233, "radius_server_profile", "mfa")],
                             {}, DEFAULT_WEIGHTS, data)
    check = cov["checks"][0]
    assert check["status"] == "by_design" and "PEAP-MSCHAPv2" in check["reason"]
    text = scm_coverage.as_text(cov)
    assert "[by_design]" in text and "why: uses PEAP-MSCHAPv2" in text and "mfa" not in text


def test_a_pap_radius_profile_scm_flags_is_still_a_miss():
    data = {"mgmt_plane": {"radius": [{"name": "old", "protocol": "PEAP-MSCHAPv2"}]}}
    cov = scm_coverage.build([_scm(233, "radius_server_profile", "other")], [_row(233, "radius_server_profile", "other")],
                             {}, DEFAULT_WEIGHTS, data)
    assert cov["checks"][0]["status"] == "core_missed"


def _portal(**config) -> dict:
    base = {"name": "cfg", "connect_method": "on-demand", "user_override": "allowed", "override_timeout_min": None,
            "internal_gateways": 0, "external_gateways": 1, "internal_host_detection": False}
    return {"globalprotect": {"portals": [{"name": "portal", "agent_configs": [{**base, **config}]}], "gateways": []}}


def test_gp_checks_skipped_on_purpose_are_deliberate_differences():
    data = _portal()
    assert _run("gp_user_can_disable", data) == [] and _run("gp_no_internal_host_detection", data) == []
    findings = [_scm(69, "global_protect_portal", "portal"), _scm(68, "global_protect_portal", "portal")]
    rows = [_row(69, "global_protect_portal", "portal"), _row(68, "global_protect_portal", "portal")]
    statuses = {c["check_id"]: c["status"] for c in scm_coverage.build(findings, rows, {}, DEFAULT_WEIGHTS, data)["checks"]}
    assert statuses == {69: "by_design", 68: "by_design"}


def test_always_on_portal_without_a_timeout_is_not_excused():
    data = _portal(connect_method="user-logon")
    assert len(_run("gp_user_can_disable", data)) == 1
    cov = scm_coverage.build([_scm(69, "global_protect_portal", "portal")], [_row(69, "global_protect_portal", "portal")],
                             {}, DEFAULT_WEIGHTS, data)
    assert cov["checks"][0]["status"] != "by_design"

"""Predefined PAN-OS profiles graded when the config uses one, plus SCM 347/350 counterparts."""
from app import parser
from app.rules import builtin_profiles, cli
from app.rules.engine import run_rules

CONFIG = """<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<profile-group><entry name="pg"><virus><member>default</member></virus></entry></profile-group>
<profiles><spyware><entry name="default"><rules><entry name="all"><severity><member>critical</member>
<member>high</member><member>medium</member></severity><action><reset-both/></action>
<packet-capture>single-packet</packet-capture></entry></rules></entry></spyware>{extra_profiles}</profiles>
<rulebase><security><rules>
<entry name="web"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source>
<destination><member>any</member></destination><application><member>web-browsing</member></application>
<service><member>application-default</member></service><action>allow</action>
<profile-setting>{profile_setting}</profile-setting></entry>
<entry name="off"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source>
<destination><member>any</member></destination><application><member>ssh</member></application>
<service><member>application-default</member></service><action>allow</action><disabled>yes</disabled>
<profile-setting><profiles><url-filtering><member>default</member></url-filtering></profiles></profile-setting></entry>
</rules></security>
<decryption><rules>{decrypt_rules}</rules></decryption></rulebase>
</entry></vsys></entry></devices></config>"""

FORWARD = ('<entry name="out"><type><ssl-forward-proxy/></type><action>decrypt</action>'
           '<profile>{profile}</profile></entry>')
STRONG = ('<decryption><entry name="bp"><ssl-forward-proxy><block-expired-certificate>yes</block-expired-certificate>'
          '<block-untrusted-issuer>yes</block-untrusted-issuer></ssl-forward-proxy>'
          '<ssl-protocol-settings><min-version>tls1-2</min-version></ssl-protocol-settings></entry></decryption>')


def _data(profile_setting="", decrypt_rules="", extra_profiles=""):
    return parser.parse_config(CONFIG.format(profile_setting=profile_setting, decrypt_rules=decrypt_rules,
                                             extra_profiles=extra_profiles).encode())


def _names(data, ptype):
    return [p["name"] for p in data["security_profiles"][ptype]]


def test_builtins_added_only_when_an_enabled_rule_uses_them():
    data = _data('<profiles><vulnerability><member>strict</member></vulnerability>'
                 '<spyware><member>default</member></spyware></profiles><group><member>pg</member></group>')
    out, added = builtin_profiles.with_builtins(data)
    # vulnerability "strict" directly, antivirus "default" through the group; the config's own spyware
    # "default" wins over the built-in; url-filtering "default" is only on a disabled rule.
    assert added == {("vulnerability", "strict"), ("antivirus", "default")}
    assert _names(out, "vulnerability") == ["strict"] and _names(out, "antivirus") == ["default"]
    assert _names(out, "spyware") == ["default"] and _names(out, "url_filtering") == []
    assert out["security_profiles"]["vulnerability"][0]["rule_count"] == 1
    assert data["security_profiles"]["vulnerability"] == []  # the stored data is left alone


def test_builtin_findings_say_to_clone_and_have_no_cli():
    data = _data('<profiles><virus><member>default</member></virus></profiles>')
    out, added = builtin_profiles.with_builtins(data)
    findings = [f for f in run_rules(out, {}) if f["rule_id"] == "av_decoder_below_baseline"]
    assert findings, "the built-in default antivirus profile doesn't reset on its decoders"
    builtin_profiles.annotate(findings, added)
    assert all(f["builtin_profile"] == "default" and "predefined PAN-OS profile" in f["recommendation"]
               for f in findings)
    cli.annotate(findings, out)
    assert all(f["cli"] is None for f in findings)


def test_unused_builtins_not_graded():
    _, added = builtin_profiles.with_builtins(_data())
    assert added == set()


def test_builtin_decryption_default_used_by_a_rule():
    out, added = builtin_profiles.with_builtins(_data(decrypt_rules=FORWARD.format(profile="default")))
    assert added == {("decryption", "default")}
    findings = run_rules(out, {})
    builtin_profiles.annotate(findings, added)
    by_key = {f["finding_key"]: f for f in findings}
    for key in ("decryption_profile_weak_tls:default", "decryption_weak_hmac:default"):
        assert by_key[key]["builtin_profile"] == "default"
    assert "decryption_no_best_practice_profile:global" in by_key


def test_best_practice_decryption_profile_passes():
    keys = {f["finding_key"] for f in run_rules(_data(decrypt_rules=FORWARD.format(profile="bp"),
                                                      extra_profiles=STRONG), {})}
    assert "decryption_no_best_practice_profile:global" not in keys


def test_no_best_practice_profile_not_raised_without_outbound_decryption():
    keys = {f["finding_key"] for f in run_rules(_data(), {})}
    assert "decryption_no_outbound:global" in keys
    assert "decryption_no_best_practice_profile:global" not in keys


def test_hold_mode_flagged_when_no_antivirus_profile_exists():
    data = _data()
    data["system_info"] = {**data["system_info"], "sw_version": "11.1.4"}
    findings = [f for f in run_rules(data, {}) if f["rule_id"] == "wildfire_realtime_hold_off"]
    assert [f["message"].split(":")[0] for f in findings] == [
        "No Antivirus profile holds files for WildFire real-time signature lookup"]

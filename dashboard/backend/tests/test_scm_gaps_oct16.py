"""Gaps from an Oct 16 2026 SCM run: checks #58/#373, #103, #228 and #45 that core rules missed, and
#414, #108 and #107, new from Palo Alto. A small synthetic config (no client data)."""
from app import parser
from app.rules import cli, scm_catalog, scm_findings
from app.rules.engine import run_rules

CONFIG = """<config version="11.1.0">
  <mgt-config><password-complexity><enabled>yes</enabled><minimum-length>12</minimum-length>
    <minimum-uppercase-letters>1</minimum-uppercase-letters><minimum-numeric-letters>1</minimum-numeric-letters>
    <minimum-special-characters>1</minimum-special-characters></password-complexity></mgt-config>
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>fw-gaps</hostname></system>
      <setting><ctd><x-forwarded-for>no</x-forwarded-for><strip-x-fwd-for>no</strip-x-fwd-for></ctd></setting></deviceconfig>
    <network><profiles><interface-management-profile>
      <entry name="spare-open"><http>yes</http><telnet>yes</telnet><https>yes</https></entry>
    </interface-management-profile></profiles><interface/></network>
    <vsys><entry name="vsys1">
      <profiles>
        <decryption><entry name="bypass-profile"><ssl-forward-proxy><block-expired-certificate>yes</block-expired-certificate></ssl-forward-proxy></entry></decryption>
        <file-blocking>
          <entry name="some-blocking"><rules><entry name="block-exe"><application><member>any</member></application>
            <file-type><member>exe</member><member>dll</member></file-type><direction>both</direction><action>block</action></entry></rules></entry>
          <entry name="strict-like"><rules>
            <entry name="block"><application><member>any</member></application><file-type>
              <member>7z</member><member>bat</member><member>chm</member><member>class</member><member>cpl</member><member>dll</member>
              <member>hlp</member><member>hta</member><member>jar</member><member>ocx</member><member>pif</member><member>scr</member>
              <member>torrent</member><member>vbe</member><member>wsf</member></file-type><direction>both</direction><action>block</action></entry>
            <entry name="alert"><application><member>any</member></application><file-type><member>any</member></file-type>
              <direction>both</direction><action>alert</action></entry></rules></entry>
          <entry name="alert-only"><rules><entry name="a"><application><member>any</member></application>
            <file-type><member>any</member></file-type><direction>both</direction><action>alert</action></entry></rules></entry>
        </file-blocking>
      </profiles>
      <rulebase/>
    </entry></vsys>
  </entry></devices>
  <shared/>
</config>"""


def _findings(settings=None):
    data = parser.parse_config(CONFIG.encode())
    return data, {f["finding_key"]: f for f in run_rules(data, settings or {})}


def test_no_decryption_checks_default_to_off():
    data, fs = _findings()
    [p] = data["decryption"]["profiles"]
    assert p["no_proxy_block_expired"] is False and p["no_proxy_block_untrusted"] is False
    for field in ("no_proxy_block_expired", "no_proxy_block_untrusted"):
        f = fs[f"decryption_no_decrypt_cert_checks:bypass-profile:{field}"]
        assert f["scm_object"] == {"type": "decryption_profile", "name": "bypass-profile"}


def test_password_complexity_needs_every_character_type():
    data, fs = _findings()
    assert data["mgmt_plane"]["password_complexity"]["minimum_classes"]["lowercase letter"] == 0
    f = fs["password_complexity_weak:global"]
    assert "don't need a lowercase letter" in f["message"] and "minimum length" not in f["message"]
    assert "minimum-lowercase-letters 1" in " ".join(cli.for_finding(f, cli.Context(data))["commands"])


def test_unattached_management_profile_is_graded():
    _, fs = _findings()
    f = fs["mgmt_profile_cleartext:spare-open"]
    assert "Telnet and HTTP" in f["message"] and "not attached to any interface yet" in f["message"]


def test_file_blocking_recommended_types():
    data, fs = _findings()
    f = fs["file_blocking_missing_recommended:some-blocking"]
    assert "doesn't block 7z, bat" in f["message"] and "no alert rule" in f["message"]
    assert "dll" not in f["message"].split("doesn't block")[1].split(" and ")[0].split(", ")
    assert "file_blocking_missing_recommended:strict-like" not in fs
    # Blocking nothing at all is the other rule's finding, not this one's.
    assert "file_blocking_nothing_blocked:alert-only" in fs and "file_blocking_missing_recommended:alert-only" not in fs
    cmds = cli.for_finding(f, cli.Context(data))["commands"]
    assert cmds[0].endswith("direction both action block") and "torrent" in cmds[0]
    assert cmds[1].endswith("file-type any direction both action alert")


def test_x_forwarded_for_settings():
    data, fs = _findings()
    assert data["device_settings"]["xff_strip"] is False and data["device_settings"]["xff_userid"] is False
    assert "xff_not_stripped:global" in fs
    assert "xff_userid_off:global" not in fs  # off by default: only matters behind an upstream proxy
    _, on = _findings({"xff_userid_off": {"enabled": True, "threshold_overrides": None, "severity_override": None}})
    assert "xff_userid_off:global" in on


def test_new_palo_alto_checks_are_in_the_bundled_list_and_linked():
    cat = scm_catalog.checks_by_id()
    assert {414, 108, 107} <= set(cat) and cat[414]["severity"] == "Critical"
    assert scm_catalog.as_of() == "2026-10-16"
    linked = scm_findings.core_rules_by_scm_check()
    assert "wildfire_realtime_hold_off" in linked[414]
    assert linked[108] == ["xff_not_stripped"] and linked[107] == ["xff_userid_off"]
    assert set(linked[45]) == {"file_blocking_nothing_blocked", "file_blocking_missing_recommended"}
    assert not scm_catalog.enabled_by_default(107)

import xml.etree.ElementTree as ET

from app import panorama_parser, parser
from app.rules import mgmt_exposure
from app.rules.engine import run_rules


def rule(name, action="allow", from_=("any",), to=("any",), src=("any",), dst=("any",),
         app=("any",), svc=("any",), **extra):
    # Full parse_rule_entry() shape, since run_rules runs every check against it.
    return {"name": name, "action": action, "disabled": "no", "from_zones": list(from_), "to_zones": list(to),
            "sources": list(src), "destinations": list(dst), "applications": list(app),
            "services": list(svc), "source_users": ["any"], "negate_source": "no",
            "negate_destination": "no", "rule_type": "universal", "log_end": "yes", "log_start": "no",
            "description": "test rule", "profile_group": "", "indiv_profiles": {}, "tags": [],
            "log_setting": "default", "rule_scope": None, **extra}


DENY_REMAINING = rule("deny-remaining", action="deny")


def make_data(rules, *, permitted=(), ips=("10.1.1.1/24",), dhcp=False, services=("https", "ssh"),
              objects=None, defaults=None):
    """One firewall: 'inside' (ethernet1/1, the mgmt interface under test) and 'outside' (ethernet1/2)."""
    return {
        "zones": [
            {"name": "inside", "interfaces": ["ethernet1/1"]},
            {"name": "outside", "interfaces": ["ethernet1/2"]},
        ],
        "interface_mgmt_profiles": [{
            "name": "mgmt", "permitted_ip": list(permitted), "interfaces": ["ethernet1/1"],
            "services": {s: s in services for s in ("https", "ssh", "ping", "snmp", "http", "http-ocsp", "telnet")},
        }],
        "mgmt_interfaces": [{"name": "ethernet1/1", "mgmt_profile": "mgmt", "ips": list(ips), "dhcp": dhcp}],
        "policy_objects": {"addresses": {}, "address_groups": {}, "services": {}, "service_groups": {},
                           "application_groups": {}, "application_filters": [], **(objects or {})},
        "default_rule_actions": defaults or {},
        "security_rules": rules,
    }


def result(data, svc="https", source_zone="inside"):
    [entry] = mgmt_exposure.analyze(data)
    return next(r for r in entry["services"][svc] if r["source_zone"] == source_zone)


def findings(data):
    return [f for f in run_rules(data, {}) if f["rule_id"] == "mgmt_interface_open_to_any_source"]


# ── The default rules only apply when nothing explicit matched ────────────

def test_catch_all_deny_ends_the_walk_before_intrazone_default():
    r = result(make_data([DENY_REMAINING]))
    assert r["status"] == "blocked"
    assert r["via"] == "deny-remaining"  # never "intrazone-default"
    assert findings(make_data([DENY_REMAINING])) == []


def test_catch_all_deny_also_ends_the_walk_before_interzone_default():
    assert result(make_data([DENY_REMAINING]), source_zone="outside")["via"] == "deny-remaining"


def test_no_rules_falls_through_to_implicit_defaults():
    data = make_data([])
    assert result(data, source_zone="inside")["status"] == "open"
    assert result(data, source_zone="inside")["via"] == "intrazone-default"
    assert result(data, source_zone="outside")["status"] == "blocked"
    assert result(data, source_zone="outside")["via"] == "interzone-default"


def test_overridden_intrazone_default_is_respected():
    r = result(make_data([], defaults={"intrazone-default": "deny"}))
    assert (r["status"], r["via"]) == ("blocked", "intrazone-default")


def test_overridden_interzone_default_allow_opens_it():
    r = result(make_data([], defaults={"interzone-default": "allow"}), source_zone="outside")
    assert (r["status"], r["via"]) == ("open", "interzone-default")


# ── Specific-source allow rules restrict rather than open ────────────────

def test_specific_source_allow_then_deny_is_restricted():
    data = make_data([
        rule("allow-admins", src=["10.1.1.50"], dst=["10.1.1.1"], app=["panos-web-interface", "ssh"]),
        DENY_REMAINING,
    ])
    r = result(data)
    assert r["status"] == "restricted"
    assert r["specific_allows"] == ["allow-admins"]
    assert r["via"] == "deny-remaining"
    assert findings(data) == []


def test_specific_source_allow_without_a_deny_still_open_via_default():
    # Only the admin rule — but everyone else in the zone falls through to intrazone-default (allow)
    data = make_data([rule("allow-admins", src=["10.1.1.50"])])
    r = result(data)
    assert (r["status"], r["via"], r["specific_allows"]) == ("open", "intrazone-default", ["allow-admins"])
    assert len(findings(data)) == 1


def test_source_user_restriction_counts_as_specific():
    data = make_data([rule("admins-by-user", source_users=["corp\\netadmins"]), DENY_REMAINING])
    assert result(data)["status"] == "restricted"


def test_negated_source_counts_as_specific():
    data = make_data([rule("not-guests", src=["10.9.0.0/16"], negate_source="yes"), DENY_REMAINING])
    assert result(data)["status"] == "restricted"


# ── The permitted-IP layer ───────────────────────────────────────────────

def test_permitted_ip_list_suppresses_the_finding_even_if_policy_is_open():
    data = make_data([rule("allow-all")], permitted=["10.1.1.50"])
    assert result(data)["status"] == "open"  # policy layer shown honestly on the dashboard
    assert findings(data) == []


def test_finding_message_names_zone_and_rule():
    data = make_data([rule("allow-all", from_=["outside"]), DENY_REMAINING])
    [f] = findings(data)
    assert f["finding_key"] == "mgmt_interface_open_to_any_source:ethernet1/1"
    assert "HTTPS, SSH on ethernet1/1 (zone inside" in f["message"]
    assert "from outside via rule 'allow-all'" in f["message"]
    assert "from inside" not in f["message"]  # deny-remaining blocks inside


# ── The classic gotcha: an outbound internet rule with destination any ──

def test_outbound_web_rule_with_any_destination_exposes_https_on_that_interface():
    data = make_data([
        rule("inside-to-internet", from_=["inside"], to=["inside"], app=["ssl", "web-browsing"],
             svc=["application-default"]),
        DENY_REMAINING,
    ])
    assert result(data, "https")["status"] == "open"
    assert result(data, "ssh")["status"] == "blocked"  # ssh isn't ssl/web-browsing


# ── Zone / rule-type matching ────────────────────────────────────────────

def test_rule_type_interzone_never_matches_intrazone_traffic():
    data = make_data([rule("interzone-allow", rule_type="interzone"), DENY_REMAINING])
    assert result(data, source_zone="inside")["via"] == "deny-remaining"
    assert result(data, source_zone="outside")["via"] == "interzone-allow"


def test_rule_type_intrazone_ignores_to_zones():
    data = make_data([rule("intra-allow", from_=["inside"], to=["outside"], rule_type="intrazone"),
                      DENY_REMAINING])
    assert result(data, source_zone="inside")["via"] == "intra-allow"


def test_disabled_rule_is_skipped():
    data = make_data([rule("off", disabled="yes"), DENY_REMAINING])
    assert result(data)["via"] == "deny-remaining"


# ── Address / service / application resolution ───────────────────────────

OBJECTS = {
    "addresses": {
        "fw-inside": {"type": "ip-netmask", "value": "10.1.1.1/32"},
        "servers": {"type": "ip-netmask", "value": "10.2.0.0/16"},
        "range-obj": {"type": "ip-range", "value": "10.1.1.0-10.1.1.10"},
        "some-fqdn": {"type": "fqdn", "value": "example.com"},
    },
    "address_groups": {
        "fw-ips": {"dynamic": False, "members": ["fw-inside"]},
        "nested": {"dynamic": False, "members": ["fw-ips"]},
        "dyn": {"dynamic": True, "members": []},
    },
    "services": {"tcp-8443": {"tcp": "8443", "udp": None}, "web-ports": {"tcp": "80,440-450", "udp": None}},
    "service_groups": {"mgmt-svcs": ["service-https", "tcp-8443"]},
    "application_groups": {"admin-apps": ["ssh", "panos-web-interface"]},
    "application_filters": ["risky-filter"],
}


def test_destination_resolves_objects_groups_and_ranges():
    for dst in (["fw-inside"], ["nested"], ["range-obj"], ["10.1.1.0/24"]):
        data = make_data([rule("allow", dst=dst), DENY_REMAINING], objects=OBJECTS)
        assert result(data)["via"] == "allow", dst


def test_destination_elsewhere_does_not_match():
    data = make_data([rule("to-servers", dst=["servers"]), DENY_REMAINING], objects=OBJECTS)
    assert result(data)["via"] == "deny-remaining"


def test_negated_destination():
    data = make_data([rule("not-servers", dst=["servers"], negate_destination="yes"), DENY_REMAINING],
                     objects=OBJECTS)
    assert result(data)["via"] == "not-servers"


def test_interface_ip_given_as_address_object():
    data = make_data([rule("allow", dst=["servers"]), DENY_REMAINING], ips=["fw-inside"], objects=OBJECTS)
    assert result(data)["via"] == "deny-remaining"
    [entry] = mgmt_exposure.analyze(data)
    assert entry["address_known"] is True


def test_service_objects_groups_and_ranges():
    data = make_data([rule("allow", svc=["mgmt-svcs"]), DENY_REMAINING], objects=OBJECTS)
    assert result(data, "https")["via"] == "allow"
    assert result(data, "ssh")["via"] == "deny-remaining"
    data = make_data([rule("allow", svc=["web-ports"]), DENY_REMAINING], objects=OBJECTS)
    assert result(data, "https")["via"] == "allow"  # 443 is inside 440-450


def test_application_group_resolves():
    data = make_data([rule("allow", app=["admin-apps"]), DENY_REMAINING], objects=OBJECTS)
    assert result(data, "ssh")["via"] == "allow"


# ── Unresolvable objects → uncertain, never a finding ─────────────────────

def test_dynamic_group_on_an_allow_any_rule_makes_it_uncertain_leaning_closed():
    data = make_data([rule("dyn-allow", dst=["dyn"]), DENY_REMAINING], objects=OBJECTS)
    r = result(data)
    assert (r["status"], r["lean"], r["via"]) == ("uncertain", "closed", "deny-remaining")
    assert r["unresolved_rules"] == [{
        "rule": "dyn-allow", "action": "allow",
        "causes": [{"field": "destination", "kind": "dynamic address group", "object": "dyn"}],
    }]
    assert findings(data) == []


def test_unresolvable_deny_before_an_allow_makes_it_uncertain_leaning_open():
    # The real-world shape: an allow-any rule reaches the interface unless an earlier deny,
    # which uses an object that can't be resolved, happens to match first
    data = make_data([rule("maybe-deny", action="deny", dst=["some-fqdn"]), rule("allow-all")],
                     objects=OBJECTS)
    r = result(data)
    assert (r["status"], r["lean"], r["via"]) == ("uncertain", "open", "allow-all")
    [u] = r["unresolved_rules"]
    assert (u["rule"], u["action"]) == ("maybe-deny", "block")
    assert u["causes"] == [{"field": "destination", "kind": "FQDN address object", "object": "some-fqdn"}]
    assert findings(data) == []


def test_unresolved_rule_that_cant_flip_the_outcome_is_not_listed():
    # An unresolvable deny before a definite deny changes nothing
    data = make_data([rule("maybe-deny", action="deny", dst=["dyn"]), DENY_REMAINING], objects=OBJECTS)
    r = result(data)
    assert (r["status"], r["lean"], r["unresolved_rules"]) == ("blocked", None, [])


def test_unknown_address_name_is_reported_as_such():
    data = make_data([rule("to-edl", action="deny", dst=["threat-edl"]), rule("allow-all")])
    [u] = result(data)["unresolved_rules"]
    assert u["causes"][0]["kind"].startswith("not a defined address object")
    assert u["causes"][0]["object"] == "threat-edl"


def test_application_filter_is_unresolvable():
    data = make_data([rule("filtered", app=["risky-filter"]), DENY_REMAINING], objects=OBJECTS)
    r = result(data)
    assert r["status"] == "uncertain"
    assert r["unresolved_rules"][0]["causes"] == [
        {"field": "application", "kind": "application filter", "object": "risky-filter"}]


def test_unknown_service_is_unresolvable():
    data = make_data([rule("odd-svc", svc=["svc-from-elsewhere"]), DENY_REMAINING])
    [u] = result(data)["unresolved_rules"]
    assert u["causes"] == [{"field": "service", "kind": "not a defined service object",
                            "object": "svc-from-elsewhere"}]


def test_dhcp_interface_address_is_unknown():
    data = make_data([rule("to-fw", dst=["10.1.1.1"]), DENY_REMAINING], ips=(), dhcp=True)
    r = result(data)
    assert r["status"] == "uncertain"
    assert r["unresolved_rules"][0]["causes"][0]["kind"] == "interface address unknown (DHCP or unset)"
    # ...but a rule with destination any still matches regardless of the address
    data = make_data([rule("allow-all"), DENY_REMAINING], ips=(), dhcp=True)
    assert result(data)["status"] == "open"


# ── Scope of the analysis ────────────────────────────────────────────────

def test_ping_only_profile_is_not_analyzed():
    assert mgmt_exposure.analyze(make_data([], services=("ping",))) == []


def test_interface_not_in_a_zone_has_no_paths():
    data = make_data([])
    data["zones"][0]["interfaces"] = []
    [entry] = mgmt_exposure.analyze(data)
    assert entry["zone"] is None
    assert entry["services"] == {"https": [], "ssh": []}
    assert findings(data) == []


def test_old_assessment_without_inputs_is_skipped():
    data = make_data([])
    del data["mgmt_interfaces"]
    assert mgmt_exposure.analyze(data) is None
    data = make_data([])
    del data["zones"][0]["interfaces"]
    assert mgmt_exposure.analyze(data) is None
    assert findings(data) == []


# ── End to end through the parsers ───────────────────────────────────────

FIREWALL_XML = b"""<config><shared>
  <address><entry name="admin-hosts"><ip-netmask>10.1.1.50/32</ip-netmask></entry></address>
</shared><devices><entry name="localhost.localdomain">
  <network>
    <profiles><interface-management-profile>
      <entry name="mgmt"><https>yes</https><ssh>yes</ssh></entry>
    </interface-management-profile></profiles>
    <interface><ethernet>
      <entry name="ethernet1/1"><layer3>
        <ip><entry name="fw-inside-ip"/></ip>
        <interface-management-profile>mgmt</interface-management-profile>
      </layer3></entry>
      <entry name="ethernet1/2"><layer3>
        <dhcp-client/>
        <interface-management-profile>mgmt</interface-management-profile>
      </layer3></entry>
    </ethernet></interface>
  </network>
  <vsys><entry name="vsys1">
    <address><entry name="fw-inside-ip"><ip-netmask>10.1.1.1/24</ip-netmask></entry></address>
    <zone>
      <entry name="inside"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="outside"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <rulebase>
      <security><rules>
        <entry name="allow-admins">
          <from><member>inside</member></from><to><member>inside</member></to>
          <source><member>admin-hosts</member></source><destination><member>fw-inside-ip</member></destination>
          <application><member>ssh</member></application><service><member>application-default</member></service>
          <action>allow</action>
        </entry>
        <entry name="inside-to-internet">
          <from><member>inside</member></from><to><member>outside</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <application><member>ssl</member></application><service><member>application-default</member></service>
          <action>allow</action>
        </entry>
      </rules></security>
      <default-security-rules><rules>
        <entry name="intrazone-default"><action>deny</action></entry>
      </rules></default-security-rules>
    </rulebase>
  </entry></vsys>
</entry></devices></config>"""


def test_firewall_config_end_to_end():
    data = parser.parse_config(FIREWALL_XML)
    assert data["default_rule_actions"] == {"intrazone-default": "deny"}
    by_iface = {e["interface"]: e for e in mgmt_exposure.analyze(data)}

    inside = by_iface["ethernet1/1"]
    assert inside["zone"] == "inside" and inside["address_known"] is True
    ssh_inside = next(r for r in inside["services"]["ssh"] if r["source_zone"] == "inside")
    # Admin hosts allowed; everyone else hits the overridden intrazone-default deny
    assert (ssh_inside["status"], ssh_inside["specific_allows"]) == ("restricted", ["allow-admins"])

    outside = by_iface["ethernet1/2"]
    assert outside["address_known"] is False  # DHCP
    https_from_inside = next(r for r in outside["services"]["https"] if r["source_zone"] == "inside")
    assert (https_from_inside["status"], https_from_inside["via"]) == ("open", "inside-to-internet")

    keys = {f["finding_key"] for f in run_rules(data, {}) if f["rule_id"] == "mgmt_interface_open_to_any_source"}
    assert keys == {"mgmt_interface_open_to_any_source:ethernet1/2"}


PANORAMA_XML = b"""<config>
<shared>
  <address><entry name="fw-branch-ip"><ip-netmask>192.0.2.1/24</ip-netmask></entry></address>
  <post-rulebase>
    <security><rules>
      <entry name="deny-remaining">
        <from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>deny</action>
      </entry>
    </rules></security>
  </post-rulebase>
</shared>
<devices><entry name="localhost.localdomain">
  <device-group><entry name="branch">
    <reference-templates><member>tmpl</member></reference-templates>
    <pre-rulebase><security><rules>
      <entry name="allow-noc">
        <from><member>lan</member></from><to><member>lan</member></to>
        <source><member>10.50.0.0/24</member></source><destination><member>fw-branch-ip</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action>
      </entry>
    </rules></security></pre-rulebase>
  </entry></device-group>
  <template><entry name="tmpl"><config><devices><entry name="localhost.localdomain">
    <network>
      <profiles><interface-management-profile>
        <entry name="branch-mgmt"><https>yes</https></entry>
      </interface-management-profile></profiles>
      <interface><ethernet><entry name="ethernet1/5"><layer3>
        <ip><entry name="fw-branch-ip"/></ip>
        <interface-management-profile>branch-mgmt</interface-management-profile>
      </layer3></entry></ethernet></interface>
    </network>
    <vsys><entry name="vsys1"><zone>
      <entry name="lan"><network><layer3><member>ethernet1/5</member></layer3></network></entry>
    </zone></entry></vsys>
  </entry></devices></config></entry></template>
</entry></devices></config>"""


def test_panorama_export_end_to_end():
    data = panorama_parser.build_assessment_data(ET.fromstring(PANORAMA_XML), "branch")
    [entry] = mgmt_exposure.analyze(data)
    assert (entry["interface"], entry["zone"], entry["address_known"]) == ("ethernet1/5", "lan", True)
    [r] = entry["services"]["https"]
    # DG pre-rule allows the NOC subnet; the shared post-rulebase catch-all denies everyone else
    assert (r["status"], r["via"], r["specific_allows"]) == ("restricted", "deny-remaining", ["allow-noc"])
    assert [f for f in run_rules(data, {}) if f["rule_id"] == "mgmt_interface_open_to_any_source"] == []

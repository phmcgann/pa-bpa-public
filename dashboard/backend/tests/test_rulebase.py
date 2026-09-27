"""Rulebase analysis: shadowed and redundant security rules, unused objects, duplicate objects."""
import pytest

from app import parser
from app.object_usage import find_duplicates
from app.rules import checks, rulebase
from app.rules.definitions import RULES_BY_ID


def rule(name, action="allow", **kw):
    base = {"name": name, "action": action, "disabled": "no", "from_zones": ["trust"], "to_zones": ["untrust"],
            "sources": ["any"], "destinations": ["any"], "source_users": ["any"], "applications": ["any"],
            "services": ["application-default"], "category": ["any"], "source_hip": ["any"],
            "destination_hip": ["any"], "rule_type": "universal", "negate_source": "no",
            "negate_destination": "no", "schedule": None, "targeted": False, "vsys": "vsys1"}
    return {**base, **kw}


OBJECTS = {
    "addresses": {
        "lan": {"type": "ip-netmask", "value": "10.0.0.0/8"},
        "web-srv": {"type": "ip-netmask", "value": "10.1.1.10"},
        "web-srv-2": {"type": "ip-netmask", "value": "10.1.1.10/32"},
        "dmz-range": {"type": "ip-range", "value": "10.2.0.1-10.2.0.50"},
        "cdn": {"type": "fqdn", "value": "cdn.example.com"},
    },
    "address_groups": {
        "servers": {"dynamic": False, "members": ["web-srv", "dmz-range"]},
        "tagged": {"dynamic": True, "members": []},
    },
    "services": {
        "tcp-8000-8100": {"tcp": "8000-8100", "udp": None, "sctp": None, "source_port": None},
        "tcp-8080": {"tcp": "8080", "udp": None, "sctp": None, "source_port": None},
        "tcp-8080-dup": {"tcp": "8080", "udp": None, "sctp": None, "source_port": None},
        "tcp-8080-from-53": {"tcp": "8080", "udp": None, "sctp": None, "source_port": "53"},
    },
    "service_groups": {"web-ports": ["tcp-8080", "service-https"]},
    "application_groups": {"browsing": ["web-browsing", "ssl"]},
    "application_filters": ["risky"],
    "external_lists": {},
}


def shadowed(rules):
    return {(s["rule"], s["by"], s["kind"]) for s in rulebase.find_shadowed(rules, OBJECTS)}


def test_broad_allow_shadows_a_later_block():
    rules = [rule("allow-out"), rule("block-web", "deny", applications=["web-browsing"])]
    assert shadowed(rules) == {("block-web", "allow-out", "block_allowed")}


def test_same_action_is_redundant_and_opposite_allow_is_blocked():
    rules = [rule("deny-all", "drop"), rule("drop-again", "deny", applications=["ssh"]),
             rule("allow-ssh", applications=["ssh"])]
    assert shadowed(rules) == {("drop-again", "deny-all", "redundant"), ("allow-ssh", "deny-all", "allow_blocked")}


def test_later_rule_that_is_broader_is_not_shadowed():
    rules = [rule("web", applications=["web-browsing"]), rule("all")]
    assert shadowed(rules) == set()


def test_addresses_resolve_through_objects_groups_and_literals():
    rules = [rule("lan-out", sources=["lan"]),
             rule("server-out", "deny", sources=["servers"]),       # group of a /32 and a range inside 10/8
             rule("literal", "deny", sources=["10.9.9.0/24"]),
             rule("outside", "deny", sources=["192.168.1.0/24"]),
             rule("partial", "deny", sources=["lan", "192.168.1.1"])]
    assert shadowed(rules) == {("server-out", "lan-out", "block_allowed"), ("literal", "lan-out", "block_allowed")}


def test_unresolvable_addresses_only_cover_the_same_object():
    rules = [rule("cdn-out", destinations=["cdn"]), rule("cdn-block", "deny", destinations=["cdn"]),
             rule("dag", destinations=["tagged"]), rule("dag-under-lan", "deny", destinations=["tagged"], sources=["lan"])]
    assert shadowed(rules) == {("cdn-block", "cdn-out", "block_allowed"), ("dag-under-lan", "dag", "block_allowed")}
    # An FQDN isn't covered by an IP range, even a large one.
    assert shadowed([rule("lan", destinations=["lan"]), rule("cdn", "deny", destinations=["cdn"])]) == set()


def test_services_compare_ports():
    rules = [rule("range", services=["tcp-8000-8100"]),
             rule("single", "deny", services=["tcp-8080"]),
             rule("group", "deny", services=["web-ports"]),          # includes 443, outside the range
             rule("src-port", "deny", services=["tcp-8080-from-53"]), # source port: compared by name only
             rule("app-default", "deny")]                           # application-default isn't a port list
    assert shadowed(rules) == {("single", "range", "block_allowed")}
    assert shadowed([rule("any-svc", services=["any"]), rule("x", "deny", services=["web-ports"])]) == \
        {("x", "any-svc", "block_allowed")}


def test_applications_expand_groups_and_compare_filters_by_name():
    rules = [rule("browsing", applications=["browsing"]), rule("ssl-only", "deny", applications=["ssl"]),
             rule("filter", "deny", applications=["risky"])]
    assert shadowed(rules) == {("ssl-only", "browsing", "block_allowed")}


def test_zones_and_rule_types():
    rules = [rule("any-zones", from_zones=["any"], to_zones=["any"], applications=["ssh"]),
             rule("intra", "deny", rule_type="intrazone", from_zones=["dmz"], applications=["ssh"])]
    assert shadowed(rules) == {("intra", "any-zones", "block_allowed")}
    rules = [rule("inter", rule_type="interzone", from_zones=["any"], to_zones=["any"]),
             rule("universal", "deny", applications=["ssh"])]
    # Conservative: an interzone rule is never taken to cover a universal one.
    assert shadowed(rules) == set()
    assert shadowed([rule("narrow", to_zones=["dmz"]), rule("b", "deny", to_zones=["dmz", "untrust"])]) == set()


def test_users_known_user_covers_named_users():
    rules = [rule("known", source_users=["known-user"]), rule("alice", "deny", source_users=["corp\\alice"]),
             rule("unknown", "deny", source_users=["unknown"])]
    assert shadowed(rules) == {("alice", "known", "block_allowed")}


def test_rules_that_dont_always_apply_never_shadow():
    for kw in ({"disabled": "yes"}, {"schedule": "weekdays"}, {"targeted": True}, {"negate_source": "yes"}):
        assert shadowed([rule("a", **kw), rule("b", "deny", applications=["ssh"])]) == set()
    # A disabled rule isn't reported as shadowed either.
    assert shadowed([rule("a"), rule("b", "deny", disabled="yes")]) == set()


def test_rules_in_different_vsys_dont_interact():
    assert shadowed([rule("a", vsys="vsys1"), rule("b", "deny", vsys="vsys2")]) == set()


def test_category_and_hip_must_be_covered():
    assert shadowed([rule("cat", category=["gambling"]), rule("b", "deny")]) == set()
    assert shadowed([rule("hip", source_hip=["compliant"]), rule("b", "deny")]) == set()
    assert shadowed([rule("a"), rule("b", "deny", category=["gambling"], source_hip=["compliant"])]) == \
        {("b", "a", "block_allowed")}


def test_checks_split_block_allowed_from_the_rest():
    data = {"security_rules": [rule("allow-out"), rule("block-web", "deny", applications=["web-browsing"]),
                               rule("dup", applications=["ssh"])],
            "policy_objects": OBJECTS}
    [f] = checks.CHECKS["security_rule_shadowed_block"](data, {})
    assert f["key"] == "block-web" and "'allow-out' (#1, allow)" in f["message"] and "is allowed" in f["message"]
    [f] = checks.CHECKS["security_rule_shadowed"](data, {})
    assert f["key"] == "dup" and "same outcome" in f["message"]


def test_older_uploads_are_left_alone():
    old = {"security_rules": [{k: v for k, v in rule("a").items() if k != "category"}], "policy_objects": OBJECTS}
    assert rulebase.analyze(old)["available"] is False
    assert checks.CHECKS["security_rule_shadowed"](old, {}) == []


def test_parser_records_match_fields_and_vsys():
    xml = b"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys2"><rulebase><security>
      <rules><entry name="r"><from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <category><member>gambling</member></category><source-hip><member>any</member></source-hip>
      <schedule>weekdays</schedule><action>deny</action></entry></rules>
      </security></rulebase></entry></vsys></entry></devices></config>"""
    [r] = parser.parse_config(xml)["security_rules"]
    assert (r["vsys"], r["category"], r["source_hip"], r["schedule"], r["targeted"]) == \
        ("vsys2", ["gambling"], ["any"], "weekdays", False)


# ── Unused and duplicate objects ─────────────────────────────────────────

USAGE_XML = b"""<config>
  <shared>
    <address>
      <entry name="used-by-rule"><ip-netmask>10.0.0.1</ip-netmask></entry>
      <entry name="in-used-group"><ip-netmask>10.0.0.2</ip-netmask></entry>
      <entry name="in-unused-group"><ip-netmask>10.0.0.3</ip-netmask></entry>
      <entry name="on-interface"><ip-netmask>10.0.0.4/24</ip-netmask></entry>
      <entry name="tagged"><ip-netmask>10.0.0.5</ip-netmask><tag><member>web</member></tag></entry>
      <entry name="orphan"><ip-netmask>10.0.0.6</ip-netmask></entry>
      <entry name="tagged-and-direct"><ip-netmask>10.0.0.7</ip-netmask><tag><member>web</member></tag></entry>
      <entry name="tagged-prod"><ip-netmask>10.0.0.8</ip-netmask><tag><member>prod</member></tag></entry>
      <entry name="tagged-unused-dag"><ip-netmask>10.0.0.9</ip-netmask><tag><member>lab</member></tag></entry>
    </address>
    <address-group>
      <entry name="used-group"><static><member>in-used-group</member></static></entry>
      <entry name="unused-group"><static><member>in-unused-group</member></static></entry>
      <entry name="dag"><dynamic><filter>'web' and 'prod'</filter></dynamic></entry>
      <entry name="lab-dag"><dynamic><filter>'lab'</filter></dynamic></entry>
    </address-group>
    <service><entry name="svc-nat"><protocol><tcp><port>8443</port></tcp></protocol></entry>
             <entry name="svc-orphan"><protocol><tcp><port>9999</port></tcp></protocol></entry></service>
    <external-list><entry name="dns-edl"><type><domain><url>https://x</url></domain></type></entry></external-list>
    <profiles>
      <custom-url-category><entry name="allowed-sites"><list><member>a.example</member></list></entry></custom-url-category>
      <url-filtering><entry name="url-prof"><alert><member>allowed-sites</member></alert></entry></url-filtering>
      <spyware><entry name="as-prof"><botnet-domains><lists><entry name="dns-edl"><action><sinkhole/></action></entry></lists></botnet-domains></entry>
               <entry name="as-orphan"/></spyware>
    </profiles>
    <profile-group><entry name="pg"><url-filtering><member>url-prof</member></url-filtering><spyware><member>as-prof</member></spyware></entry></profile-group>
  </shared>
  <devices><entry name="localhost.localdomain">
    <network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="on-interface"/></ip></layer3></entry></ethernet></interface></network>
    <vsys><entry name="vsys1"><rulebase>
      <security><rules><entry name="r1"><source><member>used-by-rule</member><member>used-group</member><member>dag</member><member>tagged-and-direct</member></source>
        <profile-setting><group><member>pg</member></group></profile-setting></entry></rules></security>
      <nat><rules><entry name="n1"><service>svc-nat</service></entry></rules></nat>
    </rulebase></entry></vsys>
  </entry></devices>
</config>"""


def test_unused_objects_follow_references_through_groups_and_profiles():
    unused = parser.parse_config(USAGE_XML)["object_usage"]["unused"]
    assert unused == {
        "addresses": ["in-unused-group", "orphan", "tagged-unused-dag"],
        "address_groups": ["lab-dag", "unused-group"],
        "services": ["svc-orphan"],
        "security_profiles": ["as-orphan (Anti-Spyware)"],
    }


def test_addresses_used_only_through_a_dynamic_group_are_listed():
    usage = parser.parse_config(USAGE_XML)["object_usage"]
    # 'tagged-prod' has only one of the two tags the filter needs, but any named tag counts (errs toward used);
    # 'tagged-and-direct' is used by a rule anyway; 'tagged-unused-dag' is under a group nothing uses.
    assert usage["used_via_dynamic_group"] == [
        {"name": "tagged", "groups": [{"name": "dag", "filter": "'web' and 'prod'"}], "tags": ["web"]},
        {"name": "tagged-prod", "groups": [{"name": "dag", "filter": "'web' and 'prod'"}], "tags": ["prod"]},
    ]


def test_unused_objects_check_rolls_up_per_kind():
    data = parser.parse_config(USAGE_XML)
    findings = {f["key"]: f for f in checks.CHECKS["unused_objects"](data, RULES_BY_ID["unused_objects"].thresholds)}
    assert set(findings) == {"addresses", "address_groups", "services", "security_profiles"}
    assert findings["addresses"]["message"].startswith("3 address objects aren't used")
    assert findings["services"]["message"].startswith("1 service object isn't used")


def test_panorama_exports_skip_unused_objects():
    from app.object_usage import unavailable_for_panorama
    assert checks.CHECKS["unused_objects"]({"object_usage": unavailable_for_panorama()}, {}) == []


def test_duplicates():
    dupes = find_duplicates(OBJECTS)
    assert {"kind": "addresses", "value": "10.1.1.10/32", "names": ["web-srv", "web-srv-2"]} in dupes
    assert {"kind": "services", "value": "TCP 8080", "names": ["tcp-8080", "tcp-8080-dup"]} in dupes
    assert len(dupes) == 2  # the source-port service differs
    [f1, f2] = checks.CHECKS["duplicate_objects"]({"policy_objects": OBJECTS}, {})
    assert f1["key"] == "addresses" and "'web-srv' = 'web-srv-2' (10.1.1.10/32)" in f1["message"]
    assert f2["key"] == "services"

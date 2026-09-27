"""NAT policy: parsing, shadowed NAT rules, destination NAT without an allow rule, all-ports forwards,
bi-directional static NAT."""
import pytest

from app import parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID

CONFIG = b"""<config>
  <shared><address>
    <entry name="web-public"><ip-netmask>203.0.113.10</ip-netmask></entry>
    <entry name="web-private"><ip-netmask>10.1.1.10</ip-netmask></entry>
    <entry name="old-public"><ip-netmask>203.0.113.99</ip-netmask></entry>
    <entry name="lan"><ip-netmask>10.0.0.0/8</ip-netmask></entry>
  </address>
  <service><entry name="tcp-443"><protocol><tcp><port>443</port></tcp></protocol></entry></service></shared>
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase>
    <security><rules>
      <entry name="allow-web-in"><from><member>untrust</member></from><to><member>dmz</member></to>
        <source><member>any</member></source><destination><member>web-public</member></destination>
        <application><member>ssl</member></application><service><member>application-default</member></service>
        <action>allow</action></entry>
      <entry name="lan-out"><from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>lan</member></source><destination><member>any</member></destination>
        <action>allow</action></entry>
    </rules></security>
    <nat><rules>
      <entry name="web-publish"><from><member>untrust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>web-public</member></destination>
        <service>tcp-443</service>
        <destination-translation><translated-address>web-private</translated-address><translated-port>8443</translated-port></destination-translation></entry>
      <entry name="web-publish-dup"><from><member>untrust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>web-public</member></destination>
        <service>tcp-443</service>
        <destination-translation><translated-address>web-private</translated-address><translated-port>8443</translated-port></destination-translation></entry>
      <entry name="old-publish"><from><member>untrust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>old-public</member></destination>
        <service>any</service>
        <destination-translation><translated-address>10.1.1.99</translated-address></destination-translation></entry>
      <entry name="outbound-pat"><from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>lan</member></source><destination><member>any</member></destination><service>any</service>
        <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation></entry>
      <entry name="outbound-other"><from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>10.5.0.0/16</member></source><destination><member>any</member></destination><service>any</service>
        <source-translation><dynamic-ip><translated-address><member>203.0.113.50</member></translated-address></dynamic-ip></source-translation></entry>
      <entry name="mail-static"><from><member>dmz</member></from><to><member>untrust</member></to>
        <source><member>10.1.1.25</member></source><destination><member>any</member></destination><service>any</service>
        <source-translation><static-ip><translated-address>203.0.113.25</translated-address><bi-directional>yes</bi-directional></static-ip></source-translation></entry>
      <entry name="disabled-publish"><disabled>yes</disabled><from><member>untrust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>old-public</member></destination><service>any</service>
        <destination-translation><translated-address>10.1.1.98</translated-address></destination-translation></entry>
    </rules></nat>
  </rulebase></entry></vsys></entry></devices>
</config>"""


@pytest.fixture(scope="module")
def data():
    return parser.parse_config(CONFIG)


def _keys(data, rule_id):
    return sorted(f["key"] for f in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def test_parses_translations(data):
    rules = {r["name"]: r for r in data["nat_rules"]}
    assert len(rules) == 7 and rules["web-publish"]["vsys"] == "vsys1"
    assert rules["web-publish"]["destination_translation"] == {"type": "static", "address": "web-private", "port": "8443"}
    assert rules["outbound-pat"]["source_translation"] == {"type": "dynamic-ip-and-port", "translated": [],
                                                           "interface": "ethernet1/1", "bidirectional": False}
    assert rules["mail-static"]["source_translation"]["bidirectional"] is True
    assert rules["disabled-publish"]["disabled"] is True


def test_shadowed_nat_rules(data):
    assert _keys(data, "nat_rule_shadowed") == ["outbound-other", "web-publish-dup"]
    msgs = {f["key"]: f["message"] for f in checks.CHECKS["nat_rule_shadowed"](data, {})}
    assert "same translation" in msgs["web-publish-dup"]
    assert "translates it differently" in msgs["outbound-other"]


def test_dnat_without_an_allow_rule(data):
    # web-publish is allowed by allow-web-in (pre-NAT destination web-public); old-publish isn't.
    assert _keys(data, "nat_dnat_no_allow_rule") == ["old-publish"]


def test_dnat_without_allow_rule_is_not_flagged_when_unsure(data):
    unsure = {**data, "security_rules": [{**r, "destinations": ["some-edl"]} if r["name"] == "allow-web-in" else r
                                         for r in data["security_rules"]]}
    assert _keys(unsure, "nat_dnat_no_allow_rule") == []
    assert _keys({**data, "security_rules": []}, "nat_dnat_no_allow_rule") == []


def test_all_ports_forward_and_bidirectional(data):
    assert _keys(data, "nat_dnat_all_ports") == ["old-publish"]
    assert _keys(data, "nat_bidirectional_static") == ["mail-static"]


def test_older_uploads_without_nat():
    for rule_id in ("nat_rule_shadowed", "nat_dnat_no_allow_rule", "nat_dnat_all_ports", "nat_bidirectional_static"):
        assert checks.CHECKS[rule_id]({"security_rules": []}, {}) == []

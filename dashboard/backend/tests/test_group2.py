"""Advanced IP Defense (license-gated), Gen AI / liability and post-quantum checks ported from Palo Alto
SCM, rules that ship switched off, and the matching SCM defaults and license gate."""
import os
import xml.etree.ElementTree as ET

import pytest

from app import parser
from app.rules import checks, scm_catalog, scm_findings
from app.rules.definitions import RULES_BY_ID
from app.rules.engine import run_rules

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "genai_aipd_pq.xml")
AIPD = ["aipd_c2_not_blocked", "aipd_malware_ip_not_blocked", "aipd_inbound_list_not_blocked", "aipd_rule_missing_pair"]
OFF = ["url_liability_categories_not_blocked", "url_liability_credentials_not_blocked", "url_genai_categories_not_blocked",
       "genai_no_block_rule", "genai_tolerated_no_users", "genai_allow_no_dlp",
       "decryption_not_quantum_safe_ciphers", "decryption_no_pqc_key_exchange"]
RULE_IDS = AIPD + OFF
VSYS = "devices/entry/vsys/entry"
RULES = f"{VSYS}/rulebase/security/rules"
LICENSED = {"available": True, "licenses": [{"feature": "Advanced IP Defense", "expired": "no"}]}


def _root():
    return ET.parse(FIXTURE).getroot()


def _data(root, licenses=LICENSED):
    data = parser.parse_config(ET.tostring(root))
    data["licenses"] = licenses
    return data


def _keys(data, rule_id):
    return sorted(i["key"] for i in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def _findings(data):
    return {rid: _keys(data, rid) for rid in RULE_IDS if _keys(data, rid)}


def _members(root, path):
    return root.find(path)


def _drop_member(root, path, value):
    el = root.find(path)
    el.remove(next(m for m in el if m.text == value))


def test_hardened_config_raises_nothing():
    assert _findings(_data(_root())) == {}


@pytest.mark.parametrize("mutate, expected", [
    (lambda r: _drop_member(r, f"{RULES}/entry[@name='aipd-out']/destination", "panw-aipd-c2-infra-ip-list"),
     {"aipd_c2_not_blocked": ["outbound"], "aipd_rule_missing_pair": ["aipd-out"]}),
    (lambda r: _drop_member(r, f"{RULES}/entry[@name='aipd-in']/source", "panw-aipd-scanning-ip-list"),
     {"aipd_inbound_list_not_blocked": ["panw-aipd-scanning-ip-list:inbound"]}),
    (lambda r: _drop_member(r, f"{VSYS}/profiles/url-filtering/entry/block", "peer-to-peer"),
     {"url_liability_categories_not_blocked": ["url"]}),
    (lambda r: _drop_member(r, f"{VSYS}/profiles/url-filtering/entry/credential-enforcement/block", "gambling"),
     {"url_liability_credentials_not_blocked": ["url"]}),
    (lambda r: _drop_member(r, f"{VSYS}/profiles/url-filtering/entry/block", "ai-writing-assistant"),
     {"url_genai_categories_not_blocked": ["url"]}),
    (lambda r: r.find(RULES).remove(r.find(f"{RULES}/entry[@name='genai-block']")), {"genai_no_block_rule": ["global"]}),
    (lambda r: r.find(f"{RULES}/entry[@name='genai-tolerated']").remove(
        r.find(f"{RULES}/entry[@name='genai-tolerated']/source-user")), {"genai_tolerated_no_users": ["genai-tolerated"]}),
    (lambda r: r.find(f"{VSYS}/profile-group/entry").remove(r.find(f"{VSYS}/profile-group/entry/data-filtering")),
     {"genai_allow_no_dlp": ["genai-sanctioned"]}),
    (lambda r: r.find(f"{VSYS}/profiles/decryption/entry/ssl-protocol-settings/enc-algo-aes-256-cbc").__setattr__("text", "yes"),
     {"decryption_not_quantum_safe_ciphers": ["dp-pq"]}),
    (lambda r: r.find(f"{VSYS}/profiles/decryption/entry/ssl-protocol-settings/keyxchg-algo-pqc-standardized").__setattr__("text", "no"),
     {"decryption_no_pqc_key_exchange": ["dp-pq"]}),
])
def test_each_weakened_setting_raises_exactly_its_finding(mutate, expected):
    root = _root()
    mutate(root)
    assert _findings(_data(root)) == expected


def test_decryption_defaults_allow_legacy_ciphers_and_no_pqc():
    root = _root()
    prof = root.find(f"{VSYS}/profiles/decryption/entry")
    prof.remove(prof.find("ssl-protocol-settings"))
    data = _data(root)
    assert data["decryption"]["profiles"][0]["legacy_ciphers"] == ["3des", "rc4", "aes-128-cbc", "aes-256-cbc", "aes-128-gcm"]
    assert _findings(data) == {"decryption_not_quantum_safe_ciphers": ["dp-pq"], "decryption_no_pqc_key_exchange": ["dp-pq"]}


@pytest.mark.parametrize("licenses", [
    {"available": False, "licenses": []},
    {"available": True, "licenses": [{"feature": "Advanced Threat Prevention", "expired": "no"}]},
    {"available": True, "licenses": [{"feature": "Advanced IP Defense", "expired": "yes"}]},
])
def test_aipd_checks_need_an_active_license(licenses):
    root = _root()
    root.find(RULES).remove(root.find(f"{RULES}/entry[@name='aipd-in']"))
    root.find(RULES).remove(root.find(f"{RULES}/entry[@name='aipd-out']"))
    assert {rid: _keys(_data(root, licenses), rid) for rid in AIPD if _keys(_data(root, licenses), rid)} == {}
    licensed = _data(root)
    assert _keys(licensed, "aipd_c2_not_blocked") == ["inbound", "outbound"]
    assert len(_keys(licensed, "aipd_inbound_list_not_blocked")) == 4


def test_business_and_post_quantum_rules_ship_off():
    for rid in OFF:
        rule = RULES_BY_ID[rid]
        assert rule.enabled_by_default is False and rule.default_off_reason.startswith("Off by default")
    for rid in AIPD:
        assert RULES_BY_ID[rid].enabled_by_default is True
    root = _root()
    _drop_member(root, f"{VSYS}/profiles/url-filtering/entry/block", "gambling")
    data = _data(root)
    assert "url_liability_categories_not_blocked" not in {f["rule_id"] for f in run_rules(data, {})}
    on = {"url_liability_categories_not_blocked": {"enabled": True, "threshold_overrides": None, "severity_override": None}}
    assert "url_liability_categories_not_blocked" in {f["rule_id"] for f in run_rules(data, on)}


def test_scm_defaults_for_unmatchable_business_and_post_quantum_checks():
    for cid in (90, 119, 157, 191, 192, 200, 201, 267, 340, 344, 348, 351, 352, 353, 354, 357, 359, 371, 375, 376, 74, 79):
        assert not scm_catalog.enabled_by_default(cid), cid
    for cid in (4, 76, 398, 410):
        assert scm_catalog.enabled_by_default(cid), cid


def _scm_row(cid, name=""):
    return {"check_id": cid, "passed": False, "excluded": False, "object_type": "security_rulebase",
            "object_name": name, "location": "", "failed_fields": None, "check_name": f"check {cid}",
            "check_type": "High", "check_message": ""}


@pytest.mark.parametrize("licenses, kept", [
    ({"available": False, "licenses": []}, False),
    ({"available": True, "licenses": [{"feature": "Advanced IP Defense", "expired": "no"}]}, True),
])
def test_scm_aipd_results_need_the_license_too(licenses, kept):
    data = {"security_rules": [], "licenses": licenses}
    out = scm_findings.build([_scm_row(398), _scm_row(4)], data, [], {})
    ids = {f["scm_check_ids"][0] for f in out}
    assert (398 in ids) is kept and 4 in ids


def test_rules_api_reports_default_off(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    import importlib
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        rules = {r["id"]: r for r in c.get("/api/rules").json()}
        r = rules["url_genai_categories_not_blocked"]
        assert r["enabled"] is False and r["enabled_by_default"] is False and r["default_off_reason"]
        # Changing only the severity keeps it off; switching it on turns it on.
        c.patch("/api/rules/url_genai_categories_not_blocked", json={"severity_override": "LOW"})
        assert {x["id"]: x for x in c.get("/api/rules").json()}["url_genai_categories_not_blocked"]["enabled"] is False
        c.patch("/api/rules/url_genai_categories_not_blocked", json={"enabled": True})
        assert {x["id"]: x for x in c.get("/api/rules").json()}["url_genai_categories_not_blocked"]["enabled"] is True

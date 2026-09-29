"""Assessing one Panorama-managed firewall: every device group above it in the hierarchy plus the
template stack it's assigned, as PAN-OS combines them."""
import copy
import importlib
import os
import xml.etree.ElementTree as ET

import pytest

from app import panorama_parser as pp
from app import tsf_parser
from app.rules import cli

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "panorama_hierarchy_config.xml")
LEAF, OTHER, LAB = "012345678901", "099999999999", "055555555555"


@pytest.fixture
def root():
    return ET.parse(FIXTURE).getroot()


def test_device_group_chain_follows_parents_to_the_top(root):
    assert pp.device_group_chain(root, "fw-leaf") == ["sdwan", "region-east", "fw-leaf"]
    assert pp.device_group_chain(root, "lab") == ["lab"]


def test_devices_list_their_device_groups_and_template_stack(root):
    devices = {d["serial"]: d for d in pp.list_devices(root)}
    assert devices[LEAF] == {
        "serial": LEAF, "hostname": "fw-leaf-01", "device_group": "fw-leaf",
        "device_groups": ["sdwan", "region-east", "fw-leaf"],
        "template_stack": "stk_fw-leaf", "templates": ["fw-leaf-tmpl", "common-shared", "iron-skillet"],
    }
    assert devices[LAB]["template_stack"] is None and devices[LAB]["hostname"] is None


def test_rules_come_from_every_device_group_in_evaluation_order(root):
    data = pp.build_assessment_data_for_device(root, LEAF)
    assert [(r["name"], r["scope_name"]) for r in data["security_rules"]] == [
        ("shared-pre-allow", None), ("sdwan-pre", "sdwan"), ("region-east-pre", "region-east"), ("leaf-pre", "fw-leaf"),
        ("leaf-post", "fw-leaf"), ("region-east-post", "region-east"), ("shared-post-deny", None),
    ]  # a sibling firewall's group (fw-other) and an unrelated one (lab) don't apply


def test_lower_device_group_profile_wins(root):
    av = {p["name"]: p for p in pp.build_assessment_data_for_device(root, LEAF)["security_profiles"]["antivirus"]}
    assert av["av-common"]["scope_name"] == "fw-leaf" and av["av-shared"]["scope"] == "shared"


def test_template_stack_layers_first_template_wins(root):
    data = pp.build_assessment_data_for_device(root, LEAF)
    # fw-leaf-tmpl (top) overrides iron-skillet's NTP primary; common-shared adds the secondary.
    assert data["management"]["ntp_primary"] == "192.0.2.99"
    assert data["management"]["ntp_secondary"] == "192.0.2.11"
    assert data["management"]["login_banner"] is True
    assert sorted(z["name"] for z in data["zones"]) == ["dmz", "trust", "untrust"]
    assert data["panorama"] == {"mode": "device", "serial": LEAF, "device_groups": ["sdwan", "region-east", "fw-leaf"],
                                "template_stack": "stk_fw-leaf",
                                "templates": ["fw-leaf-tmpl", "common-shared", "iron-skillet"], "hierarchy_known": True}
    assert data["system_info"]["hostname"] == "fw-leaf-01" and data["system_info"]["serial"] == LEAF


def test_cli_changes_each_rule_in_its_own_device_group(root):
    ctx = cli.Context(pp.build_assessment_data_for_device(root, LEAF))
    finding = {"rule_id": "security_rule_no_logging_allow", "finding_key": "security_rule_no_logging_allow:region-east-pre",
               "program": "core"}
    assert cli.for_finding(finding, ctx)["commands"] == \
        ["set device-group region-east pre-rulebase security rules region-east-pre log-end yes"]
    assert ctx.profile("antivirus", "av-common") == "device-group fw-leaf profiles virus av-common"
    assert ctx.profile("antivirus", "av-shared") == "shared profiles virus av-shared"


def test_without_hierarchy_information_only_the_firewalls_own_group_applies(root):
    flat = copy.deepcopy(root)
    flat.remove(flat.find("readonly"))
    data = pp.build_assessment_data_for_device(flat, LEAF)
    assert data["panorama"]["device_groups"] == ["fw-leaf"] and data["panorama"]["hierarchy_known"] is False
    assert [r["name"] for r in data["security_rules"]] == ["shared-pre-allow", "leaf-pre", "leaf-post", "shared-post-deny"]


def test_device_group_mode_now_includes_parent_groups(root):
    data = pp.build_assessment_data(root, "fw-other")
    assert [r["name"] for r in data["security_rules"]][:4] == ["shared-pre-allow", "sdwan-pre", "region-east-pre", "other-pre"]


def test_unknown_serial_is_rejected(root):
    with pytest.raises(ValueError, match="isn't managed"):
        pp.build_assessment_data_for_device(root, "000000000000")


# ── Hostnames from Panorama's own device list (its tech support file) ─────

def test_hostnames_from_key_value_blocks():
    text = "serial: 055555555555\nconnected: yes\nhostname: lab-fw-01\n\nserial: 000000000001\nhostname: pano\n"
    assert tsf_parser.parse_cli_managed_devices(text, [LAB, LEAF]) == {LAB: "lab-fw-01"}


def test_hostnames_from_a_table():
    text = ("Serial           Hostname        IP             Model\n"
            "--------------------------------------------------\n"
            f"{LAB}     lab-fw-01       192.0.2.5      PA-440\n")
    assert tsf_parser.parse_cli_managed_devices(text, [LAB]) == {LAB: "lab-fw-01"}


# ── Through the API ──────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    from fastapi.testclient import TestClient
    with TestClient(main.app) as c:
        yield c


def test_pick_a_firewall_then_reanalyze(client):
    with open(FIXTURE, "rb") as fh:
        up = client.post("/api/assessments/upload", files={"file": ("panorama.xml", fh.read())}).json()
    assert [d["serial"] for d in up["devices"]] == [LEAF, OTHER, LAB]  # named ones first, then by serial
    made = client.post("/api/assessments/from-panorama", json={"upload_id": up["upload_id"], "serial": LEAF})
    assert made.status_code == 200, made.text
    aid = made.json()["id"]
    detail = client.get(f"/api/assessments/{aid}").json()
    assert detail["hostname"] == "fw-leaf-01" and detail["serial"] == LEAF
    assert detail["data"]["panorama"]["template_stack"] == "stk_fw-leaf"
    assert detail["cli_unavailable"] is None
    rules_before = [r["name"] for r in detail["data"]["security_rules"]]
    again = client.post(f"/api/assessments/{aid}/reanalyze")
    assert again.status_code == 200, again.text
    after = client.get(f"/api/assessments/{aid}").json()
    assert [r["name"] for r in after["data"]["security_rules"]] == rules_before
    assert after["data"]["panorama"]["mode"] == "device"


def test_device_group_choice_still_works(client):
    with open(FIXTURE, "rb") as fh:
        up = client.post("/api/assessments/upload", files={"file": ("panorama.xml", fh.read())}).json()
    made = client.post("/api/assessments/from-panorama", json={"upload_id": up["upload_id"], "device_group": "lab"})
    assert made.status_code == 200, made.text
    assert client.get(f"/api/assessments/{made.json()['id']}").json()["hostname"] == "lab"

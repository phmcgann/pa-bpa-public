"""PAN-OS end-of-life: Palo Alto's published dates, graded by how far past (or near) they are.
conftest pins today to 2026-10-14."""
import os
import re
from datetime import date

import pytest

from app import panorama_parser, parser
from app.rules import pan_os_lifecycle as lc
from app.rules.engine import run_rules

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _eol(data, settings=None):
    return [f for f in run_rules(data, settings or {}) if f["rule_id"] == "eol_pan_os_version"]


def _running(version):
    return {"system_info": {"available": True, "sw_version": version}}


def test_lifecycle_states():
    assert lc.status("10.1.14-h4")["state"] == "eol"          # extended support ended 2026-03-31
    assert lc.status("10.2.9")["state"] == "extended"         # standard ended 2025-08-27, extended to 2027-03-31
    assert lc.status("11.1.4-h7")["state"] == "standard"
    assert lc.status("7.1.0")["state"] == "eol"               # older than the table: long gone
    assert lc.status("13.0.1") is None                         # newer than the table: no judgement
    assert lc.status("N/A") is None and lc.status(None) is None
    assert lc.supported_releases() == ["11.1", "11.2", "12.1", "12.2"]


def test_past_end_of_life_is_critical():
    [f] = _eol(_running("10.1.14-h4"))
    assert f["severity"] == "CRITICAL" and f["default_severity"] == "CRITICAL"
    assert "standard support for 10.1 ended on December 1, 2024 and extended support on March 31, 2026" in f["message"]
    assert "11.1, 11.2, 12.1 or 12.2" in f["recommendation"]
    [f] = _eol(_running("11.0.3"))
    assert f["severity"] == "CRITICAL" and "support for 11.0 ended on November 17, 2024" in f["message"]


def test_extended_support_is_a_warning():
    [f] = _eol(_running("10.2.9-h1"))
    assert f["severity"] == "WARNING" and not f["severity_overridden"]
    assert "Extended support runs until March 31, 2027 (168 days)" in f["message"]


def test_nearing_end_of_life():
    # 11.1's standard support ends 2027-05-03 with extended support to follow: only Low.
    f = lc.finding("11.1.4", "running on the firewall", 180, on=date(2027, 1, 1))
    assert f["severity"] == "LOW" and "extended support follows until August 31, 2027" in f["message"]
    # 11.0 had no extended support, so its approaching end-of-life was a Warning.
    f = lc.finding("11.0.2", "running on the firewall", 180, on=date(2024, 9, 1))
    assert f["severity"] == "WARNING" and "reaches end-of-life on November 17, 2024 (77 days)" in f["message"]
    assert lc.finding("11.1.4", "running on the firewall", 180) is None  # 201 days out today


def test_warning_window_is_a_setting():
    settings = {"eol_pan_os_version": {"enabled": True, "threshold_overrides": {"warn_days_before_end": 365},
                                       "severity_override": None}}
    [f] = _eol(_running("11.2.3"), settings)
    assert f["severity"] == "LOW"


def test_severity_set_in_settings_still_wins():
    settings = {"eol_pan_os_version": {"enabled": True, "threshold_overrides": None, "severity_override": "LOW"}}
    [f] = _eol(_running("10.1.3"), settings)
    assert f["severity"] == "LOW" and f["default_severity"] == "CRITICAL" and f["severity_overridden"]


def _config(version):
    with open(os.path.join(FIXTURES, "sample_config.xml"), "rb") as fh:
        xml = fh.read().decode()
    return parser.parse_config(re.sub(r'<config version="[^"]+"', f'<config version="{version}"', xml, count=1).encode())


def test_config_export_uses_its_version_stamp():
    data = _config("10.1.0")
    assert data["config_version"] == {"version": "10.1.0", "schema_version": "10.1.0"}
    [f] = _eol(data)
    assert f["severity"] == "CRITICAL" and "PAN-OS 10.1.0 (per the config file's version stamp)" in f["message"]
    assert _eol(_config("11.2.0")) == []


def test_running_version_beats_the_config_stamp():
    data = {**_config("10.1.0"), **_running("12.1.2")}
    assert _eol(data) == []


def test_panorama_device_does_not_use_panoramas_own_version():
    import xml.etree.ElementTree as ET
    root = ET.parse(os.path.join(FIXTURES, "panorama_hierarchy_config.xml")).getroot()
    root.set("version", "10.1.0")
    data = panorama_parser.build_assessment_data_for_device(root, "012345678901")
    assert "config_version" not in data and _eol(data) == []


@pytest.mark.parametrize("release", sorted(lc.RELEASES))
def test_table_dates_are_ordered(release):
    standard, extended = lc.RELEASES[release]
    assert extended is None or date.fromisoformat(extended) > date.fromisoformat(standard)

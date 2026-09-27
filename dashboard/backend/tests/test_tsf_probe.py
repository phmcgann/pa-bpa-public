"""The tech support file probe reports structure and counts without leaking identifying values."""
import os
import re
import sys

from app import tsf_probe

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_techsupport.tgz")


def test_probe_reports_without_hostname_serial_or_addresses(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["tsf_probe", FIXTURE])
    tsf_probe.main()
    out = capsys.readouterr().out
    for section in ("== Archive", "== CLI dump", "== Parsing", "== Certificates", "== Security advisories",
                    "== Rulebase analysis", "== Findings"):
        assert section in out
    assert "PAN-OS: 11.1.0" in out and "security rules: 6" in out
    assert "tsf-test-fw" not in out and "999900001111" not in out
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", out)


def test_masker_and_shapes():
    m = tsf_probe.Masker()
    m.add("fw-client-01")
    assert m("host fw-client-01 at 10.1.2.3/24 and 2001:db8::1") == "host <masked> at <ip> and <ip>"
    assert tsf_probe._command_stem("> show rule-hit-count vsys vsys-name vsys1 rule-base security") == \
        "show rule-hit-count vsys vsys-name"
    assert tsf_probe._header_shape("Rule Name   Hit Count  Last Hit  my_rule#1") == "Rule Name Hit Count Last Hit <…>"

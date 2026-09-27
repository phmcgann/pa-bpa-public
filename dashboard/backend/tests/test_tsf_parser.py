import os

import pytest

from app import tsf_parser

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_techsupport.tgz")


@pytest.fixture
def raw():
    with open(FIXTURE, "rb") as f:
        return f.read()


def test_looks_like_tsf_by_extension(raw):
    assert tsf_parser.looks_like_tsf("export.tgz", raw) is True
    assert tsf_parser.looks_like_tsf("export.tar.gz", raw) is True


def test_looks_like_tsf_by_magic_bytes_when_extension_missing(raw):
    # A renamed/extension-stripped upload should still be detected.
    assert tsf_parser.looks_like_tsf("weird-filename", raw) is True


def test_plain_xml_is_not_a_tsf():
    xml_bytes = b"<config version='11.1.0'></config>"
    assert tsf_parser.looks_like_tsf("config.xml", xml_bytes) is False


def test_extract_config_and_cli_text(raw):
    config_bytes, cli_text = tsf_parser.extract_config_and_cli_text(raw)
    assert b"<config" in config_bytes
    assert "show system info" in cli_text


def test_extract_cli_section_bounded_by_next_command(raw):
    _, cli_text = tsf_parser.extract_config_and_cli_text(raw)
    section = tsf_parser.extract_cli_section(cli_text, "show system info")
    assert "hostname: tsf-test-fw" in section
    # must not bleed into the next command's output
    assert "commit-type" not in section


def test_extract_cli_section_missing_command_returns_empty(raw):
    _, cli_text = tsf_parser.extract_config_and_cli_text(raw)
    assert tsf_parser.extract_cli_section(cli_text, "show nonexistent thing") == ""


def test_parse_cli_system_info(raw):
    _, cli_text = tsf_parser.extract_config_and_cli_text(raw)
    info = tsf_parser.parse_cli_system_info(cli_text)
    assert info["available"] is True
    assert info["hostname"] == "tsf-test-fw"
    assert info["serial"] == "999900001111"
    assert info["sw_version"] == "11.1.0"
    assert info["uptime"] == "10 days, 1:02:03"


def test_parse_cli_license_info(raw):
    _, cli_text = tsf_parser.extract_config_and_cli_text(raw)
    licenses = tsf_parser.parse_cli_license_info(cli_text)
    by_feature = {lic["feature"]: lic for lic in licenses}
    assert by_feature["Test Feature Active"]["expired"] == "no"
    assert by_feature["Test Feature Active"]["expires"] == "January 01, 2030"
    assert by_feature["Test Feature Expired"]["expired"] == "yes"


def test_parse_cli_ha_status_not_enabled(raw):
    _, cli_text = tsf_parser.extract_config_and_cli_text(raw)
    ha = tsf_parser.parse_cli_ha_status(cli_text)
    assert ha == {"available": True, "enabled": False}


def test_parse_cli_ha_status_unrecognized_text_stays_unavailable():
    # Regression guard: an enabled-HA (or any other unrecognized) section must
    # never be guessed at — only the verified "HA not enabled" text is trusted.
    cli_text = "> show high-availability all\n\nsome text this parser has never verified\n"
    ha = tsf_parser.parse_cli_ha_status(cli_text)
    assert ha["available"] is False
    assert "unverified" in ha["reason"].lower() or "unconfirmed" in ha["reason"].lower()


def test_build_assessment_data_from_tsf_matches_config_and_overlays_runtime_data(raw):
    data = tsf_parser.build_assessment_data_from_tsf(raw)

    # Config-derived fields come straight from parser.parse_config() on the
    # merged config (which is just sample_config.xml here) — unchanged.
    assert len(data["security_rules"]) == 6
    assert len(data["zones"]) == 2

    # Runtime fields are overlaid from the CLI text dump instead of parser.py's
    # "unavailable in file-upload mode" placeholders.
    assert data["system_info"]["available"] is True
    assert data["system_info"]["hostname"] == "tsf-test-fw"
    assert data["licenses"]["available"] is True
    assert len(data["licenses"]["licenses"]) == 2
    assert data["ha"] == {"available": True, "enabled": False}


def test_missing_config_member_raises():
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="tmp/cli/techsupport_x.txt")
        data = b"> show system info\n\nhostname: x\n"
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    raw_bytes = buf.getvalue()

    with pytest.raises(ValueError):
        tsf_parser.extract_config_and_cli_text(raw_bytes)

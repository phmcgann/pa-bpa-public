import importlib.util
import io
import os
import re
import tarfile

import pytest

HERE = os.path.dirname(__file__)
FIXTURES = os.path.join(HERE, "fixtures")

_spec = importlib.util.spec_from_file_location(
    "verify_tsf", os.path.join(HERE, "..", "scripts", "verify_tsf.py"))
verify_tsf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_tsf)

# Identifying values from network_decryption_settings.xml the default report must never print
SENSITIVE = [
    "fw-netdec", "decrypt-outbound", "exclude-finance", "weak-decrypt", "insecure-mgmt",
    "good-zpp", "untrust", "ethernet1/1", "loopback.1", "10.0.0.0/24", "10.1.0.5", "to-panorama",
    "web-cert", "financial-services",
]


@pytest.fixture
def tsf_path(tmp_path):
    """The sample TSF's CLI text + the network/decryption fixture as its merged config."""
    with tarfile.open(os.path.join(FIXTURES, "sample_techsupport.tgz")) as src:
        cli_member = next(m for m in src.getmembers() if m.name.endswith(".txt"))
        cli_bytes = src.extractfile(cli_member).read()
    with open(os.path.join(FIXTURES, "network_decryption_settings.xml"), "rb") as f:
        config_bytes = f.read()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in [
            ("opt/pancfg/mgmt/saved-configs/.merged-running-config.xml", config_bytes),
            (cli_member.name, cli_bytes),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    path = tmp_path / "techsupport.tgz"
    path.write_bytes(buf.getvalue())
    return str(path)


def test_default_report_contains_no_identifying_values(tsf_path, capsys):
    assert verify_tsf.main([tsf_path]) == 0
    out = capsys.readouterr().out
    for value in SENSITIVE:
        # Whole-name match: 'untrust' (a zone) is also a substring of the tag block-untrusted-issuer
        pattern = rf"(?<![\w-]){re.escape(value)}(?![\w-])"
        assert not re.search(pattern, out), f"{value!r} leaked into the anonymized report"


def test_report_covers_every_section(tsf_path, capsys):
    verify_tsf.main([tsf_path])
    out = capsys.readouterr().out
    for heading in ["Parser lookup paths", "Tag structure", "Decryption (as parsed)", "Zone protection (as parsed)",
                    "Interface management profiles (as parsed)", "log forwarding", "Inline Cloud Analysis (as parsed)",
                    "Licenses", "Findings from the new checks"]:
        assert heading in out
    # The raw tag vocabulary is what verifies field names against a real device
    assert "ssl-forward-proxy/block-expired-certificate   [no×3]" in out
    assert "flood/udp/enable" in out
    # Placeholders stay consistent: the rule's profile is the same placeholder as the profile line
    assert "rule rule-4: action=decrypt type=ssl-forward-proxy disabled=no profile=profile-2" in out
    assert "rule rule-1: action=no-decrypt type=ssl-forward-proxy disabled=no profile=profile-1" in out
    assert "no_decrypt_block_expired=no" in out
    assert "profile profile-2: min_version=tls1-0 (explicit=no)" in out


def test_show_names_prints_real_names(tsf_path, capsys):
    verify_tsf.main([tsf_path, "--show-names"])
    out = capsys.readouterr().out
    assert "decrypt-outbound" in out
    assert "insecure-mgmt" in out


def test_rejects_non_tsf_file(capsys):
    assert verify_tsf.main([os.path.join(FIXTURES, "sample_config.xml")]) == 2
    assert "doesn't look like a tech support file" in capsys.readouterr().err


def test_safe_values():
    assert verify_tsf.safe("tls1-2") == "tls1-2"
    assert verify_tsf.safe("10000") == "10000"
    assert verify_tsf.safe("10.0.0.1") == "<other>"
    assert verify_tsf.safe("my-profile") == "<other>"
    assert verify_tsf.safe(None) == "—"
    assert verify_tsf.safe(False) == "no"


def test_output_file_is_utf8(tsf_path, tmp_path, capsys):
    out_file = tmp_path / "report.txt"
    assert verify_tsf.main([tsf_path, "-o", str(out_file)]) == 0
    text = out_file.read_bytes().decode("utf-8")
    assert "Findings from the new checks" in text
    assert "×" in text
    # Only the confirmation line goes to the console
    assert capsys.readouterr().out.strip() == f"Report written to {out_file}"

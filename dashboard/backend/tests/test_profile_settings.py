import os

import pytest

from app import parser
from app.rules.engine import run_rules

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "security_profile_settings.xml")


@pytest.fixture
def data():
    with open(FIXTURE, "rb") as f:
        return parser.parse_config(f.read())


@pytest.fixture
def keys(data):
    findings = run_rules(data, {})
    return {f["finding_key"] for f in findings}


def test_av_decoder_below_baseline(keys):
    assert "av_decoder_below_baseline:av_test:http2" in keys
    assert "av_decoder_below_baseline:av_test:ftp" not in keys


def test_av_inline_ml_disabled(keys):
    assert "av_inline_ml_disabled:av_test:MSOffice" in keys
    assert "av_inline_ml_disabled:av_test:Windows Executables" not in keys


def test_spyware_severity_below_baseline(keys):
    assert "spyware_severity_below_baseline:spy_test:simple-high" in keys
    assert "spyware_severity_below_baseline:spy_test:simple-critical" not in keys
    assert "spyware_severity_below_baseline:spy_test:simple-medium" not in keys
    # low severity isn't held to the reset baseline
    assert "spyware_severity_below_baseline:spy_test:simple-low" not in keys


def test_spyware_dns_category_mismatch(keys):
    assert "spyware_dns_category_mismatch:spy_test:pan-dns-sec-ddns" in keys
    assert "spyware_dns_category_mismatch:spy_test:pan-dns-sec-malware" not in keys


def test_vulnerability_severity_below_baseline(keys):
    assert "vulnerability_severity_below_baseline:vuln_test:simple-client-high" in keys
    assert "vulnerability_severity_below_baseline:vuln_test:simple-client-critical" not in keys


def test_url_mandatory_category_not_blocked(keys):
    assert "url_mandatory_category_not_blocked:url_test:scanning-activity" in keys
    assert "url_mandatory_category_not_blocked:url_test:malware" not in keys


def test_url_elevated_risk_category_not_blocked(keys):
    assert "url_elevated_risk_category_not_blocked:url_test:dynamic-dns" in keys
    assert "url_elevated_risk_category_not_blocked:url_test:encrypted-dns" in keys
    # proxy-avoidance-and-anonymizers is in the block list, so it shouldn't be flagged
    assert "url_elevated_risk_category_not_blocked:url_test:proxy-avoidance-and-anonymizers" not in keys


def test_url_credential_enforcement_disabled(keys):
    assert "url_credential_enforcement_disabled:url_test" in keys


def test_file_blocking_nothing_blocked(keys):
    assert "file_blocking_nothing_blocked:fb_alert_only" in keys
    assert "file_blocking_nothing_blocked:fb_blocking" not in keys


def test_threat_profile_missing_file_blocking_not_flagged(keys):
    # both file-blocking profiles are defined in this fixture, so the
    # "no File Blocking profiles at all" check shouldn't fire here
    assert "threat_profile_missing_file_blocking:global" not in keys


def test_wildfire_missing_recommended_filetype(keys):
    assert "wildfire_missing_recommended_filetype:wf_missing_types:pdf" in keys
    assert "wildfire_missing_recommended_filetype:wf_missing_types:ms-office" in keys
    assert "wildfire_missing_recommended_filetype:wf_full_coverage:pdf" not in keys
    assert "wildfire_missing_recommended_filetype:wf_full_coverage:ms-office" not in keys


# ── Inline Cloud Analysis (gated on an Advanced Threat Prevention license) ──

ICA_RULE_IDS = {
    "spyware_inline_cloud_analysis_disabled", "vulnerability_inline_cloud_analysis_disabled",
    "spyware_inline_cloud_model_not_reset", "vulnerability_inline_cloud_model_not_reset",
}


def _with_licenses(data, licenses):
    return {**data, "licenses": {"available": True, "licenses": licenses}}


ATP_ACTIVE = {"feature": "Advanced Threat Prevention", "expires": "December 31, 2099", "expired": "no"}
ATP_EXPIRED = {"feature": "Advanced Threat Prevention", "expires": "January 01, 2020", "expired": "yes"}
BASIC_TP = {"feature": "Threat Prevention", "expires": "December 31, 2099", "expired": "no"}


def _ica_keys(data):
    return {f["finding_key"] for f in run_rules(data, {}) if f["rule_id"] in ICA_RULE_IDS}


def test_parses_inline_cloud_analysis(data):
    spy = data["security_profiles"]["spyware"][0]["settings"]["inline_cloud_analysis"]
    assert spy == {"enabled": True, "models": {
        "HTTP Command and Control detector": "reset-both",
        "HTTP2 Command and Control detector": "alert",
    }}
    vuln = data["security_profiles"]["vulnerability"][0]["settings"]["inline_cloud_analysis"]
    # Absent <cloud-inline-analysis> is off; a model with no action takes the schema default, alert
    assert vuln == {"enabled": False, "models": {"SQL Injection": "alert"}}


def test_inline_cloud_checks_run_with_active_atp_license(data):
    keys = _ica_keys(_with_licenses(data, [BASIC_TP, ATP_ACTIVE]))
    assert keys == {
        "vulnerability_inline_cloud_analysis_disabled:vuln_test",
        "spyware_inline_cloud_model_not_reset:spy_test:HTTP2 Command and Control detector",
    }


def test_inline_cloud_checks_skipped_without_atp_license(data):
    # Basic Threat Prevention isn't Advanced Threat Prevention
    assert _ica_keys(_with_licenses(data, [BASIC_TP])) == set()


def test_inline_cloud_checks_skipped_with_expired_atp_license(data):
    assert _ica_keys(_with_licenses(data, [ATP_EXPIRED])) == set()


def test_inline_cloud_checks_run_when_renewal_sits_next_to_expired(data):
    assert _ica_keys(_with_licenses(data, [ATP_EXPIRED, ATP_ACTIVE])) != set()


def test_inline_cloud_checks_run_when_licenses_unknown(data):
    # A plain config upload has no license info at all: the checks run (as Palo Alto SCM's do), and say
    # they apply if the firewall is licensed. They're skipped only when the license is known to be absent.
    assert data["licenses"]["available"] is False
    assert _ica_keys(data) == _ica_keys(_with_licenses(data, [ATP_ACTIVE]))
    assert _ica_keys(_with_licenses(data, [BASIC_TP])) == set()


def test_inline_cloud_gate_status(data):
    from app.rules.checks import inline_cloud_analysis_gate
    assert inline_cloud_analysis_gate(data)["status"] == "license_unknown"
    assert inline_cloud_analysis_gate(_with_licenses(data, [BASIC_TP]))["status"] == "no_license"
    assert inline_cloud_analysis_gate(_with_licenses(data, [ATP_EXPIRED]))["status"] == "no_license"
    assert inline_cloud_analysis_gate(_with_licenses(data, [ATP_ACTIVE]))["status"] == "applies"


def test_inline_cloud_checks_skip_profiles_parsed_before_the_feature(data):
    licensed = _with_licenses(data, [ATP_ACTIVE])
    for ptype in ("spyware", "vulnerability"):
        for p in licensed["security_profiles"][ptype]:
            del p["settings"]["inline_cloud_analysis"]
    assert _ica_keys(licensed) == set()

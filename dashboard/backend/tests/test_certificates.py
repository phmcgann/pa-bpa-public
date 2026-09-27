"""Certificates: parsing (expiry, key, signature, where they're used) and the certificate checks.
Certificates are generated per test run; no real certificates are stored."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app import parser
from app.rules import checks
from app.rules.definitions import RULES_BY_ID

NOW = datetime.now(timezone.utc)
# The cryptography library no longer signs with SHA-1, so this one was made once with openssl:
# CN=weak, a 1024-bit RSA key, signed with SHA-1 by a throwaway "legacy-ca", valid until 2126.
WEAK_SHA1_PEM = """-----BEGIN CERTIFICATE-----
MIICKDCCARACFEWszf2rgvRvqXoxyfSM/45XiWQoMA0GCSqGSIb3DQEBBQUAMBQx
EjAQBgNVBAMMCWxlZ2FjeS1jYTAgFw0yNjA5MjQxNzQ2NDlaGA8yMTI2MDgzMTE3
NDY0OVowDzENMAsGA1UEAwwEd2VhazCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEA49oGSgI0R0uDduFhARQBzi7qtiwClSWUGivLvxroc/K80XTTbsDjMlRyqTfF
GF/wwXXQPg3inOtqkLRsx6JGLtLQi65YPAXRLcxV5LzS92/YBRdSUoCnR19nQnI/
2Zk2+vnWyuzf6mxph/DEUN+OY2+U5y6sMVyJaYmitL2JUV0CAwEAATANBgkqhkiG
9w0BAQUFAAOCAQEAj7gZyfnxFJSuCHzOYfb0Ns65spwutO5WJhUUDHo+PrN8SRXU
n/LpxVDg74keWqLMfQdA6FaUnXDLC92iCB507NW0/mz5eTASRlWUDL5j8vV84Vy8
QF9LPXTu9bfB9/iiz+9eN+yTrFtZOt6NI+z/5HbUS6J5WP85dNvyvv080XDPPpmb
0Z3HUqiE3n5hM9Ue0F6ZVSlObfZnPIJSWbWuDF7RLQzkXnRIlyullZWx2Ve53fWg
IziLVvPyzXfEVHxPHjsZ4pnvi3kraOcpBghrV0IVIxSHroMs1YFg7LOCYkZd3HsM
Qhqu1EFjddxiCCJQg2ltEUauVfCHsZlq6rW5wQ==
-----END CERTIFICATE-----"""
_KEYS = {}


def _key(kind):
    if kind not in _KEYS:
        _KEYS[kind] = {"rsa1024": lambda: rsa.generate_private_key(65537, 1024),
                       "rsa2048": lambda: rsa.generate_private_key(65537, 2048),
                       "ec256": lambda: ec.generate_private_key(ec.SECP256R1())}[kind]()
    return _KEYS[kind]


def _pem(cn, days, key="ec256", issuer=None, ca=False):
    """A certificate valid until `days` from now. `issuer` is (cn, key) of the CA; None → self-signed."""
    k = _key(key)
    issuer_cn, issuer_key = issuer or (cn, k)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
            .public_key(k.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=400)).not_valid_after(NOW + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _entry(name, pem, ca=False, private=True):
    return (f'<entry name="{name}"><common-name>{name}.example.com</common-name><ca>{"yes" if ca else "no"}</ca>'
            f'<public-key>{pem}</public-key>' + ("<private-key>-----ENCRYPTED-----</private-key>" if private else "")
            + "</entry>")


def _config():
    ca = ("corp-ca", _key("rsa2048"))
    certs = "".join([
        _entry("corp-ca", _pem("corp-ca", 3000, key="rsa2048", ca=True), ca=True),
        _entry("gp-cert", _pem("gp", 400)),                                           # self-signed, on GP portal
        _entry("mgmt-cert", _pem("mgmt", 20, issuer=ca)),                             # expiring soon, management
        _entry("ike-cert", _pem("ike", -5, issuer=ca)),                               # expired, IKE gateway
        _entry("old-cert", _pem("old", -30, issuer=ca)),                              # expired, unused
        _entry("weak-cert", WEAK_SHA1_PEM),                                          # weak key + SHA-1
        _entry("fwd-trust", _pem("fwd", 1000, key="rsa2048", ca=True), ca=True),     # decryption forward trust
    ])
    return f"""<config>
  <shared>
    <certificate>{certs}</certificate>
    <ssl-tls-service-profile>
      <entry name="gp-tls"><certificate>gp-cert</certificate></entry>
      <entry name="mgmt-tls"><certificate>mgmt-cert</certificate></entry>
      <entry name="weak-tls"><certificate>weak-cert</certificate></entry>
    </ssl-tls-service-profile>
    <certificate-profile><entry name="cp"><CA><entry name="corp-ca"/></CA></entry></certificate-profile>
    <ssl-decrypt><forward-trust-certificate><rsa>fwd-trust</rsa></forward-trust-certificate></ssl-decrypt>
  </shared>
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>fw</hostname><ssl-tls-service-profile>mgmt-tls</ssl-tls-service-profile></system></deviceconfig>
    <network><ike><gateway><entry name="branch">
      <authentication><certificate><local-certificate><name>ike-cert</name></local-certificate></certificate></authentication>
    </entry></gateway></ike></network>
    <vsys><entry name="vsys1">
      <global-protect><global-protect-portal><entry name="portal">
        <portal-config><ssl-tls-service-profile>gp-tls</ssl-tls-service-profile></portal-config>
      </entry></global-protect-portal></global-protect>
    </entry></vsys>
  </entry></devices>
</config>""".encode()


@pytest.fixture(scope="module")
def data():
    return parser.parse_config(_config())


def _certs(data):
    return {c["name"]: c for c in data["certificates"]["certificates"]}


def _keys(data, rule_id):
    return sorted(f["key"] for f in checks.CHECKS[rule_id](data, RULES_BY_ID[rule_id].thresholds))


def test_parses_key_signature_and_expiry(data):
    c = _certs(data)
    assert (c["weak-cert"]["key_algorithm"], c["weak-cert"]["key_bits"], c["weak-cert"]["signature_hash"]) == \
        ("RSA", 1024, "SHA-1")
    assert (c["gp-cert"]["key_algorithm"], c["gp-cert"]["key_bits"], c["gp-cert"]["self_signed"]) == ("EC", 256, True)
    assert c["mgmt-cert"]["self_signed"] is False and c["corp-ca"]["ca"] is True
    assert datetime.fromisoformat(c["ike-cert"]["not_after"]) < NOW


def test_finds_where_each_certificate_is_used(data):
    c = _certs(data)
    assert c["gp-cert"]["used_by"] == ["SSL/TLS service profile 'gp-tls' (GlobalProtect portal 'portal')"]
    assert c["gp-cert"]["services"] == ["GlobalProtect portal 'portal'"]
    assert c["mgmt-cert"]["used_by"] == ["SSL/TLS service profile 'mgmt-tls' (management interface)"]
    assert c["ike-cert"]["used_by"] == ["IKE gateway 'branch'"]
    assert c["corp-ca"]["used_by"] == ["certificate profile 'cp'"]
    assert c["fwd-trust"]["used_by"] == ["decryption forward trust"]
    assert c["weak-cert"]["used_by"] == ["SSL/TLS service profile 'weak-tls'"]
    assert c["old-cert"]["used_by"] == []


def test_certificate_checks(data):
    assert _keys(data, "cert_expired") == ["ike-cert"]
    assert _keys(data, "cert_expiring_soon") == ["mgmt-cert"]
    assert _keys(data, "cert_expired_unused") == ["old-cert"]
    assert _keys(data, "cert_weak_key") == ["weak-cert"]
    assert _keys(data, "cert_weak_signature") == ["weak-cert"]
    # Self-signed CAs used as trust anchors (corp-ca, fwd-trust) aren't user-facing services.
    assert _keys(data, "cert_self_signed_service") == ["gp-cert"]


def test_expiring_soon_threshold_is_adjustable(data):
    fn = checks.CHECKS["cert_expiring_soon"]
    assert fn(data, {"expiry_warning_days": 10}) == []


def test_message_names_the_use(data):
    [f] = checks.CHECKS["cert_expired"](data, {})
    assert "IKE gateway 'branch'" in f["message"] and "ike-cert.example.com" in f["message"]


def test_config_without_certificates_and_old_assessments():
    for d in ({"certificates": {"certificates": []}}, {}):
        for rule_id in ("cert_expired", "cert_expiring_soon", "cert_expired_unused", "cert_weak_key",
                        "cert_weak_signature", "cert_self_signed_service"):
            assert checks.CHECKS[rule_id](d, RULES_BY_ID[rule_id].thresholds) == []


def test_certificate_without_pem_falls_back_to_xml_fields():
    xml = b"""<config><shared><certificate><entry name="x"><subject>/CN=x</subject><issuer>/CN=x</issuer>
      <expiry-epoch>1000000000</expiry-epoch><algorithm>RSA</algorithm></entry></certificate></shared></config>"""
    [c] = parser.parse_config(xml)["certificates"]["certificates"]
    assert c["not_after"].startswith("2001-09-09") and c["self_signed"] is True and c["key_bits"] is None

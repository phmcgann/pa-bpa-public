"""
Certificates in a PAN-OS config and where the config uses them.

A certificate lives under shared/certificate/entry or a vsys's certificate/entry. Its
XML carries the PEM (<public-key>), the expiry (<expiry-epoch>, <not-valid-after>), the
subject and issuer, whether it's a CA, and — when the firewall holds the key — a
<private-key> or <private-key-on-hsm>. Key size and signature hash come from the PEM.

References are found by walking the rest of the config for values naming a certificate
under a certificate-related element (an SSL/TLS service profile's <certificate>, the
decryption forward trust/untrust, a certificate profile's CA list, an IKE gateway's
local certificate, a GlobalProtect root CA list, …). SSL/TLS service profiles are
followed one step further to the services that use them (management interface,
GlobalProtect portals and gateways, Authentication Portal).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

_CERT_TAG = re.compile(r"cert|^ca$|root-ca|trusted-root|ssl-inbound-inspection", re.IGNORECASE)
# Services a user connects to, which should present a certificate clients can verify.
USER_FACING = ("GlobalProtect portal", "GlobalProtect gateway", "Authentication Portal")


def _text(el: Optional[ET.Element], path: str) -> Optional[str]:
    node = el.find(path) if el is not None else None
    return node.text.strip() if node is not None and node.text and node.text.strip() else None


def _pem_details(pem: Optional[str]) -> dict:
    if not pem or "BEGIN CERTIFICATE" not in pem:
        return {}
    try:
        cert = x509.load_pem_x509_certificate(pem.strip().encode())
    except ValueError:
        return {"parse_error": True}
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algo, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algo, bits = "EC", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        algo, bits = "DSA", key.key_size
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        algo, bits = "EdDSA", 256 if isinstance(key, ed25519.Ed25519PublicKey) else 456
    else:
        algo, bits = type(key).__name__, None
    try:
        sig_hash = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else None
    except Exception:  # an algorithm cryptography doesn't know
        sig_hash = None
    return {
        "key_algorithm": algo,
        "key_bits": bits,
        "signature_hash": sig_hash.replace("SHA", "SHA-") if sig_hash and sig_hash.startswith("SHA") and "-" not in sig_hash else sig_hash,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "self_signed": cert.issuer == cert.subject,
    }


def _xml_not_after(e: ET.Element) -> Optional[str]:
    epoch = _text(e, "expiry-epoch")
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), timezone.utc).isoformat()
    raw = _text(e, "not-valid-after")
    if raw:
        try:
            return datetime.strptime(" ".join(raw.split()), "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return None
    return None


def _cert_entry(e: ET.Element, scope: str) -> dict:
    details = _pem_details(_text(e, "public-key"))
    subject, issuer = _text(e, "subject"), _text(e, "issuer")
    return {
        "name": e.get("name"),
        "scope": scope,
        "common_name": _text(e, "common-name"),
        "subject": subject,
        "issuer": issuer,
        "ca": _text(e, "ca") == "yes",
        "has_private_key": e.find("private-key") is not None or _text(e, "private-key-on-hsm") == "yes",
        "key_algorithm": details.get("key_algorithm") or _text(e, "algorithm"),
        "key_bits": details.get("key_bits"),
        "signature_hash": details.get("signature_hash"),
        "not_after": details.get("not_after") or _xml_not_after(e),
        "self_signed": details["self_signed"] if "self_signed" in details else (bool(subject) and subject == issuer),
        "used_by": [],
        "services": [],
    }


def _context(stack: list[tuple[str, Optional[str]]]) -> str:
    """A readable name for where a reference sits, from the innermost recognisable element outwards."""
    tags = [t for t, _ in stack]
    for i in range(len(stack) - 1, 0, -1):
        tag, name = stack[i]
        kind = stack[i - 1][0]
        if tag == "entry" and name:
            label = {
                "ssl-tls-service-profile": "SSL/TLS service profile", "certificate-profile": "certificate profile",
                "global-protect-portal": "GlobalProtect portal", "global-protect-gateway": "GlobalProtect gateway",
                "gateway": "IKE gateway" if "ike" in tags else None, "rules": "decryption rule" if "decryption" in tags else None,
                "scep": "SCEP profile", "syslog": "syslog profile", "ldap": "LDAP server profile",
            }.get(kind)
            if label:
                return f"{label} '{name}'"
    if "ssl-decrypt" in tags:
        for tag, label in (("forward-trust-certificate", "decryption forward trust"),
                           ("forward-untrust-certificate", "decryption forward untrust"),
                           ("trusted-root-CA", "decryption trusted root CA")):
            if tag in tags:
                return label
        return "decryption"
    if "captive-portal" in tags:
        return "Authentication Portal"
    if "deviceconfig" in tags and "system" in tags:
        return "management interface"
    return "/".join(tags[-3:])


def parse_certificates(layers: list[ET.Element]) -> dict:
    """`layers` are <config>-shaped roots, lowest priority first; a later layer's same-named certificate wins."""
    certs: dict[str, dict] = {}
    for layer in layers:
        shared = layer.find("shared")
        for e in (shared.findall("certificate/entry") if shared is not None else []):
            if e.get("name"):
                certs[e.get("name")] = _cert_entry(e, "shared")
        for v in layer.findall("devices/entry/vsys/entry"):
            for e in v.findall("certificate/entry"):
                if e.get("name"):
                    certs[e.get("name")] = _cert_entry(e, v.get("name") or "vsys")

    cert_refs: dict[str, set[str]] = {}
    tls_certs: dict[str, set[str]] = {}   # SSL/TLS service profile → certificates
    tls_users: dict[str, set[str]] = {}   # SSL/TLS service profile → services using it

    def walk(el: ET.Element, stack: list[tuple[str, Optional[str]]]) -> None:
        for child in el:
            tag = child.tag
            if tag == "certificate" and stack and stack[-1][0] in ("shared", "entry") and len(child) and \
                    all(c.tag == "entry" for c in child):
                continue  # the certificate store itself
            here = stack + [(tag, child.get("name"))]
            recent = [t for t, _ in here[-4:]]
            value = child.text.strip() if child.text and child.text.strip() and not len(child) else None
            if value is None and tag == "entry" and child.get("name") and not len(child):
                value = child.get("name")  # e.g. <CA><entry name="corp-ca"/></CA>
            if value is not None:
                if tag == "ssl-tls-service-profile":
                    tls_users.setdefault(value, set()).add(_context(stack))
                elif value in certs and any(_CERT_TAG.search(t) for t in recent):
                    ctx = _context(here)
                    if ctx.startswith("SSL/TLS service profile '"):
                        tls_certs.setdefault(ctx[len("SSL/TLS service profile '"):-1], set()).add(value)
                    else:
                        cert_refs.setdefault(value, set()).add(ctx)
            walk(child, here)

    for layer in layers:
        walk(layer, [])

    for profile, names in tls_certs.items():
        services = sorted(tls_users.get(profile, set()))
        label = f"SSL/TLS service profile '{profile}'" + (f" ({', '.join(services)})" if services else "")
        for n in names:
            certs[n]["used_by"].append(label)
            certs[n]["services"].extend(s for s in services if s not in certs[n]["services"])
    for n, ctxs in cert_refs.items():
        certs[n]["used_by"].extend(sorted(ctxs))
        certs[n]["services"].extend(c for c in sorted(ctxs) if c.startswith(USER_FACING) and c not in certs[n]["services"])

    return {"certificates": [certs[n] for n in sorted(certs)]}

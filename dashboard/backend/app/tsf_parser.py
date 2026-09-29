"""
PAN-OS Tech Support File (.tgz) parsing.

A TSF is a diagnostic bundle a firewall generates on demand. Traced against a
real TSF from a Panorama-managed firewall rather than assumed, this turned
out to be a *better* data source than either of the other two ingestion
paths:

  - opt/pancfg/mgmt/saved-configs/.merged-running-config.xml is the actual
    PAN-OS-computed effective config — for a Panorama-managed firewall this
    is the real merge (zones, rules, profiles, profile groups, admin
    accounts, mgmt settings), more accurate than panorama_parser.py's own
    device-group/template-stack approximation (verified: 68 real rules here
    vs 51 from the approximation, on the same firewall). It parses cleanly
    through parser.parse_config() completely unchanged — no new config
    parsing logic needed here at all.
  - opt/pancfg/mgmt/saved-configs/running-config.xml (and the byte-identical
    techsupport-saved-currcfg.xml) is the same thin "local view" a
    Panorama-managed firewall's own live export gives — used as a fallback
    for a TSF from a non-Panorama-managed firewall, where there's nothing to
    merge and this is simply the config.
  - tmp/cli/techsupport_<hostname>_<timestamp>.txt is a large concatenated
    dump of CLI "show"/"request" command output. "show system info",
    "request license info", and "show high-availability all" are in there as
    plain key:value / repeating-block text — not XML — giving us system
    info, license status, and (at least the disabled case) HA state without
    any live API connection.

The one unverified piece: the *enabled*-HA text format. This firewall's HA
was disabled, so only "HA not enabled" was confirmed. Rather than guess the
enabled-case format, that path is left explicitly unavailable with a reason
saying so — same "don't guess unverified schema" rule that's caught real
bugs elsewhere in this codebase.
"""

from __future__ import annotations

import fnmatch
import io
import re
import tarfile

from . import parser

MERGED_CONFIG_SUFFIX = "saved-configs/.merged-running-config.xml"
PLAIN_CONFIG_SUFFIX = "saved-configs/running-config.xml"
CLI_TEXT_PATTERN = "*/tmp/cli/techsupport_*.txt"

# System info CLI keys (hyphenated, matching PAN-OS's own field spelling) ->
# our AssessmentData field names (same mapping parser.parse_system_info's
# live branch uses for the XML equivalent).
SYSTEM_INFO_FIELD_MAP = {
    "hostname": "hostname",
    "ip-address": "ip_address",
    "model": "model",
    "serial": "serial",
    "sw-version": "sw_version",
    "app-version": "app_version",
    "av-version": "av_version",
    "wildfire-version": "wildfire_version",
    "threat-version": "threat_version",
    "uptime": "uptime",
    "operational-mode": "operational_mode",
}


def looks_like_tsf(filename: str, raw: bytes) -> bool:
    """.tgz/.tar.gz by extension, or gzip magic bytes as a fallback in case
    the extension was stripped/renamed."""
    name = (filename or "").lower()
    if name.endswith(".tgz") or name.endswith(".tar.gz"):
        return True
    return raw[:2] == b"\x1f\x8b"


def _find_member(tar: tarfile.TarFile, suffix: str) -> tarfile.TarInfo | None:
    for member in tar.getmembers():
        if member.isfile() and member.name.endswith(suffix):
            return member
    return None


def _find_member_glob(tar: tarfile.TarFile, pattern: str) -> tarfile.TarInfo | None:
    for member in tar.getmembers():
        if member.isfile() and fnmatch.fnmatch("/" + member.name, pattern):
            return member
    return None


def extract_config_and_cli_text(raw: bytes) -> tuple[bytes, str]:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        config_member = _find_member(tar, MERGED_CONFIG_SUFFIX) or _find_member(tar, PLAIN_CONFIG_SUFFIX)
        if config_member is None:
            raise ValueError(
                "No running-config.xml or merged-running-config.xml found inside this tech "
                "support file — is this a genuine PAN-OS TSF?"
            )
        config_fileobj = tar.extractfile(config_member)
        config_bytes = config_fileobj.read() if config_fileobj else b""

        cli_member = _find_member_glob(tar, CLI_TEXT_PATTERN)
        cli_text = ""
        if cli_member is not None:
            cli_fileobj = tar.extractfile(cli_member)
            if cli_fileobj:
                cli_text = cli_fileobj.read().decode("utf-8", errors="replace")

    return config_bytes, cli_text


def extract_cli_section(cli_text: str, command: str) -> str:
    """The tech-support CLI dump is a sequence of "> <command>" markers each
    followed by that command's output. Returns everything between the given
    command's marker and the next "> " marker (or EOF)."""
    lines = cli_text.splitlines()
    marker = f"> {command}"
    start = None
    for i, line in enumerate(lines):
        if line.strip() == marker:
            start = i + 1
            break
    if start is None:
        return ""

    end = len(lines)
    for i in range(start, len(lines)):
        if lines[i].startswith("> "):
            end = i
            break
    return "\n".join(lines[start:end])


def _parse_kv_block(text: str) -> dict[str, str]:
    kv = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        kv[key.strip()] = value.strip()
    return kv


def parse_cli_system_info(cli_text: str) -> dict:
    section = extract_cli_section(cli_text, "show system info")
    if not section.strip():
        return {
            "available": False,
            "hostname": "N/A",
            "reason": "'show system info' section not found in this tech support file.",
        }
    kv = _parse_kv_block(section)
    data = {"available": True}
    for cli_key, field in SYSTEM_INFO_FIELD_MAP.items():
        data[field] = kv.get(cli_key, "N/A")
    return data


def parse_cli_license_info(cli_text: str) -> list[dict]:
    section = extract_cli_section(cli_text, "request license info")
    if not section.strip():
        return []
    blocks = section.split("License entry:")[1:]  # first split chunk is empty preamble
    licenses = []
    for block in blocks:
        kv = _parse_kv_block(block)
        feature = kv.get("Feature")
        if not feature:
            continue
        licenses.append({
            "feature": feature,
            "expires": kv.get("Expires", "N/A"),
            "expired": (kv.get("Expired?", "no") or "no").lower(),
        })
    return licenses


def parse_cli_ha_status(cli_text: str) -> dict:
    section = extract_cli_section(cli_text, "show high-availability all")
    if not section.strip():
        return {
            "available": False,
            "reason": "'show high-availability all' section not found in this tech support file.",
        }
    if "ha not enabled" in section.lower():
        return {"available": True, "enabled": False}
    return {
        "available": False,
        "reason": "HA appears to be enabled on this device, but this tool hasn't verified the "
                  "tech-support text format for the enabled-HA case yet, so it isn't parsed — "
                  "treat this as unconfirmed rather than guessed. Connect a live device for a "
                  "reliable HA state.",
    }


_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def parse_cli_managed_devices(cli_text: str, serials: list[str]) -> dict[str, str]:
    """Hostnames of Panorama's managed firewalls, by serial, from its own device list in the tech
    support text ("show devices all"). Best effort: it reads both "serial: …" / "hostname: …" blocks
    and tables with Serial and Hostname columns, and only for the serials Panorama's config lists."""
    wanted = set(serials)
    found: dict[str, str] = {}
    current: str | None = None
    columns: tuple[int, int] | None = None
    for line in cli_text.splitlines():
        stripped = line.strip()
        kv = re.match(r"^(serial|hostname)\s*:\s*(\S+)$", stripped, re.IGNORECASE)
        if kv:
            key, value = kv.group(1).lower(), kv.group(2)
            if key == "serial":
                current = value if value in wanted else None
            elif current and current not in found and _HOSTNAME.match(value) and value != current:
                found[current] = value
            continue
        tokens = stripped.split()
        lowered = [t.lower() for t in tokens]
        if "serial" in lowered and "hostname" in lowered:
            columns = (lowered.index("serial"), lowered.index("hostname"))
            continue
        if columns and len(tokens) > max(columns):
            serial, host = tokens[columns[0]], tokens[columns[1]]
            if serial in wanted and serial not in found and _HOSTNAME.match(host) and host != serial:
                found[serial] = host
    return found


def build_assessment_data_from_tsf(raw: bytes) -> dict:
    """Same AssessmentData shape parser.parse_config() returns — the config
    fields come from parse_config() unchanged, then system_info/licenses/ha
    are overlaid with what the tech-support CLI text dump actually has,
    instead of parser.py's live-only "unavailable" placeholders."""
    return build_assessment_data_from_parts(*extract_config_and_cli_text(raw))


def build_assessment_data_from_parts(config_bytes: bytes, cli_text: str) -> dict:
    """The same, from the two parts of the file it reads (kept with the assessment for re-analysis)."""
    data = parser.parse_config(config_bytes)

    data["system_info"] = parse_cli_system_info(cli_text)
    data["licenses"] = {"available": True, "licenses": parse_cli_license_info(cli_text)}
    data["ha"] = parse_cli_ha_status(cli_text)

    return data

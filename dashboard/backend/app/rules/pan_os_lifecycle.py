"""PAN-OS release lifecycle: when Palo Alto Networks stops supporting each feature release.

From Palo Alto's End-of-Life Summary (SOURCE). Its "End-of-Life Date" for a release has two parts:
Standard Support, and the Extended Support that begins automatically when standard support ends
(only some releases have it). A release is end-of-life once the last of the two has passed.

Update RELEASES and AS_OF when Palo Alto publishes a new release or moves a date; the Settings page
shows AS_OF so it's clear how current this table is.
"""
from __future__ import annotations

import re
from datetime import date

SOURCE = "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary"
AS_OF = "2026-10-14"

# feature release -> (standard support ends, extended support ends or None)
RELEASES: dict[tuple[int, int], tuple[str, str | None]] = {
    (12, 2): ("2029-07-30", "2030-07-30"),
    (12, 1): ("2028-08-28", "2029-08-28"),
    (11, 2): ("2027-05-02", "2027-08-31"),
    (11, 1): ("2027-05-03", "2027-08-31"),
    (11, 0): ("2024-11-17", None),
    (10, 2): ("2025-08-27", "2027-03-31"),
    (10, 1): ("2024-12-01", "2026-03-31"),
    (10, 0): ("2022-07-16", None),
    (9, 1): ("2024-06-30", None),
    (9, 0): ("2022-03-01", None),
    (8, 1): ("2022-03-01", None),
    (8, 0): ("2019-10-31", None),
}
OLDEST = min(RELEASES)
NEWEST = max(RELEASES)

_VERSION = re.compile(r"^\s*(\d+)\.(\d+)")


def today() -> date:
    """Separate so tests can pin the date."""
    return date.today()


def feature_release(version: str | None) -> tuple[int, int] | None:
    """'10.2.9-h1' -> (10, 2)."""
    m = _VERSION.match(version or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def _label(release: tuple[int, int]) -> str:
    return f"{release[0]}.{release[1]}"


def _when(iso: str) -> str:
    d = date.fromisoformat(iso)
    return f"{d:%B} {d.day}, {d.year}"


def status(version: str | None, on: date | None = None) -> dict | None:
    """Where `version` is in its lifecycle on `on` (default today). None when the version can't be
    read or is newer than this table knows about (no judgement either way)."""
    rel = feature_release(version)
    if rel is None or rel > NEWEST:
        return None
    on = on or today()
    if rel not in RELEASES:
        if rel < OLDEST:
            return {"release": _label(rel), "state": "eol", "standard_end": None, "extended_end": None, "days_left": None}
        return None  # a gap in the table, e.g. a VM-Series-only release; don't guess
    standard, extended = RELEASES[rel]
    final = extended or standard
    if on > date.fromisoformat(final):
        state = "eol"
    elif on > date.fromisoformat(standard):
        state = "extended"
    else:
        state = "standard"
    return {"release": _label(rel), "state": state, "standard_end": standard, "extended_end": extended,
            "days_left": (date.fromisoformat(final) - on).days, "standard_days_left": (date.fromisoformat(standard) - on).days}


def supported_releases(on: date | None = None) -> list[str]:
    """Releases still in standard support, oldest first."""
    on = on or today()
    return [_label(r) for r in sorted(RELEASES) if date.fromisoformat(RELEASES[r][0]) >= on]


def finding(version: str, source: str, warn_days: int, on: date | None = None) -> dict | None:
    """The end-of-life finding for `version` (or None): a check item with its own severity."""
    s = status(version, on)
    if s is None:
        return None
    rel = s["release"]
    supported = supported_releases(on)
    upgrade = (f"Upgrade to a release in standard support ({', '.join(supported[:-1])} or {supported[-1]})"
               if len(supported) > 1 else f"Upgrade to {supported[0]}" if supported else "Upgrade to a supported release")
    upgrade += ", after checking Palo Alto's recommended release for your hardware model."
    where = f"PAN-OS {version} ({source})"
    if s["state"] == "eol":
        if s["standard_end"] is None:
            message = f"{where} is long past end-of-life."
        elif s["extended_end"]:
            message = (f"{where} is past end-of-life: standard support for {rel} ended on {_when(s['standard_end'])} "
                       f"and extended support on {_when(s['extended_end'])}.")
        else:
            message = f"{where} is past end-of-life: support for {rel} ended on {_when(s['standard_end'])}."
        return {"key": "global", "severity": "CRITICAL", "message": message,
                "recommendation": upgrade + " Palo Alto no longer fixes bugs or vulnerabilities in this release. "
                "If it's the last release your hardware supports, check Palo Alto's hardware end-of-life summary: "
                "support may run until the hardware's own end-of-life."}
    if s["state"] == "extended":
        return {"key": "global", "severity": "WARNING",
                "message": f"{where} is out of standard support: standard support for {rel} ended on "
                           f"{_when(s['standard_end'])}. Extended support runs until {_when(s['extended_end'])} "
                           f"({s['days_left']} days).",
                "recommendation": f"Plan the upgrade before {_when(s['extended_end'])}. {upgrade}"}
    if s["standard_days_left"] <= warn_days:
        if s["extended_end"]:
            return {"key": "global", "severity": "LOW",
                    "message": f"{where}: standard support for {rel} ends on {_when(s['standard_end'])} "
                               f"({s['standard_days_left']} days); extended support follows until {_when(s['extended_end'])}.",
                    "recommendation": f"Plan the upgrade. {upgrade}"}
        return {"key": "global", "severity": "WARNING",
                "message": f"{where} reaches end-of-life on {_when(s['standard_end'])} ({s['standard_days_left']} days).",
                "recommendation": f"Plan the upgrade before {_when(s['standard_end'])}. {upgrade}"}
    return None

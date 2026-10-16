"""How current the Palo Alto content bundled with the dashboard is.

Most of what the checks know about Palo Alto (its SCM BPA checks, PAN-OS end-of-life dates, the
predefined profiles, the built-in IP lists) is a snapshot that's only as new as the dashboard
release. Settings lists each with its date, so it's clear when it's due a review. Security
advisories are the exception: they're downloaded live.
"""
from __future__ import annotations

from datetime import date, datetime

from . import advisories
from .rules import builtin_profiles, pan_os_lifecycle, scm_catalog, threat_intel

# Bundled content older than this is flagged as due a review.
REVIEW_AFTER_DAYS = 180


def _bundled(id_: str, label: str, as_of: str, detail: str, source: str | None, on: date) -> dict:
    age = (on - date.fromisoformat(as_of)).days
    return {"id": id_, "label": label, "kind": "bundled", "as_of": as_of, "age_days": age,
            "review_due": age > REVIEW_AFTER_DAYS, "detail": detail, "source": source}


def report(on: date | None = None) -> dict:
    on = on or pan_os_lifecycle.today()
    catalog = scm_catalog.load()
    newest = max(pan_os_lifecycle.RELEASES)
    items = [
        _bundled("pan_os_lifecycle", "PAN-OS end-of-life dates", pan_os_lifecycle.AS_OF,
                 f"{len(pan_os_lifecycle.RELEASES)} feature releases, up to {newest[0]}.{newest[1]}. "
                 "Newer releases aren't judged until this is updated.",
                 pan_os_lifecycle.SOURCE, on),
        _bundled("scm_catalog", "Strata Cloud Manager BPA checks", catalog["retrieved"],
                 f"{len(catalog['checks'])} checks. Checks Palo Alto added since are labelled "
                 "\"New from Palo Alto\" on an assessment's SCM coverage.",
                 None, on),
        _bundled("builtin_profiles", "PAN-OS predefined security profiles", builtin_profiles.AS_OF,
                 "Settings of the built-in profiles (default, strict, …), graded when a rule uses one.", None, on),
        _bundled("threat_intel", "Palo Alto built-in IP lists", threat_intel.AS_OF,
                 f"{len(threat_intel.ALL_LISTS)} lists, including Advanced IP Defense.", None, on),
    ]
    feed = advisories.status()
    fetched = feed.get("fetched_at")
    items.append({
        "id": "advisories", "label": "PAN-OS security advisories", "kind": "live",
        "as_of": datetime.fromisoformat(fetched).date().isoformat() if fetched else None,
        "fetched_at": fetched, "status": feed["status"], "age_days": None, "review_due": False,
        "detail": (f"{feed['count']} advisories, downloaded from Palo Alto every 12 hours."
                   if feed["status"] == "ok" else feed.get("reason")),
        "source": advisories.FEED_URL.removesuffix("json/"),
    })
    return {"items": items, "review_after_days": REVIEW_AFTER_DAYS}

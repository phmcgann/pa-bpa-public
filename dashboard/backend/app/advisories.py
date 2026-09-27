"""
Palo Alto Networks security advisories for PAN-OS, from the public feed behind
security.paloaltonetworks.com (the site's own JSON API, 25 advisories a page).

The feed is fetched in a background thread and cached in memory and on disk, so a
page view never waits on it. Checks read the cached copy through `snapshot()`;
until the first fetch finishes (or when the feed can't be reached and there's no
cached copy) the advisory checks report nothing and `status()` says why.

Matching uses each advisory's explicit list of affected versions when it has one,
and otherwise its per-release "< x.y.z-hN" ranges.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone

import httpx

FEED_URL = "https://security.paloaltonetworks.com/json/"
ADVISORY_URL = "https://security.paloaltonetworks.com/{id}"
REFRESH_SECONDS = 12 * 3600
RETRY_SECONDS = 10 * 60
MAX_PAGES = 60

_lock = threading.Lock()
_state: dict = {"advisories": None, "fetched_at": None, "error": None, "last_attempt": 0.0, "refreshing": False}


def _enabled() -> bool:
    """PAN_ADVISORY_FEED=off turns fetching off (tests, air-gapped installs)."""
    return os.environ.get("PAN_ADVISORY_FEED", "on").lower() not in ("off", "0", "false", "no")


def _cache_file() -> str:
    return os.environ.get("PAN_ADVISORY_CACHE", os.path.join(tempfile.gettempdir(), "pan_advisories.json"))


def _slim(a: dict) -> dict:
    return {
        "id": a.get("ID"),
        "title": " ".join((a.get("title") or "").split()),
        "severity": (a.get("severity") or a.get("baseSeverity") or "NONE").upper(),
        "score": a.get("baseScore"),
        "date": a.get("date"),
        "version": a.get("version") or [],
        "affected": a.get("affected") or [],
        "fixed": a.get("fixed") or [],
        "affected_list": [v for v in a.get("affected_list") or [] if isinstance(v, str) and v.startswith("PAN-OS ")],
    }


def fetch(client: httpx.Client | None = None) -> list[dict]:
    client = client or httpx.Client(timeout=30)
    seen: dict[str, dict] = {}
    for page in range(1, MAX_PAGES + 1):
        resp = client.get(FEED_URL, params={"product": "PAN-OS", "page": page})
        resp.raise_for_status()
        batch = resp.json()
        new = [a for a in batch if a.get("ID") and a["ID"] not in seen]
        if not new:
            break
        for a in new:
            seen[a["ID"]] = _slim(a)
    return list(seen.values())


def _load_cache() -> None:
    try:
        with open(_cache_file()) as f:
            cached = json.load(f)
        _state["advisories"] = cached["advisories"]
        _state["fetched_at"] = cached["fetched_at"]
    except (OSError, ValueError, KeyError):
        pass


def _refresh() -> None:
    try:
        advisories = fetch()
        fetched_at = datetime.now(timezone.utc).isoformat()
        with _lock:
            _state.update(advisories=advisories, fetched_at=fetched_at, error=None)
        try:
            with open(_cache_file(), "w") as f:
                json.dump({"advisories": advisories, "fetched_at": fetched_at}, f)
        except OSError:
            pass
    except (httpx.HTTPError, ValueError) as e:
        with _lock:
            _state["error"] = f"Couldn't reach the Palo Alto Networks security advisory feed ({type(e).__name__})."
    finally:
        with _lock:
            _state["refreshing"] = False


def ensure_fresh() -> None:
    """Start a background refresh when the cached copy is missing or old. Never blocks."""
    if not _enabled():
        return
    with _lock:
        if _state["advisories"] is None and _state["fetched_at"] is None:
            _load_cache()
        age = _age_seconds()
        stale = age is None or age > REFRESH_SECONDS
        if not stale or _state["refreshing"] or time.time() - _state["last_attempt"] < RETRY_SECONDS:
            return
        _state.update(refreshing=True, last_attempt=time.time())
    threading.Thread(target=_refresh, daemon=True).start()


def _age_seconds() -> float | None:
    if not _state["fetched_at"]:
        return None
    return (datetime.now(timezone.utc) - datetime.fromisoformat(_state["fetched_at"])).total_seconds()


def snapshot() -> list[dict] | None:
    """The cached advisories, or None when there's no copy yet."""
    ensure_fresh()
    return _state["advisories"]


def status() -> dict:
    ensure_fresh()
    if _state["advisories"] is None and not _enabled():
        return {"status": "disabled", "fetched_at": None, "count": 0,
                "reason": "Checking Palo Alto Networks security advisories is turned off (PAN_ADVISORY_FEED=off)."}
    if _state["advisories"] is None:
        return {"status": "error" if _state["error"] else "loading", "fetched_at": None, "count": 0,
                "reason": _state["error"] or "Downloading Palo Alto Networks security advisories — reload in a moment."}
    return {"status": "ok", "fetched_at": _state["fetched_at"], "count": len(_state["advisories"]),
            "reason": _state["error"]}


def set_for_tests(advisories: list[dict] | None) -> None:
    with _lock:
        _state.update(advisories=advisories, fetched_at=datetime.now(timezone.utc).isoformat() if advisories is not None
                      else None, error=None)


# ── Version matching ──────────────────────────────────────────────────────

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?")


def parse_version(v: str) -> tuple[int, int, int, int] | None:
    m = _VERSION.match((v or "").strip())
    if not m:
        return None
    return int(m[1]), int(m[2]), int(m[3]), int(m[4] or 0)


def _bounds(text: str) -> list[tuple[str, tuple]] | None:
    """'< 11.2.4-h21, < 11.2.7-h20' → [(op, version)], or None when a part isn't a plain range
    (qualified by platform, e.g. 'on Panorama', or a format this doesn't read)."""
    out = []
    for part in text.split(","):
        part = part.strip()
        m = re.fullmatch(r"(<=?)\s*(\d+\.\d+\.\d+(?:-h\d+)?)", part)
        if not m:
            return None
        out.append((m[1], parse_version(m[2])))
    return out


def _range_affected(text: str, v: tuple) -> bool | None:
    """Whether `v` falls in an advisory's range text for its release, e.g. '< 11.2.4-h21, < 11.2.7-h20'.
    A hotfix bound (x.y.z-hN) fixes only that maintenance release (11.2.5 still needs 11.2.7-h20); a
    plain bound (x.y.z) fixes every later build up to the next bound's maintenance release. The last
    bound fixes everything after it. None when the text isn't a plain range this can read."""
    text = text.strip()
    if text in ("", "None"):
        return False
    if text == "All" or re.fullmatch(r"\d+\.\d+\.\*", text):
        return True
    bounds = _bounds(text)
    if not bounds:
        return None
    bounds.sort(key=lambda b: b[1])
    last = len(bounds) - 1
    for i, (op, b) in enumerate(bounds):
        hotfix = b[3] > 0
        # '<= 10.2.3' covers all of 10.2.3's hotfixes; '< b' and '<= b-hN' are exact.
        past = (v >= b) if op == "<" else (v > b if hotfix else v[:3] > b[:3])
        if not past:
            continue
        if i == last:
            return False
        if hotfix and v[:3] == b[:3]:
            return False
        if not hotfix and v[:3] < bounds[i + 1][1][:3]:
            return False
    return True


def match(advisory: dict, version: str) -> dict | None:
    """{"fix": "Upgrade to …"} when `version` (e.g. '11.1.4-h7') is affected, else None."""
    v = parse_version(version)
    if v is None:
        return None
    train = f"PAN-OS {v[0]}.{v[1]}"
    listed = advisory.get("affected_list") or []
    idx = next((i for i, name in enumerate(advisory.get("version") or []) if name.strip() == train), None)
    if listed and any(x == train or x.startswith(train + ".") for x in listed):
        affected = f"PAN-OS {version.strip()}" in listed
    elif idx is not None and idx < len(advisory.get("affected") or []):
        affected = bool(_range_affected(advisory["affected"][idx], v))
    else:
        affected = False
    if not affected:
        return None
    return {"fix": _fix_hint(advisory, idx, v)}


def _fix_hint(advisory: dict, idx: int | None, v: tuple) -> str:
    fixed = (advisory.get("fixed") or [])
    if idx is not None and idx < len(fixed):
        candidates = []
        for part in fixed[idx].split(","):
            m = re.fullmatch(r">=?\s*(\d+\.\d+\.\d+(?:-h\d+)?)", part.strip())
            if m and (pv := parse_version(m[1])) and pv > v:
                candidates.append((pv, m[1]))
        if candidates:
            return f"Upgrade to PAN-OS {min(candidates)[1]} or later"
    return "Upgrade to a fixed PAN-OS release"


def affecting(advisories: list[dict], version: str) -> list[dict]:
    out = []
    for a in advisories:
        hit = match(a, version)
        if hit:
            out.append({**a, **hit, "url": ADVISORY_URL.format(id=a["id"])})
    return out


def recommended_upgrade(advisories: list[dict], version: str) -> str | None:
    """The earliest build in the installed release (e.g. 11.1) that fixes this version's issues and that
    no critical or high advisory affects. Candidates are the fixed builds the advisories name."""
    v = parse_version(version)
    if v is None:
        return None
    train = f"PAN-OS {v[0]}.{v[1]}"
    # Only a release Palo Alto still publishes fixes for: an end-of-life release drops out of new
    # advisories, so "nothing affects it" would be wrong there.
    latest = max((a.get("date") or "" for a in advisories), default="")
    recent = [a for a in advisories if (a.get("date") or "")[:4] >= str(int(latest[:4] or 0) - 1)]
    if not any(name.strip() == train for a in recent for name in a.get("version") or []):
        return None
    candidates: dict[tuple, str] = {}
    for a in advisories:
        for name, fixed in zip(a.get("version") or [], a.get("fixed") or []):
            if name.strip() != train:
                continue
            for part in fixed.split(","):
                m = re.fullmatch(r">=?\s*(\d+\.\d+\.\d+(?:-h\d+)?)", part.strip())
                if m and (pv := parse_version(m[1])) and pv > v and pv[:2] == v[:2]:
                    candidates[pv] = m[1]
    for pv in sorted(candidates):
        if not any(a["severity"] in ("CRITICAL", "HIGH") for a in affecting(advisories, candidates[pv])):
            return candidates[pv]
    return None


def report(data: dict) -> dict:
    """What the assessment page shows: feed status, the installed version and every advisory affecting it."""
    info = data.get("system_info") or {}
    version = info.get("sw_version") if info.get("available") else None
    base = status()
    if not version or parse_version(version) is None:
        return {**base, "version": None, "matches": [], "recommended": None,
                "reason": "Matching advisories needs the exact PAN-OS version and hotfix, which comes from a tech "
                          "support file or a live connection, not a config export."}
    feed = _state["advisories"] if base["status"] == "ok" else None
    if not feed:
        return {**base, "version": version, "matches": [], "recommended": None}
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "NONE": 5}
    matches = sorted(affecting(feed, version), key=lambda a: (order.get(a["severity"], 9), -(a.get("score") or 0)))
    return {**base, "version": version, "recommended": recommended_upgrade(feed, version) if matches else None,
            "matches": [{k: m.get(k) for k in ("id", "title", "severity", "score", "date", "fix", "url")}
                        for m in matches]}

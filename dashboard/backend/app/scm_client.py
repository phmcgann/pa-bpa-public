"""Client for Palo Alto Strata Cloud Manager's BPA (Posture Management API).

Flow (pan.dev, openapi-specs/scm/config/posture-management/checks):
  1. POST /posture/checks/v1/reports/config-file-upload -> task_id + signed upload URL
  2. PUT the gzipped config XML to the signed URL
  3. GET  /posture/checks/v1/reports/{task_id}/bpa-result until COMPLETED/FAILED
  4. GET  the result's signed `custom_check_url` -> per-object check results (JSON)

Configuration (environment):
  SCM_CLIENT_ID / SCM_CLIENT_SECRET  service account; used for the OAuth2 client-credentials
                                     grant. If unset, requests go out without an Authorization
                                     header — for hosts whose egress proxy injects the token.
  SCM_TSG_ID                         tenant service group; token scope and x-tenant-id header.
  SCM_API_BASE                       default https://api.strata.paloaltonetworks.com

The service account needs a role that can run BPA uploads — Network Administrator plus
Security Administrator worked when this was written; View Only Administrator does not.
The config is uploaded with delete_after_processing=true.
"""
from __future__ import annotations

import gzip
import os
import time

import httpx

TOKEN_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
UPLOAD_PATH = "/posture/checks/v1/reports/config-file-upload"
RESULT_PATH = "/posture/checks/v1/reports/{task_id}/bpa-result"


class ScmError(Exception):
    def __init__(self, message: str, task_id: str | None = None) -> None:
        super().__init__(message)
        # Palo Alto support needs the task ID to look up a failed BPA run.
        self.task_id = task_id


def configured() -> bool:
    """True when this backend has what it needs to call SCM on its own, or has been told an
    egress proxy supplies the credential (SCM_AUTH=proxy)."""
    has_creds = bool(os.environ.get("SCM_CLIENT_ID") and os.environ.get("SCM_CLIENT_SECRET"))
    return has_creds or os.environ.get("SCM_AUTH") == "proxy"


def _api_base() -> str:
    return os.environ.get("SCM_API_BASE", "https://api.strata.paloaltonetworks.com").rstrip("/")


def _headers(client: httpx.Client) -> dict:
    headers = {"Accept": "application/json"}
    tsg = os.environ.get("SCM_TSG_ID")
    if tsg:
        headers["x-tenant-id"] = tsg
    cid, secret = os.environ.get("SCM_CLIENT_ID"), os.environ.get("SCM_CLIENT_SECRET")
    if cid and secret:
        if not tsg:
            raise ScmError("SCM_TSG_ID must be set alongside SCM_CLIENT_ID/SCM_CLIENT_SECRET")
        resp = client.post(TOKEN_URL, auth=(cid, secret),
                           data={"grant_type": "client_credentials", "scope": f"tsg_id:{tsg}"})
        _raise_for(resp, "get an access token")
        headers["Authorization"] = f"Bearer {resp.json()['access_token']}"
    return headers


def _raise_for(resp: httpx.Response, action: str) -> None:
    if resp.status_code < 400:
        return
    hint = ""
    if resp.status_code in (401, 403):
        hint = (" — check the service account's role (it needs BPA upload rights, e.g. Network + "
                "Security Administrator) and the tenant ID")
    raise ScmError(f"SCM refused to {action} (HTTP {resp.status_code}){hint}: {resp.text[:300]}")


def run_bpa(config_xml: bytes, *, poll_seconds: float = 5, timeout_seconds: float = 300,
            client: httpx.Client | None = None) -> dict:
    """Upload a PAN-OS config to SCM's BPA and return the raw result JSON."""
    own = client is None
    client = client or httpx.Client(timeout=60)
    try:
        headers = _headers(client)
        base = _api_base()
        resp = client.post(base + UPLOAD_PATH, headers=headers, json={"delete_after_processing": True})
        _raise_for(resp, "start a BPA upload")
        task = resp.json()
        task_id, upload_url = task["task_id"], task["upload_url"]

        put = client.put(upload_url, content=gzip.compress(config_xml),
                         headers={"Content-Type": "text/plain", "Content-Encoding": "gzip"})
        _raise_for(put, "accept the config upload")

        deadline = time.monotonic() + timeout_seconds
        while True:
            st = client.get(base + RESULT_PATH.format(task_id=task_id), headers=headers)
            _raise_for(st, "report BPA status")
            status = st.json()
            if status.get("status") == "COMPLETED":
                break
            if status.get("status") == "FAILED":
                raise ScmError(f"SCM BPA failed: {status.get('message')} (SCM task {task_id})", task_id)
            if time.monotonic() > deadline:
                raise ScmError(f"SCM BPA didn't finish in time; try again later (SCM task {task_id})", task_id)
            time.sleep(poll_seconds)

        url = (status.get("result") or {}).get("custom_check_url") or (status.get("result") or {}).get("report_url")
        if not url:
            raise ScmError("SCM BPA completed but returned no result URL")
        res = client.get(url)
        _raise_for(res, "return the BPA result")
        out = res.json()
        out["_task_id"] = task_id
        return out
    finally:
        if own:
            client.close()


def extract_results(result: dict) -> list[dict]:
    """Flatten SCM's per-object result tree into one row per (check, object)."""
    rows = []
    for section, types in (result.get("best_practices") or {}).items():
        for object_type, objects in (types or {}).items():
            for obj in objects or []:
                cfg = obj.get("configuration") or {}
                name = cfg.get("name") or cfg.get("uuid") or ""
                location = cfg.get("location") or cfg.get("container") or ""
                for w in obj.get("warnings") or []:
                    if "check_id" not in w:
                        continue
                    rows.append({
                        "check_id": int(w["check_id"]),
                        "section": section,
                        "object_type": object_type,
                        "object_name": str(name),
                        "location": str(location),
                        "passed": bool(w.get("check_passed")),
                        "excluded": bool(w.get("check_excluded") or w.get("user_excluded")),
                        "failed_fields": w.get("failed_fields") or None,
                        # Kept so checks missing from the bundled catalogue still render.
                        "check_name": w.get("check_name"),
                        "check_type": w.get("check_type"),
                        "check_message": w.get("check_message"),
                    })
    return rows

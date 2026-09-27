"""Download Strata Cloud Manager's posture check catalogue, so its checks can be compared
with this dashboard's own rules.

Only the catalogue is fetched: check names, severities, descriptions, rationale and
recommendations (GET /posture/checks/v1/all-checks), plus the list of compliance frameworks
(GET /posture/compliance-frameworks/v1/definitions). That's Palo Alto's generic content, not
any firewall's configuration or results. Nothing is uploaded, created or changed.

Needs an SCM service account (Identity & Access > Service Accounts) with read access to
posture, and your tenant service group (TSG) ID. Standard library only, so it runs anywhere
Python 3.9+ does:

    set SCM_CLIENT_ID=...            (PowerShell: $env:SCM_CLIENT_ID="...")
    set SCM_TSG_ID=...
    py scripts\\fetch_scm_checks.py -o scm_checks.json

The client secret is read from SCM_CLIENT_SECRET, or prompted for (not echoed) if unset.
The output file holds no credentials or tokens.
"""
import argparse
import base64
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

TOKEN_URL = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
API_BASE = "https://api.strata.paloaltonetworks.com"
CHECKS_PATH = "/posture/checks/v1/all-checks"
FRAMEWORKS_PATH = "/posture/compliance-frameworks/v1/definitions"
PAGE_SIZE = 100


def get_token(client_id: str, client_secret: str, tsg_id: str) -> str:
    """Client-credentials grant; tokens last 15 minutes, which is plenty for this."""
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"}).encode()
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    req = urllib.request.Request(TOKEN_URL, data=body, method="POST", headers={
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)["access_token"]


def get_json(path: str, token: str, params: Optional[dict] = None) -> dict:
    url = API_BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def fetch_all(path: str, token: str) -> list[dict]:
    """Follow limit/offset pagination until `total` items are collected."""
    items: list[dict] = []
    while True:
        page = get_json(path, token, {"limit": PAGE_SIZE, "offset": len(items)})
        data = page.get("data") or []
        items.extend(data)
        total = page.get("total")
        if not data or total is None or len(items) >= total:
            return items


def summarize(checks: list[dict]) -> str:
    by_type: dict[str, int] = {}
    by_object: dict[str, int] = {}
    for c in checks:
        key = f"{c.get('management_type', '?')}/{c.get('type', '?')}"
        by_type[key] = by_type.get(key, 0) + 1
        by_object[c.get("object_type", "?")] = by_object.get(c.get("object_type", "?"), 0) + 1
    lines = [f"{len(checks)} posture checks"]
    lines += [f"  {k}: {v}" for k, v in sorted(by_type.items())]
    lines.append("By object type:")
    lines += [f"  {k}: {v}" for k, v in sorted(by_object.items(), key=lambda kv: -kv[1])]
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-o", "--output", default="scm_checks.json", help="where to write the catalogue (JSON)")
    args = ap.parse_args(argv)

    client_id = os.environ.get("SCM_CLIENT_ID")
    tsg_id = os.environ.get("SCM_TSG_ID")
    if not client_id or not tsg_id:
        print("Set SCM_CLIENT_ID and SCM_TSG_ID first (see the top of this script).", file=sys.stderr)
        return 2
    client_secret = os.environ.get("SCM_CLIENT_SECRET") or getpass.getpass("SCM client secret: ")

    try:
        token = get_token(client_id, client_secret, tsg_id)
        checks = fetch_all(CHECKS_PATH, token)
        try:
            frameworks = fetch_all(FRAMEWORKS_PATH, token)
        except urllib.error.HTTPError as e:
            # Compliance Center may not be licensed/permitted; the checks are what matter.
            print(f"Compliance frameworks not retrieved (HTTP {e.code}); continuing without them.", file=sys.stderr)
            frameworks = []
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        print(f"HTTP {e.code} from {e.url}\n{detail}", file=sys.stderr)
        if e.code in (401, 403):
            print("Check the service account's role includes posture/read access, and the TSG ID.", file=sys.stderr)
        return 1

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"checks": checks, "compliance_frameworks": frameworks}, f, indent=2)
    print(summarize(checks))
    print(f"{len(frameworks)} compliance frameworks")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

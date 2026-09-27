# PA BPA Dashboard

Developer notes: running the backend and frontend from source, and the tests.

**Just want to use it?** Follow [`docs/INSTALL.md`](../docs/INSTALL.md) instead: one command
installs a released version on Windows or macOS, with no development tools needed.

## Running it from source

**Backend** (FastAPI, SQLite):

```bash
cd backend
python3 -m venv venv          # first time only
./venv/bin/pip install -r requirements.txt   # first time only
./venv/bin/uvicorn app.main:app --reload
```

Runs on `http://127.0.0.1:8000`. Data persists to `backend/app.db` (SQLite, gitignored-worthy — delete it to reset).

**Frontend** (Vite + React + TS):

```bash
cd frontend
npm install       # first time only
npm run dev
```

Runs on `http://localhost:5173`.

**Tests:**

```bash
cd backend
./venv/bin/pytest
```

**Checking the parser against a real tech support file** (without sharing it):

```bash
cd backend
python3 scripts/verify_tsf.py /path/to/techsupport.tgz -o tsf_report.txt
```

Windows (PowerShell or cmd):

```powershell
cd backend
py scripts\verify_tsf.py C:\path\to\techsupport.tgz -o tsf_report.txt
```

Standard library only — any Python 3.9+, no venv or `pip install` needed. Use
`-o` rather than `>` so the file is written as UTF-8 (PowerShell's `>`
re-encodes it).

Prints what the decryption, zone protection, interface management, log
forwarding, and Inline Cloud Analysis checks actually find in the file —
lookup-path match counts, the tag names present, parsed values, license
names, and finding counts. Names are replaced with placeholders and free-text
values hidden, so the report is safe to share; add `--show-names` for your
own use. Read it before sharing either way.

**Core rules and Palo Alto SCM BPA.** Every assessment runs the **core rules** —
the dashboard's own checks, shown under the brand's name for them (Harborlight BPA
by default), each labelled with what it's based on (CIS benchmark,
Palo Alto's public documentation, or custom) and with the matching Palo Alto
Strata Cloud Manager check numbers where Palo Alto checks the same setting.

Optionally, an assessment can also be sent to **Palo Alto's own BPA** in Strata
Cloud Manager ("Run Palo Alto SCM BPA" on the dashboard). Its results appear in
Palo Alto's wording, tagged `PAN SCM #<check>`; a check a core rule already
flagged is listed but not scored twice, and Settings can leave SCM findings out
of the score entirely. This sends the configuration to Palo Alto (deleted after
processing), so it only runs when you click it. To enable it, set these for the
backend (or in `.env` for Docker):

```bash
export SCM_CLIENT_ID=...       # service account client ID
export SCM_CLIENT_SECRET=...   # service account secret
export SCM_TSG_ID=...          # tenant service group ID
```

The service account needs the Network Administrator and Security Administrator
roles (View Only Administrator can't run BPA uploads). Assessments uploaded
before this feature don't have their config stored — re-upload to run SCM on them.
The catalogue of Palo Alto's checks is in `backend/app/rules/scm_catalog.json`.

**Known vulnerabilities.** The backend downloads Palo Alto Networks' public
security advisories for PAN-OS (security.paloaltonetworks.com) in the background
at startup and every 12 hours, caching them on disk. Each assessment with an
exact PAN-OS version (a tech support file or live connection — a config export
doesn't carry the hotfix) is matched against them: critical and high advisories
are findings of their own, medium ones one rolled-up finding, and every match is
listed under *Known vulnerabilities* on the Overview. Only the feed is
downloaded; nothing about the firewall is sent. Set `PAN_ADVISORY_FEED=off` to
turn it off (`PAN_ADVISORY_CACHE` sets the cache file path).

**CLI remediation commands.** Findings whose fix is mechanical (attach a
profile group, turn on logging, disable a redundant rule, move a shadowed block
rule, delete unused objects, device settings, and security profile settings such as
decoder actions, severity-rule actions, DNS sinkholing, inline cloud analysis, URL
category blocking and WildFire file types) have a **CLI** button, and each
remediation work item a **Copy CLI** button for all its commands at once. The
commands follow the config's own XML paths (`app/rules/cli.py`), start with
`configure` and never commit: review with `show | compare`, then commit
yourself. Values the config can't supply (which profile group, which Log
Forwarding profile) are picked from objects that exist on the firewall, or left
as a `<PLACEHOLDER>`. Panorama exports get rule commands only. Verify the output
on a lab firewall before first use.

**Checking a real tech support file without sharing it.** `app/tsf_probe.py`
prints how well the parser understands a tech support file: which files and
command outputs it has (including whether it carries rule hit counts), which
XML fields certificates have, how many advisories, shadowed rules and unused
objects were found, and findings by severity. It prints structure and counts
only, never object, rule, user or zone names, addresses or secrets, and masks
the hostname, serial and any IP address. Read the output before sharing it.

```bash
docker compose cp ~/Downloads/client-ts.tgz backend:/tmp/client-ts.tgz
docker compose exec backend python -m app.tsf_probe /tmp/client-ts.tgz
docker compose exec backend rm /tmp/client-ts.tgz
```

**Docker (Postgres-backed, HTTPS + Basic Auth via Caddy, all four services):**

```bash
cp .env.example .env   # first time only — edit with real values, see DEPLOYMENT.md
docker compose up --build
```

App on `https://localhost/` (self-signed cert for local testing — browsers will warn, that's expected). Only Caddy is exposed to the host; Postgres, the backend, and the frontend's nginx are only reachable from other containers.

Deploying this to another machine (including via Arcane), or need to generate real Basic Auth credentials? See [DEPLOYMENT.md](DEPLOYMENT.md).

## Current scope (Phase 1: file upload)

Upload a full PAN-OS running-config export (Device → Setup → Operations →
Export named configuration snapshot). Everything reachable from that file is
analyzed: admin accounts, zones, security rulebase, threat/WildFire profile
objects, syslog server profiles, and management hardening settings
(`deviceconfig/system`).

**Not available from a config file** — these come from PAN-OS `op` commands,
not the config tree, so they render as "unavailable" until Phase 2:
- System runtime info (PAN-OS version, serial, uptime, content versions)
- License status/expiry
- Live HA sync state

## Phase 2 (not yet wired up)

`app/live_client.py` already has `get_api_key()` / `api_call()` ported from
the original `collect_data.py`, ready to authenticate against a live firewall
and fetch the three op-command responses above. Wiring it in means:

1. Implement `POST /api/live/connect` (currently a 501 stub in `app/main.py`)
   to call `live_client.get_api_key()`, then fetch the config tree + the three
   op-command responses.
2. Pass those into `parser.parse_system_info(config_root, op_root=...)`,
   `parser.parse_licenses(op_root=...)`, `parser.parse_ha(op_root=...)` — they
   already accept an optional live root and will flip `"available": True`.
3. Store the resulting `Assessment` with `source="live"`.

No other code changes needed — the rules engine and every dashboard page
already handle the resulting data shape identically to file-upload mode.

## Rule sourcing

Every check in `app/rules/definitions.py` is tagged `source_type: "cis"` (with
a verified CIS Palo Alto Firewall Benchmark control number) or `"custom"` (a
house heuristic with no external standard). Only add a `"cis"` tag with a
control number you've actually confirmed — see the module docstring.

## Settings model

- **Rule enable/disable + thresholds** (Settings page → Rules): global,
  applies to every assessment immediately, persisted in the `rulesetting`
  table.
- **Per-finding dismiss** (assessment view → Dismiss button): per-assessment,
  persisted in `dismissedfinding`, excluded from the risk score but not
  deleted — restorable.
- **Section visibility** (Settings page → Dashboard sections): purely a
  display preference, stored in this browser's `localStorage`, doesn't touch
  the backend or the analysis.

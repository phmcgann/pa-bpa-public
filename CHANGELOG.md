# Changelog

All notable changes to the PA BPA Dashboard. Versions follow [Semantic Versioning](https://semver.org/):
**major** for changes you must act on when upgrading, **minor** for new features and checks, **patch** for fixes.

## [1.0.5] - 2026-10-18

### Checks
- Decryption profiles that don't set the No Decryption certificate checks (block sessions with expired certificates, and with untrusted issuers) are now flagged: PAN-OS leaves both off unless they're set. Before, a profile that didn't mention them wasn't judged.
- Minimum password complexity also needs at least one uppercase letter, lowercase letter, number and special character, as Palo Alto SCM checks, not only a minimum length. The Copy CLI commands set all four.
- Interface management profiles that allow HTTP or Telnet are flagged even when no interface uses them yet, as Palo Alto SCM does.
- New: File Blocking profiles that block something but not the file types commonly used by malware (7z, bat, chm, class, cpl, dll, hlp, hta, jar, ocx, pif, scr, torrent, vbe, wsf), or that have no rule alerting on all other file types.
- New: Strip X-Forwarded-For Header turned off. A rule for using the X-Forwarded-For header in User-ID is also available, off by default, since it only matters behind an upstream proxy.
- Three checks Palo Alto added to its SCM BPA since September (WildFire real-time hold in Antivirus profiles, and the two X-Forwarded-For settings) are now in the bundled SCM check list and matched to core rules. Re-analyze an assessment to apply the parsing changes.

## [1.0.4] - 2026-10-16

### Maintenance
- Updated the backend to Python 3.14 and its packages (FastAPI, SQLModel, Uvicorn and others) to their current versions, and the frontend build to Node 24 (long-term support) and TypeScript 7, plus current versions of the frontend's other packages. Nothing changes in how the dashboard works or in stored data.
- Release images are built with the current versions of Docker's build tools.

### Fixes
- The sidebar's sign-out button now has a label and its own row with the theme switch, so the sidebar footer no longer runs past the sidebar's edge when a website link is shown.

## [1.0.3] - 2026-10-14

### Checks
- The PAN-OS end-of-life check now uses Palo Alto's published end-of-life dates. Before, it only flagged PAN-OS 9.x and older, so firewalls on 10.1, 10.2 or 11.0 passed. A release past end-of-life (standard and any extended support over) is **Critical**; one in extended support, or about to reach end-of-life with none to follow, is a **Warning**; one whose standard support is about to end is **Low**. How far ahead to warn is a setting (180 days by default).
- The check also works for config exports, using the PAN-OS version stamped in the file (the System card shows it as "from config"). Re-analyze an existing assessment to pick it up.

### Signing in
- The dashboard has its own sign-in page instead of the browser's pop-up box. It uses the same username and password as before, so nothing needs to change in `.env`. You stay signed in for 12 hours, and a **sign-out** button sits at the bottom of the sidebar. After five wrong passwords in a row, sign-in pauses for up to 15 minutes. Run the install command again to update as usual: it also brings the new `Caddyfile` and `docker-compose.yml` this needs.

### Keeping up with Palo Alto
- **Settings → Palo Alto content** shows how current everything the checks know about Palo Alto is: the end-of-life dates, the SCM check list, the predefined profiles and the built-in IP lists (bundled with each release, marked *Review due* after six months), and the live security-advisory download.
- After a Palo Alto SCM run, checks Palo Alto added since this release's SCM check list was taken are labelled **New from Palo Alto** in the coverage view, and marked in the copied gap list.

## [1.0.2] - 2026-09-29

### Remediation
- Panorama-managed firewalls assessed from their own export or tech support file no longer get Copy CLI commands, which would have been typed at the firewall for rules and settings Panorama pushes. The Remediation plan and Findings tabs explain why and point to Panorama instead. Assessments from a Panorama export still get commands for their device group.
- Panorama exports and Panorama's own tech support file are now assessed per firewall: pick a managed firewall and it's resolved the way Panorama builds its configuration, from Shared and every device group above it (pre-rules top-down, post-rules bottom-up, a lower group's object winning) plus the template stack it's assigned (first template wins). Before, only one device group and its reference templates were used. CLI commands change each rule or profile in the device group it comes from.
- Panorama's own tech support file now goes to that picker, like a Panorama export. Before, it was assessed as a single device, mixing every device group, and labelled a Panorama-managed firewall. Assessments already made that way say so and ask for the file to be uploaded again.

### Installing
- The Windows installer can start Docker Desktop when it was installed per user (Docker's current default), not only for all users.
- The install guide matches Docker Desktop's current installer, which offers a per-user installation, and now has screenshots for every Windows step.

### Releases
- Release images build faster and more reliably: the frontend is compiled once instead of under emulation for each processor type.

## [1.0.1] - 2026-09-29

### Checks
- Closer to Palo Alto SCM's results, based on a real SCM run:
  - Every decryption and Log Forwarding profile is graded whether or not a rule uses it, as the documentation already said.
  - New check: SSL Forward Proxy decryption profiles that let sessions with unknown certificate status, check timeouts, unsupported versions or ciphers, or resource failures through (SCM check 55).
  - A single NTP server with no secondary is flagged.
  - A GlobalProtect SSL/TLS service profile that caps the maximum version below "Max" is flagged.
  - PAN-OS defaults are applied when a setting is missing: "Log container page only" is on, and a RADIUS profile with no protocol uses CHAP.
  - RADIUS, LDAP and TACACS+ server profiles defined in a vsys are checked, not just shared ones.
  - A Log Forwarding profile that only sends email, SNMP traps or HTTP is flagged: those don't store the logs.
- The SCM coverage view marks results about unused PAN-OS built-in profiles, and HA settings on a firewall without HA, and disabled PBF rules, as not applicable instead of listing them as gaps.
- Where a core rule deliberately differs from SCM (a RADIUS profile using PEAP, GlobalProtect settings that only matter with an always-on connect method or both gateway types), the coverage view says so and why, instead of calling it a gap.

## [1.0.0] - 2026-09-26

First public release.

### Assessments
- Upload a PAN-OS configuration export, a tech support file, or a Panorama export (assessed per device group); several files at once.
- 189 core checks across security policy, security profiles, decryption, management access, logging, GlobalProtect, HA, VPN, DoS and zone protection, certificates, NAT, software and licensing. 132 are mapped to the matching Palo Alto Strata Cloud Manager checks.
- PAN-OS predefined profiles are graded when a rule uses them; known PAN-OS security advisories are matched to the running version.
- Optional Palo Alto SCM BPA run on the stored configuration, shown alongside the core findings without double counting, plus a coverage view of any gaps.

### Dashboard
- Risk score and severity tiles, executive summary, findings by category, and a searchable findings list with dismiss/restore.
- Remediation plan grouping findings into pieces of work, with copy-ready PAN-OS CLI commands where a fix is mechanical.
- Rulebase analysis (shadowed rules, unused and duplicate objects), NAT review, threat-intelligence blocking coverage.
- Notes on findings, work items and rules, numbered as superscript references with a Notes appendix; notes carry over to the next run.
- Compare any two runs, and "changes since last run" for each firewall.
- Re-analyze an assessment from its stored file without uploading it again.
- Branded print/PDF report with cover page, numbered sections and appendix; filtered prints are labelled.
- Ships with the fictional Harborlight Consulting brand; your own logo, colours and name can be built in as a brand pack.

### Installing
- One-command installers for Windows (PowerShell) and macOS (Terminal) using prebuilt images for Intel and Apple Silicon.

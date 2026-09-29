from __future__ import annotations

import gzip
import re
import os
from datetime import datetime
from typing import Optional
import tarfile
import xml.etree.ElementTree as ET

from fastapi import Depends, FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlmodel import Session, select

from . import advisories, panorama_parser, parser, remediation, scm_client, tsf_parser
from .db import create_db_and_tables, get_session
from .models import (Assessment, AssessmentConfig, AssessmentNote, DismissedFinding, PanoramaUpload, RuleSetting, ScmBpaRun,
                     ScmSettings, ScoringSettings)
from .object_usage import find_duplicates
from .rules import builtin_profiles, cli, mgmt_exposure, rulebase, scm_catalog, scm_coverage, scm_findings, threat_intel
from .rules.checks import inline_cloud_analysis_gate
from .rules.definitions import RULES, RULES_BY_ID
from .rules.engine import DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS, run_rules, summarize
from .schemas import (NOTE_KINDS, AssessmentUpdateRequest, DismissRequest, FromPanoramaRequest, LiveConnectRequest,
                      NoteCreateRequest, NoteUpdateRequest, RuleUpdateRequest, ScmSettingsUpdateRequest,
                      ScoringUpdateRequest)

VALID_SEVERITIES = {"CRITICAL", "WARNING", "LOW", "INFORMATIONAL"}

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")

app = FastAPI(title="PA BPA Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    advisories.ensure_fresh()


@app.get("/health")
def health(session: Session = Depends(get_session)):
    session.exec(text("SELECT 1"))
    return {"status": "ok", "version": os.environ.get("PA_BPA_VERSION", "dev")}


def get_rule_settings(session: Session) -> dict[str, dict]:
    settings = {
        row.rule_id: {
            "enabled": row.enabled,
            "threshold_overrides": row.threshold_overrides,
            "severity_override": row.severity_override,
        }
        for row in session.exec(select(RuleSetting))
    }
    return settings


def get_scoring_settings(session: Session) -> ScoringSettings:
    settings = session.get(ScoringSettings, 1)
    if settings is None:
        settings = ScoringSettings(id=1)
        session.add(settings)
        session.commit()
        session.refresh(settings)
    return settings


def scoring_weights_and_thresholds(settings: ScoringSettings) -> tuple[dict, dict]:
    weights = {
        "CRITICAL": settings.weight_critical, "WARNING": settings.weight_warning,
        "LOW": settings.weight_low, "INFORMATIONAL": settings.weight_informational,
    }
    thresholds = {
        "informational_max": settings.informational_max, "low_max": settings.low_max,
        "warning_max": settings.warning_max,
    }
    return weights, thresholds


def get_scm_settings(session: Session) -> ScmSettings:
    settings = session.get(ScmSettings, 1)
    if settings is None:
        settings = ScmSettings(id=1)
        session.add(settings)
        session.commit()
        session.refresh(settings)
    return settings


def compute_findings(assessment: Assessment, session: Session) -> tuple[list[dict], dict]:
    rule_settings = get_rule_settings(session)
    # Built-in profiles the config uses are graded like its own (see builtin_profiles).
    data, builtins = builtin_profiles.with_builtins(assessment.parsed_data)
    # The advisory feed isn't part of the stored config; checks read the current cached copy.
    findings = run_rules({**data, "_advisories": advisories.snapshot()}, rule_settings)
    builtin_profiles.annotate(findings, builtins)
    scm_run = session.get(ScmBpaRun, assessment.id)
    if scm_run is not None and scm_run.status == "completed":
        findings += scm_findings.build(scm_run.results or [], data, findings, rule_settings)
    include_scm = get_scm_settings(session).include_in_score

    dismissed_keys = {
        row.finding_key
        for row in session.exec(
            select(DismissedFinding).where(DismissedFinding.assessment_id == assessment.id)
        )
    }
    for f in findings:
        f["dismissed"] = f["finding_key"] in dismissed_keys

    weights, thresholds = scoring_weights_and_thresholds(get_scoring_settings(session))
    for f in findings:
        # Why a finding doesn't count toward the score, beyond dismissal / a disabled rule.
        f["not_scored_reason"] = None
        if f.get("program") == "scm":
            if f.get("duplicate_of"):
                f["not_scored_reason"] = "duplicate"
            elif not include_scm:
                f["not_scored_reason"] = "scm_excluded"
    active = [f for f in findings
              if not f["dismissed"] and not f["rule_disabled"] and f["not_scored_reason"] is None]
    summary = summarize(active, weights, thresholds)
    return findings, summary


# ── Assessments ──────────────────────────────────────────────────────────

def serial_from_data(data: dict) -> str | None:
    serial = (data.get("system_info") or {}).get("serial")
    return serial if serial and serial != "N/A" else None


def effective_serial(assessment: Assessment) -> str | None:
    """Stored serial, falling back to the parsed data for assessments saved before the column."""
    return assessment.serial or serial_from_data(assessment.parsed_data)


# Hostnames that don't identify a firewall: unset, placeholders, and factory defaults (the model name).
_GENERIC_HOSTNAME = re.compile(r"^(|n/a|localhost(\.localdomain)?|pa-vm|pa-\d+[a-z]*)$", re.IGNORECASE)


def inherit_client(session: Session, assessment: Assessment) -> None:
    """A new upload of a firewall that already has a client keeps that client.

    Matched by serial. A plain config export has no serial, so it falls back to the hostname —
    only when the hostname is specific and every earlier run with it agrees on one client — and
    then also takes that firewall's serial if the earlier runs agree on one, so the runs group
    together. An upload whose serial matches nothing is a new firewall: no hostname guessing.
    """
    if assessment.client_name:
        return
    others = session.exec(
        select(Assessment)
        .where(Assessment.id != assessment.id, Assessment.client_name.is_not(None))
        .order_by(Assessment.uploaded_at.desc())
    ).all()
    serial = effective_serial(assessment)
    if serial:
        match = next((o for o in others if effective_serial(o) == serial), None)
        if match is None:
            return
        assessment.client_name = match.client_name
    else:
        host = (assessment.hostname or "").strip()
        if _GENERIC_HOSTNAME.match(host):
            return
        same = [o for o in others if (o.hostname or "").strip().lower() == host.lower()]
        clients = {o.client_name for o in same}
        if len(clients) != 1:
            return
        assessment.client_name = clients.pop()
        serials = {effective_serial(o) for o in same} - {None}
        if len(serials) == 1:
            assessment.serial = serials.pop()
    session.add(assessment)
    session.commit()
    session.refresh(assessment)


def model_from_data(data: dict) -> str | None:
    model = (data.get("system_info") or {}).get("model")
    return model if model and model != "N/A" else None


def assessment_identity(a: Assessment) -> dict:
    return {"client_name": a.client_name, "serial": effective_serial(a), "model": model_from_data(a.parsed_data)}


def store_config(session: Session, assessment: Assessment, config_xml: bytes, platform: str = "ngfw",
                 cli_text: Optional[str] = None) -> None:
    session.add(AssessmentConfig(assessment_id=assessment.id, platform=platform,
                                 config_gz=gzip.compress(config_xml),
                                 cli_text_gz=gzip.compress(cli_text.encode()) if cli_text is not None else None))
    session.commit()


def stage_panorama(session: Session, filename: str, config_xml: bytes, cli_text: Optional[str] = None) -> dict:
    """Keeps a Panorama config until the user picks which firewall to assess. Panorama's tech support
    file also carries its own device list, which gives hostnames the config doesn't."""
    root = ET.fromstring(config_xml)
    serials = [d["serial"] for d in panorama_parser.list_devices(root)]
    hostnames = tsf_parser.parse_cli_managed_devices(cli_text, serials) if cli_text else {}
    devices = panorama_parser.list_devices(root, hostnames)
    staged = PanoramaUpload(filename=filename, raw_xml=config_xml, devices=devices)
    session.add(staged)
    session.commit()
    session.refresh(staged)
    return {
        "panorama_export": True,
        "upload_id": staged.id,
        "filename": staged.filename,
        "devices": devices,
        "device_groups": panorama_parser.list_device_groups(root),
    }


@app.post("/api/assessments/upload")
async def upload_assessment(file: UploadFile, session: Session = Depends(get_session)):
    raw = await file.read()

    if tsf_parser.looks_like_tsf(file.filename or "", raw):
        try:
            config_xml, cli_text = tsf_parser.extract_config_and_cli_text(raw)
            if panorama_parser.is_panorama_export(ET.fromstring(config_xml)):
                # Panorama's own tech support file: its config is a Panorama export, assessed one device
                # group at a time like one.
                return stage_panorama(session, file.filename or "techsupport.tgz", config_xml, cli_text)
            data = tsf_parser.build_assessment_data_from_parts(config_xml, cli_text)
        except (ValueError, tarfile.TarError, ET.ParseError) as e:
            raise HTTPException(status_code=400, detail=f"Could not read tech support file: {e}")

        assessment = Assessment(
            filename=file.filename or "techsupport.tgz",
            hostname=data.get("system_info", {}).get("hostname"),
            source="tsf_upload",
            parsed_data=data,
            serial=serial_from_data(data),
        )
        session.add(assessment)
        session.commit()
        session.refresh(assessment)
        store_config(session, assessment, config_xml, cli_text=cli_text)
        inherit_client(session, assessment)

        findings, summary = compute_findings(assessment, session)
        carry_over_notes(session, assessment, findings, summary)
        return {"id": assessment.id, "filename": assessment.filename, "hostname": assessment.hostname,
                **assessment_identity(assessment), "summary": summary}

    try:
        config_root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"Could not parse XML: {e}")

    rejection = parser.config_rejection(config_root)
    if rejection:
        raise HTTPException(status_code=400, detail=rejection)

    if panorama_parser.is_panorama_export(config_root):
        return stage_panorama(session, file.filename or "config.xml", raw)

    data = parser.parse_config(raw)
    assessment = Assessment(
        filename=file.filename or "config.xml",
        hostname=data.get("system_info", {}).get("hostname"),
        source="file_upload",
        parsed_data=data,
        serial=serial_from_data(data),
    )
    session.add(assessment)
    session.commit()
    session.refresh(assessment)
    store_config(session, assessment, raw)
    inherit_client(session, assessment)

    findings, summary = compute_findings(assessment, session)
    carry_over_notes(session, assessment, findings, summary)
    return {"id": assessment.id, "filename": assessment.filename, "hostname": assessment.hostname,
            **assessment_identity(assessment), "summary": summary}


@app.post("/api/assessments/from-panorama")
def create_from_panorama(body: FromPanoramaRequest, session: Session = Depends(get_session)):
    staged = session.get(PanoramaUpload, body.upload_id)
    if staged is None:
        raise HTTPException(status_code=404, detail="Panorama upload not found or already used")

    config_root = ET.fromstring(staged.raw_xml)
    try:
        if body.serial:
            known = next((d for d in staged.devices or [] if d.get("serial") == body.serial), {})
            data = panorama_parser.build_assessment_data_for_device(config_root, body.serial, known.get("hostname"))
        elif body.device_group:
            data = panorama_parser.build_assessment_data(config_root, body.device_group)
        else:
            raise ValueError("Choose a firewall (or a device group) to assess")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    assessment = Assessment(
        filename=staged.filename,
        hostname=data["system_info"]["hostname"],
        source="panorama_export",
        parsed_data=data,
        serial=serial_from_data(data),
    )
    session.add(assessment)
    raw_panorama = staged.raw_xml
    session.delete(staged)
    session.commit()
    session.refresh(assessment)
    store_config(session, assessment, raw_panorama, platform="panorama")
    inherit_client(session, assessment)

    findings, summary = compute_findings(assessment, session)
    carry_over_notes(session, assessment, findings, summary)
    return {"id": assessment.id, "filename": assessment.filename, "hostname": assessment.hostname,
            **assessment_identity(assessment), "summary": summary}


@app.get("/api/assessments")
def list_assessments(session: Session = Depends(get_session)):
    out = []
    for a in session.exec(select(Assessment).order_by(Assessment.uploaded_at.desc())):
        _, summary = compute_findings(a, session)
        out.append({
            "id": a.id, "filename": a.filename, "hostname": a.hostname,
            **assessment_identity(a),
            "source": a.source, "uploaded_at": a.uploaded_at.isoformat(),
            "summary": summary,
            "panorama_managed": a.parsed_data.get("panorama_managed", False)
                                and not parser.panorama_appliance(a.parsed_data),
        })
    return out


def previous_run(session: Session, assessment: Assessment) -> Assessment | None:
    """The same firewall's run just before this one: matched by serial when known, otherwise by
    hostname (the same grouping the Assessments list uses)."""
    serial = effective_serial(assessment)
    earlier = session.exec(
        select(Assessment)
        .where(Assessment.id != assessment.id, Assessment.uploaded_at < assessment.uploaded_at)
        .order_by(Assessment.uploaded_at.desc())
    ).all()
    for o in earlier:
        if serial and effective_serial(o) == serial:
            return o
        if not serial and not effective_serial(o) and (o.hostname or "") == (assessment.hostname or ""):
            return o
    return None


@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: int, session: Session = Depends(get_session)):
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    findings, summary = compute_findings(assessment, session)
    cli.annotate(findings, assessment.parsed_data)
    advisory_report = advisories.report(assessment.parsed_data)
    return {
        "id": assessment.id, "filename": assessment.filename, "hostname": assessment.hostname,
        **assessment_identity(assessment),
        "source": assessment.source, "uploaded_at": assessment.uploaded_at.isoformat(),
        "reanalyzed_at": assessment.reanalyzed_at.isoformat() if assessment.reanalyzed_at else None,
        "data": assessment.parsed_data,
        "findings": findings,
        "summary": summary,
        "license_gates": {"inline_cloud_analysis": inline_cloud_analysis_gate(assessment.parsed_data)},
        "mgmt_exposure": mgmt_exposure.analyze(assessment.parsed_data),
        "threat_intel": threat_intel.coverage(assessment.parsed_data),
        "advisories": advisory_report,
        "remediation": remediation.build(findings, summary["weights"], advisory_report.get("recommended")),
        "cli_unavailable": cli.unavailable_reason(assessment.parsed_data),
        "panorama_appliance": parser.panorama_appliance(assessment.parsed_data),
        "rulebase": {**rulebase.analyze(assessment.parsed_data),
                     "duplicates": find_duplicates(assessment.parsed_data.get("policy_objects") or {})},
        "scm": scm_status(assessment, session),
        "scm_coverage": scm_coverage_for(assessment, session, findings, summary),
        "notes": notes_for(session, assessment.id),
        "previous_run": (lambda p: {"id": p.id, "uploaded_at": p.uploaded_at.isoformat(), "filename": p.filename}
                         if p else None)(previous_run(session, assessment)),
    }


PANORAMA_TSF_REUPLOAD = ("this is Panorama's own tech support file. Upload it again and choose a device group "
                         "to assess that group's policy")


def reparse(assessment: Assessment, stored: AssessmentConfig) -> dict:
    """The assessment's data, parsed again from its stored source with the current parser."""
    config_xml = gzip.decompress(stored.config_gz)
    if stored.platform == "panorama":
        resolved = assessment.parsed_data.get("panorama") or {}
        if resolved.get("mode") == "device":
            return panorama_parser.build_assessment_data_for_device(
                ET.fromstring(config_xml), resolved["serial"], assessment.hostname)
        device_group = assessment.parsed_data.get("device_group") or assessment.hostname
        return panorama_parser.build_assessment_data(ET.fromstring(config_xml), device_group)
    if assessment.source != "tsf_upload":
        return parser.parse_config(config_xml)
    if panorama_parser.is_panorama_export(ET.fromstring(config_xml)):
        raise ValueError(PANORAMA_TSF_REUPLOAD)
    if stored.cli_text_gz is not None:
        return tsf_parser.build_assessment_data_from_parts(config_xml, gzip.decompress(stored.cli_text_gz).decode())
    # Uploaded before the CLI output was kept: re-parse the config, keep what the CLI output gave.
    old = assessment.parsed_data
    return {**parser.parse_config(config_xml),
            **{k: old[k] for k in ("system_info", "licenses", "ha") if k in old}}


@app.post("/api/assessments/{assessment_id}/reanalyze")
def reanalyze_assessment(assessment_id: int, session: Session = Depends(get_session)):
    """Re-parses the stored config with the current parser and checks, in place: dismissals, notes and
    the Palo Alto SCM run stay. Findings are always computed with the current rules; this also brings
    in what newer parser versions read from the config."""
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    stored = session.get(AssessmentConfig, assessment_id)
    if stored is None:
        raise HTTPException(status_code=409, detail="This assessment was uploaded before its file was kept — "
                                                    "upload the file again to re-analyze it")
    _, before = compute_findings(assessment, session)
    try:
        data = reparse(assessment, stored)
    except (ValueError, ET.ParseError) as e:
        raise HTTPException(status_code=400, detail=f"Could not re-analyze the stored file: {e}")
    assessment.parsed_data = data
    assessment.reanalyzed_at = datetime.utcnow()
    session.add(assessment)
    session.commit()
    session.refresh(assessment)
    _, after = compute_findings(assessment, session)
    return {"before": {"score": before["score"], "total": before["total"]},
            "after": {"score": after["score"], "total": after["total"]},
            "full_source": stored.platform == "panorama" or assessment.source != "tsf_upload"
                           or stored.cli_text_gz is not None}


def _counted(f: dict) -> bool:
    return not f["dismissed"] and not f["rule_disabled"] and f["not_scored_reason"] is None


# Parsed-data sections that later versions of the parser added. When one side of a comparison lacks
# a section the other has, its checks couldn't run there, and the score difference isn't a config change.
_SECTION_LABELS = {
    "decryption": "decryption", "zone_protection_profiles": "zone protection", "interface_mgmt_profiles":
    "interface management profiles", "globalprotect": "GlobalProtect", "policy_objects": "policy objects",
    "mgmt_plane": "management plane", "ha_config": "HA configuration", "vpn": "site-to-site VPN",
    "dos": "DoS protection", "session_settings": "session settings", "device_settings": "device settings",
    "misc_policy": "PBF / GRE / app override", "log_forwarding_profiles": "log forwarding profiles",
    "default_rule_logging": "default-rule logging", "identity": "authentication and User-ID",
    "certificates": "certificates", "object_usage": "unused objects", "nat_rules": "NAT policy",
}


@app.get("/api/compare")
def compare_assessments(base: int, target: int, session: Session = Depends(get_session)):
    """What changed between two assessments, and which rules account for the score difference.
    Findings are matched by finding_key; a finding counts when it's scored (not dismissed, not on a
    disabled rule, not an SCM duplicate or excluded SCM result)."""
    sides = {}
    for role, aid in (("base", base), ("target", target)):
        a = session.get(Assessment, aid)
        if a is None:
            raise HTTPException(status_code=404, detail=f"Assessment {aid} not found")
        findings, summary = compute_findings(a, session)
        run = session.get(ScmBpaRun, a.id)
        sides[role] = {"assessment": a, "findings": findings, "summary": summary,
                       "scm_run": run is not None and run.status == "completed"}
    weights = sides["target"]["summary"]["weights"]

    def points(f: dict) -> int:
        return weights[f["severity"]] if _counted(f) else 0

    by_key = {role: {f["finding_key"]: f for f in sides[role]["findings"]} for role in sides}
    new, resolved, changed = [], [], []
    for key, f in by_key["target"].items():
        old = by_key["base"].get(key)
        if old is None:
            if _counted(f):
                new.append(f)
        elif points(old) != points(f) or old["severity"] != f["severity"]:
            changed.append({"finding": f, "before": {"severity": old["severity"], "counted": _counted(old),
                                                      "dismissed": old["dismissed"]},
                            "after": {"severity": f["severity"], "counted": _counted(f), "dismissed": f["dismissed"]}})
    for key, f in by_key["base"].items():
        if key not in by_key["target"] and _counted(f):
            resolved.append(f)

    # Points by rule, so the table can say which rules moved the score.
    rules: dict[str, dict] = {}
    for role in ("base", "target"):
        for f in sides[role]["findings"]:
            r = rules.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "title": f["title"], "category": f["category"],
                                                "program": f.get("program", "core"), "base_count": 0, "target_count": 0,
                                                "base_points": 0, "target_points": 0})
            if _counted(f):
                r[f"{role}_count"] += 1
                r[f"{role}_points"] += points(f)
    by_rule = sorted((r for r in rules.values() if r["base_points"] != r["target_points"]
                      or r["base_count"] != r["target_count"]),
                     key=lambda r: (-abs(r["target_points"] - r["base_points"]), r["title"]))

    def program_points(role: str, program: str) -> int:
        return sum(points(f) for f in sides[role]["findings"] if f.get("program", "core") == program)

    notes = []
    b, t = sides["base"]["assessment"], sides["target"]["assessment"]
    if (effective_serial(b) or b.hostname) != (effective_serial(t) or t.hostname):
        notes.append({"kind": "different_firewall",
                      "text": "These are different firewalls, so differences reflect two configurations, not a change over time."})
    for role, other in (("base", "target"), ("target", "base")):
        if sides[role]["scm_run"] and not sides[other]["scm_run"]:
            pts = program_points(role, "scm")
            if pts:
                notes.append({"kind": "scm_run",
                              "text": f"Only the {'earlier' if role == 'base' else 'later'} assessment has Palo Alto SCM "
                                      f"results; they add {pts} points to its score. Run the SCM BPA on the other "
                                      "(or turn SCM scoring off) to compare like for like."})
    missing = {role: [label for key, label in _SECTION_LABELS.items()
                      if key in sides[other]["assessment"].parsed_data and key not in sides[role]["assessment"].parsed_data]
               for role, other in (("base", "target"), ("target", "base"))}
    for role, labels in missing.items():
        if labels:
            notes.append({"kind": "parser_coverage",
                          "text": f"The {'earlier' if role == 'base' else 'later'} assessment was uploaded before this "
                                  f"dashboard parsed {', '.join(labels)}, so those checks couldn't run on it. "
                                  "Re-upload its file to compare like for like."})

    def side(role: str) -> dict:
        a, s = sides[role]["assessment"], sides[role]["summary"]
        return {"id": a.id, "filename": a.filename, "hostname": a.hostname, **assessment_identity(a),
                "uploaded_at": a.uploaded_at.isoformat(), "summary": s, "scm_run": sides[role]["scm_run"],
                "points_by_program": {p: program_points(role, p) for p in ("core", "scm")}}

    sev_rank = {"CRITICAL": 0, "WARNING": 1, "LOW": 2, "INFORMATIONAL": 3}
    order = lambda f: (sev_rank.get(f["severity"], 9), f["title"])  # noqa: E731
    return {
        "base": side("base"), "target": side("target"),
        "score_delta": sides["target"]["summary"]["score"] - sides["base"]["summary"]["score"],
        "by_rule": by_rule,
        "new": sorted(new, key=order),
        "resolved": sorted(resolved, key=order),
        "changed": sorted(changed, key=lambda c: order(c["finding"])),
        "notes": notes,
    }


def scm_coverage_for(assessment: Assessment, session: Session, findings: list[dict], summary: dict) -> Optional[dict]:
    """Which failed SCM checks the core rules did and didn't catch, from the stored run (kept even if SCM
    can't be reached any more)."""
    run = session.get(ScmBpaRun, assessment.id)
    if run is None or run.status != "completed":
        return None
    coverage = scm_coverage.build(findings, run.results or [], get_rule_settings(session), summary["weights"],
                                  assessment.parsed_data)
    return {**coverage, "text": scm_coverage.as_text(coverage)}


def scm_status(assessment: Assessment, session: Session) -> dict:
    stored = session.get(AssessmentConfig, assessment.id)
    run = session.get(ScmBpaRun, assessment.id)
    out = {
        "configured": scm_client.configured(),
        "config_stored": stored is not None,
        "platform": stored.platform if stored else None,
        "include_in_score": get_scm_settings(session).include_in_score,
        "run": None,
    }
    if run is not None:
        rows = run.results or []
        out["run"] = {
            "status": run.status, "ran_at": run.ran_at.isoformat(), "error": run.error,
            "checks_evaluated": len({r["check_id"] for r in rows}),
            "results_evaluated": len(rows),
            "failed": sum(1 for r in rows if not r["passed"] and not r["excluded"]),
            "passed": sum(1 for r in rows if r["passed"]),
        }
    return out


@app.post("/api/assessments/{assessment_id}/scm-bpa")
def run_scm_bpa(assessment_id: int, session: Session = Depends(get_session)):
    """Send this assessment's stored config to Palo Alto SCM's BPA and keep the results."""
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    stored = session.get(AssessmentConfig, assessment_id)
    if stored is None:
        raise HTTPException(status_code=409, detail="This assessment was uploaded before configs were kept — "
                                                    "re-upload the file to run the Palo Alto SCM BPA")
    if not scm_client.configured():
        raise HTTPException(status_code=409, detail="SCM isn't configured on the server (set SCM_CLIENT_ID, "
                                                    "SCM_CLIENT_SECRET and SCM_TSG_ID)")
    run = session.get(ScmBpaRun, assessment_id) or ScmBpaRun(assessment_id=assessment_id, status="failed")
    try:
        result = scm_client.run_bpa(gzip.decompress(stored.config_gz))
        run.status, run.error, run.task_id = "completed", None, result.get("_task_id")
        run.results = scm_client.extract_results(result)
    except scm_client.ScmError as e:
        run.status, run.error, run.task_id = "failed", str(e), e.task_id
    except (ValueError, KeyError) as e:
        run.status, run.error = "failed", str(e)
    except Exception as e:  # network errors etc. — record, don't 500
        run.status, run.error = "failed", f"{type(e).__name__}: {e}"
    run.ran_at = datetime.utcnow()
    session.add(run)
    session.commit()
    if run.status == "failed":
        raise HTTPException(status_code=502, detail=run.error)
    return scm_status(assessment, session)


@app.patch("/api/assessments/{assessment_id}")
def update_assessment(assessment_id: int, body: AssessmentUpdateRequest, session: Session = Depends(get_session)):
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    for field in body.model_fields_set & {"client_name", "serial"}:
        value = (getattr(body, field) or "").strip() or None
        if value is not None and len(value) > 200:
            raise HTTPException(status_code=400, detail=f"{field} is too long")
        setattr(assessment, field, value)
    session.add(assessment)

    # A client belongs to the firewall, not one run: give the same client to this firewall's
    # other runs (matched by serial) that don't have one yet. Runs already assigned elsewhere
    # are left alone.
    also_applied = 0
    serial = effective_serial(assessment)
    if "client_name" in body.model_fields_set and assessment.client_name and serial:
        for other in session.exec(select(Assessment).where(Assessment.id != assessment.id,
                                                           Assessment.client_name.is_(None))):
            if effective_serial(other) == serial:
                other.client_name = assessment.client_name
                session.add(other)
                also_applied += 1
    session.commit()
    session.refresh(assessment)
    return {"id": assessment.id, **assessment_identity(assessment), "also_applied": also_applied}


@app.get("/api/clients")
def list_clients(session: Session = Depends(get_session)):
    """Every client name in use, with how many assessments carry it."""
    counts: dict[str, int] = {}
    for name in session.exec(select(Assessment.client_name).where(Assessment.client_name.is_not(None))):
        counts[name] = counts.get(name, 0) + 1
    return [{"name": n, "assessments": c} for n, c in sorted(counts.items(), key=lambda kv: kv[0].lower())]


@app.delete("/api/assessments/{assessment_id}", status_code=204)
def delete_assessment(assessment_id: int, session: Session = Depends(get_session)):
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    for model in (DismissedFinding, AssessmentNote):
        for row in session.exec(select(model).where(model.assessment_id == assessment_id)):
            session.delete(row)
    for model in (AssessmentConfig, ScmBpaRun):
        row = session.get(model, assessment_id)
        if row is not None:
            session.delete(row)
    # No ORM relationship() links Assessment/DismissedFinding (plain FK column
    # only), so SQLAlchemy's flush ordering won't infer child-before-parent —
    # flush explicitly or Postgres (unlike SQLite, which doesn't enforce FKs
    # by default) rejects the assessment delete with a FK violation.
    session.flush()
    session.delete(assessment)
    session.commit()


# ── Findings ─────────────────────────────────────────────────────────────

@app.post("/api/assessments/{assessment_id}/findings/{finding_key}/dismiss")
def dismiss_finding(assessment_id: int, finding_key: str, body: DismissRequest,
                     session: Session = Depends(get_session)):
    assessment = session.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")

    existing = session.exec(
        select(DismissedFinding)
        .where(DismissedFinding.assessment_id == assessment_id)
        .where(DismissedFinding.finding_key == finding_key)
    ).first()
    if existing is None:
        session.add(DismissedFinding(assessment_id=assessment_id, finding_key=finding_key,
                                      reason=body.reason))
        session.commit()
    return {"ok": True}


@app.post("/api/assessments/{assessment_id}/findings/{finding_key}/undismiss")
def undismiss_finding(assessment_id: int, finding_key: str, session: Session = Depends(get_session)):
    rows = session.exec(
        select(DismissedFinding)
        .where(DismissedFinding.assessment_id == assessment_id)
        .where(DismissedFinding.finding_key == finding_key)
    ).all()
    for row in rows:
        session.delete(row)
    session.commit()
    return {"ok": True}


# ── Notes (numbered endnotes on findings and other entries) ──────────────

def _note_out(note: AssessmentNote, number: int, carried_from: Optional[Assessment]) -> dict:
    return {"id": note.id, "number": number, "target_kind": note.target_kind, "target_key": note.target_key,
            "target_label": note.target_label, "body": note.body,
            "created_at": note.created_at.isoformat(), "updated_at": note.updated_at.isoformat(),
            "carried_from": {"id": carried_from.id, "uploaded_at": carried_from.uploaded_at.isoformat()}
            if carried_from else None}


def notes_for(session: Session, assessment_id: int) -> list[dict]:
    """Numbered 1, 2, 3… in the order they were added; deleting one renumbers those after it."""
    rows = session.exec(select(AssessmentNote).where(AssessmentNote.assessment_id == assessment_id)
                        .order_by(AssessmentNote.created_at, AssessmentNote.id)).all()
    return [_note_out(n, i, session.get(Assessment, n.carried_from_id) if n.carried_from_id else None)
            for i, n in enumerate(rows, 1)]


def _note_targets(assessment: Assessment, findings: list[dict], summary: dict) -> set[tuple[str, str]]:
    """Every entry of this run a note can be on, as (kind, key) — the keys the dashboard uses."""
    data = assessment.parsed_data
    return ({("finding", f["finding_key"]) for f in findings}
            | {("remediation", i["key"]) for i in remediation.build(findings, summary["weights"])}
            | {("security_rule", f"{r.get('rule_scope') or ''}:{r['name']}") for r in data.get("security_rules") or []}
            | {("nat_rule", f"{r.get('vsys') or ''}:{r['name']}") for r in data.get("nat_rules") or []})


def carry_over_notes(session: Session, assessment: Assessment, findings: list[dict], summary: dict) -> None:
    """Copies the notes from the same firewall's previous run onto this one, for entries that still
    exist (a note on a finding that's since been fixed stays with the old run). They keep their order."""
    prev = previous_run(session, assessment)
    if prev is None:
        return
    targets = _note_targets(assessment, findings, summary)
    for n in session.exec(select(AssessmentNote).where(AssessmentNote.assessment_id == prev.id)
                          .order_by(AssessmentNote.created_at, AssessmentNote.id)).all():
        if (n.target_kind, n.target_key) in targets:
            session.add(AssessmentNote(assessment_id=assessment.id, target_kind=n.target_kind,
                                       target_key=n.target_key, target_label=n.target_label, body=n.body,
                                       created_at=n.created_at, updated_at=n.updated_at,
                                       carried_from_id=n.carried_from_id or prev.id))
    session.commit()


def _get_note(session: Session, assessment_id: int, note_id: int) -> AssessmentNote:
    note = session.get(AssessmentNote, note_id)
    if note is None or note.assessment_id != assessment_id:
        raise HTTPException(status_code=404, detail="Note not found")
    return note


@app.post("/api/assessments/{assessment_id}/notes")
def create_note(assessment_id: int, body: NoteCreateRequest, session: Session = Depends(get_session)):
    """Adds a note, or replaces the text of the entry's existing one (one note per entry)."""
    if session.get(Assessment, assessment_id) is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if body.target_kind not in NOTE_KINDS:
        raise HTTPException(status_code=422, detail=f"target_kind must be one of {', '.join(NOTE_KINDS)}")
    text_ = body.body.strip()
    if not text_:
        raise HTTPException(status_code=422, detail="The note is empty")
    note = session.exec(select(AssessmentNote).where(AssessmentNote.assessment_id == assessment_id)
                        .where(AssessmentNote.target_kind == body.target_kind)
                        .where(AssessmentNote.target_key == body.target_key)).first()
    if note is None:
        now = datetime.utcnow()
        note = AssessmentNote(assessment_id=assessment_id, target_kind=body.target_kind, target_key=body.target_key,
                              target_label=body.target_label, body=text_, created_at=now, updated_at=now)
    else:
        note.body, note.target_label, note.updated_at = text_, body.target_label, datetime.utcnow()
    session.add(note)
    session.commit()
    return notes_for(session, assessment_id)


@app.patch("/api/assessments/{assessment_id}/notes/{note_id}")
def update_note(assessment_id: int, note_id: int, body: NoteUpdateRequest, session: Session = Depends(get_session)):
    note = _get_note(session, assessment_id, note_id)
    if not body.body.strip():
        raise HTTPException(status_code=422, detail="The note is empty")
    note.body, note.updated_at = body.body.strip(), datetime.utcnow()
    session.add(note)
    session.commit()
    return notes_for(session, assessment_id)


@app.delete("/api/assessments/{assessment_id}/notes/{note_id}")
def delete_note(assessment_id: int, note_id: int, session: Session = Depends(get_session)):
    session.delete(_get_note(session, assessment_id, note_id))
    session.commit()
    return notes_for(session, assessment_id)


# ── Rules / settings ─────────────────────────────────────────────────────

@app.get("/api/rules")
def list_rules(session: Session = Depends(get_session)):
    settings = get_rule_settings(session)
    out = []
    for rule in RULES:
        setting = settings.get(rule.id, {"enabled": rule.enabled_by_default, "threshold_overrides": None,
                                         "severity_override": None})
        effective_severity = setting.get("severity_override") or rule.default_severity
        out.append({
            "id": rule.id, "title": rule.title, "category": rule.category,
            "default_severity": rule.default_severity,
            "effective_severity": effective_severity,
            "severity_override": setting.get("severity_override"),
            "program": "core", "source_type": rule.source_type, "source_ref": rule.source_ref,
            "scm_check_ids": list(rule.scm_check_ids),
            "description": rule.description, "default_thresholds": rule.thresholds,
            "enabled": setting["enabled"],
            "enabled_by_default": rule.enabled_by_default,
            "default_off_reason": rule.default_off_reason,
            "threshold_overrides": setting["threshold_overrides"],
        })
    return out


@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdateRequest, session: Session = Depends(get_session)):
    if rule_id not in RULES_BY_ID and not is_scm_rule_id(rule_id):
        raise HTTPException(status_code=404, detail="Unknown rule id")

    setting = session.get(RuleSetting, rule_id)
    if setting is None:
        # A new row starts from the rule's default, so changing only the severity of a check
        # that's off by default doesn't switch it on.
        setting = RuleSetting(rule_id=rule_id,
                              enabled=scm_catalog.enabled_by_default(int(rule_id[4:])) if is_scm_rule_id(rule_id)
                              else RULES_BY_ID[rule_id].enabled_by_default)

    if body.enabled is not None:
        setting.enabled = body.enabled
    if body.threshold_overrides is not None:
        setting.threshold_overrides = body.threshold_overrides
    if body.severity_override is not None:
        if body.severity_override == "":
            setting.severity_override = None
        elif body.severity_override in VALID_SEVERITIES:
            setting.severity_override = body.severity_override
        else:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {body.severity_override}")

    session.add(setting)
    session.commit()
    session.refresh(setting)
    return {"id": setting.rule_id, "enabled": setting.enabled,
            "threshold_overrides": setting.threshold_overrides,
            "severity_override": setting.severity_override}


def is_scm_rule_id(rule_id: str) -> bool:
    return rule_id.startswith("scm_") and rule_id[4:].isdigit() and int(rule_id[4:]) in scm_catalog.checks_by_id()


# ── Palo Alto SCM BPA catalogue / settings ───────────────────────────────

@app.get("/api/scm/catalog")
def get_scm_catalog(session: Session = Depends(get_session)):
    settings = get_rule_settings(session)
    linked = scm_findings.core_rules_by_scm_check()
    catalog = scm_catalog.load()
    checks = []
    for c in catalog["checks"]:
        rid = scm_findings.scm_rule_id(c["id"])
        setting = settings.get(rid, {})
        default = scm_catalog.SEVERITY_MAP.get(c["severity"], "INFORMATIONAL")
        checks.append({
            **c, "rule_id": rid, "category": scm_catalog.category_for(c["object_type"]),
            "object_type_label": scm_catalog.object_type_label(c["object_type"]),
            "default_severity": default,
            "effective_severity": setting.get("severity_override") or default,
            "severity_override": setting.get("severity_override"),
            "enabled": setting.get("enabled", scm_catalog.enabled_by_default(c["id"])),
            "default_off_reason": scm_catalog.DISABLED_BY_DEFAULT.get(c["id"]),
            "core_rules": linked.get(c["id"], []),
        })
    return {"about": catalog["_about"], "retrieved": catalog["retrieved"], "checks": checks,
            "include_in_score": get_scm_settings(session).include_in_score,
            "configured": scm_client.configured()}


@app.patch("/api/scm/settings")
def update_scm_settings(body: ScmSettingsUpdateRequest, session: Session = Depends(get_session)):
    settings = get_scm_settings(session)
    if body.include_in_score is not None:
        settings.include_in_score = body.include_in_score
    session.add(settings)
    session.commit()
    return {"include_in_score": settings.include_in_score}


# ── Risk scoring formula ─────────────────────────────────────────────────

@app.get("/api/scoring")
def get_scoring(session: Session = Depends(get_session)):
    settings = get_scoring_settings(session)
    weights, thresholds = scoring_weights_and_thresholds(settings)
    return {"weights": weights, "thresholds": thresholds,
            "default_weights": DEFAULT_WEIGHTS, "default_thresholds": DEFAULT_THRESHOLDS}


@app.patch("/api/scoring")
def update_scoring(body: ScoringUpdateRequest, session: Session = Depends(get_session)):
    settings = get_scoring_settings(session)
    for field, value in body.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(settings, field, value)
    session.add(settings)
    session.commit()
    session.refresh(settings)
    weights, thresholds = scoring_weights_and_thresholds(settings)
    return {"weights": weights, "thresholds": thresholds}


# ── Live device (Phase 2 stub) ─────────────────────────────────────────

@app.post("/api/live/connect", status_code=501)
def live_connect(body: LiveConnectRequest):
    raise HTTPException(
        status_code=501,
        detail="Live PAN-OS API connections aren't wired up yet — this is a Phase 2 feature. "
               "app/live_client.py already has the authenticated api_call()/get_api_key() "
               "helpers ready to use here.",
    )

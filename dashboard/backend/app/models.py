from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Column, LargeBinary
from sqlmodel import Field, SQLModel


class Assessment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    filename: str
    hostname: Optional[str] = None
    source: str = "file_upload"  # "file_upload" | "live" (Phase 2) | "panorama_export"
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)
    parsed_data: dict = Field(sa_column=Column(JSON))
    # Set by hand from the dashboard; None until someone assigns one.
    client_name: Optional[str] = Field(default=None, index=True)
    # From the file when it has one (tech support file, Panorama export); plain config
    # exports don't carry it, so it can also be entered by hand.
    serial: Optional[str] = None
    # When the stored source was last re-parsed with the current parser ("Re-analyze").
    reanalyzed_at: Optional[datetime] = None


class PanoramaUpload(SQLModel, table=True):
    """Short-lived staging row: a Panorama export is uploaded once, the user
    picks which device-group/firewall to assess from a follow-up request, and
    this row is deleted once that second request completes."""
    id: Optional[int] = Field(default=None, primary_key=True)
    filename: str
    raw_xml: bytes = Field(sa_column=Column(LargeBinary))
    # The managed firewalls offered in the picker (with hostnames read at upload time).
    devices: Optional[list] = Field(default=None, sa_column=Column(JSON))
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)


class RuleSetting(SQLModel, table=True):
    rule_id: str = Field(primary_key=True)
    enabled: bool = True
    threshold_overrides: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    severity_override: Optional[str] = None  # CRITICAL | WARNING | LOW | INFORMATIONAL, None = use rule default


class DismissedFinding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    finding_key: str = Field(index=True)
    reason: Optional[str] = None
    dismissed_at: datetime = Field(default_factory=datetime.utcnow)


class AssessmentNote(SQLModel, table=True):
    """An analyst's note on one entry of an assessment — a finding, a remediation work item, a rule —
    listed as a numbered endnote in the report. One note per entry. `target_label` keeps what the note
    was about in words, so the endnote still reads correctly if the entry later disappears."""
    id: Optional[int] = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    target_kind: str
    target_key: str
    target_label: str
    body: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    # Set on a note copied forward from the same firewall's previous run: that run's id.
    carried_from_id: Optional[int] = None


class ScoringSettings(SQLModel, table=True):
    """Single-row table (id fixed at 1) holding the risk-score formula."""
    id: Optional[int] = Field(default=1, primary_key=True)
    weight_critical: int = 10
    weight_warning: int = 5
    weight_low: int = 2
    weight_informational: int = 1
    informational_max: int = 0  # score <= informational_max -> INFORMATIONAL
    low_max: int = 15           # score <= low_max           -> LOW
    warning_max: int = 40       # score <= warning_max       -> WARNING, above -> CRITICAL


class AssessmentConfig(SQLModel, table=True):
    """The config the assessment was built from (gzipped), kept so it can be sent to Palo
    Alto's SCM BPA later. Separate table so existing databases pick it up via create_all."""
    assessment_id: int = Field(foreign_key="assessment.id", primary_key=True)
    platform: str = "ngfw"  # "ngfw" | "panorama"
    config_gz: bytes = Field(sa_column=Column(LargeBinary))
    # A tech support file's CLI output (system info, licenses, HA state), gzipped, so the
    # assessment can be re-analyzed without the file. None for other sources and older uploads.
    cli_text_gz: Optional[bytes] = Field(default=None, sa_column=Column(LargeBinary, nullable=True))


class ScmBpaRun(SQLModel, table=True):
    """The latest Palo Alto SCM BPA run for an assessment, flattened to one row per
    (check, object) — see scm_client.extract_results."""
    assessment_id: int = Field(foreign_key="assessment.id", primary_key=True)
    status: str  # "completed" | "failed"
    ran_at: datetime = Field(default_factory=datetime.utcnow)
    task_id: Optional[str] = None
    error: Optional[str] = None
    results: Optional[list] = Field(default=None, sa_column=Column(JSON))


class ScmSettings(SQLModel, table=True):
    """Single-row table (id fixed at 1)."""
    id: Optional[int] = Field(default=1, primary_key=True)
    include_in_score: bool = True


class AppMeta(SQLModel, table=True):
    """Single-row table (id fixed at 1) recording one-time data migrations applied."""
    id: Optional[int] = Field(default=1, primary_key=True)
    severity_scale: int = 1  # 2 = Critical / Warning / Low / Informational

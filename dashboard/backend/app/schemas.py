from typing import Optional

from pydantic import BaseModel, Field


class RuleUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    threshold_overrides: Optional[dict] = None
    severity_override: Optional[str] = None  # "CRITICAL" | "WARNING" | "LOW" | "INFORMATIONAL" | "" (empty string resets to default)


class ScoringUpdateRequest(BaseModel):
    weight_critical: Optional[int] = None
    weight_warning: Optional[int] = None
    weight_low: Optional[int] = None
    weight_informational: Optional[int] = None
    informational_max: Optional[int] = None
    low_max: Optional[int] = None
    warning_max: Optional[int] = None


class DismissRequest(BaseModel):
    reason: Optional[str] = None


NOTE_KINDS = ("finding", "remediation", "security_rule", "nat_rule")


class NoteCreateRequest(BaseModel):
    target_kind: str = Field(max_length=32)
    target_key: str = Field(min_length=1, max_length=512)
    target_label: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=10000)


class NoteUpdateRequest(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


class LiveConnectRequest(BaseModel):
    host: str
    user: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None


class FromPanoramaRequest(BaseModel):
    upload_id: int
    # A managed firewall's serial (its device groups and template stack are worked out from it), or,
    # as before, a device group.
    serial: Optional[str] = None
    device_group: Optional[str] = None


class ScmSettingsUpdateRequest(BaseModel):
    include_in_score: Optional[bool] = None


class AssessmentUpdateRequest(BaseModel):
    """Only the fields sent are changed; send null or "" to clear one."""
    client_name: Optional[str] = None
    serial: Optional[str] = None

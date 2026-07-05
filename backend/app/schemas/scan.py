from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator

from ..config import settings


class TargetType(str, Enum):
    MCP_SERVER = "mcp_server"
    AGENT_SKILL = "agent_skill"
    NPM_PACKAGE = "npm_package"
    PYPI_PACKAGE = "pypi_package"


class ScanOptions(BaseModel):
    deep: bool = True
    timeout: int = Field(default=120, ge=1, le=120)
    inline_content: str | None = Field(default=None, max_length=settings.MAX_INLINE_CONTENT_BYTES)
    ai_api_key: str | None = Field(default=None, max_length=200)
    ai_model: str | None = Field(default=None, max_length=100)

    @field_validator("inline_content")
    @classmethod
    def validate_inline_content(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if len(value.encode("utf-8")) > settings.MAX_INLINE_CONTENT_BYTES:
            raise ValueError("inline content exceeds maximum allowed size")
        return value


class ScanRequest(BaseModel):
    target_type: TargetType
    target: str = Field(min_length=1, max_length=settings.MAX_TARGET_LENGTH)
    options: ScanOptions = Field(default_factory=ScanOptions)
    rescan_of: str | None = Field(default=None, max_length=36)

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target cannot be empty")
        return cleaned


class FindingCreate(BaseModel):
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    references: list[str] = Field(default_factory=list)


class FindingResponse(BaseModel):
    id: str
    category: str
    severity: str
    title: str
    description: str
    evidence: str
    remediation: str
    cwe: str | None
    owasp: str | None
    references: list[str]

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    target_type: str
    overall_risk: int
    risk_level: str
    summary: dict[str, int]
    findings: list[FindingResponse]
    metadata: dict[str, int | dict]
    created_at: str | None = None
    error_message: str | None = None
    content_changed: bool = False
    rescan_of: str | None = None
    ai_attack_scenarios: list[dict] = Field(default_factory=list)
    ai_remediation: list[dict] = Field(default_factory=list)
    ai_narrative: dict = Field(default_factory=dict)
    ai_threat_intel: list[dict] = Field(default_factory=list)


class ReportResponse(BaseModel):
    """Structured report with findings grouped by severity."""
    scan_id: str
    target: str
    target_type: str
    status: str
    overall_risk: int
    risk_level: str
    summary: dict[str, int]
    findings: dict[str, list[FindingResponse]]
    total_findings: int
    metadata: dict[str, int | dict]
    created_at: str | None = None
    error_message: str | None = None


class ScanListItem(BaseModel):
    scan_id: str
    target: str
    target_type: str
    status: str
    overall_risk: int
    risk_level: str
    created_at: str | None = None


class ScanListResponse(BaseModel):
    scans: list[ScanListItem]
    total: int
    page: int
    limit: int


class StatsResponse(BaseModel):
    total_scans: int
    risk_distribution: dict[str, int]
    recent_scans: list[ScanListItem]


# --- Report schemas ---

class ScoreDetail(BaseModel):
    value: int
    label: str
    scale: str

class Scores(BaseModel):
    risk_score: ScoreDetail
    trust_score: ScoreDetail

class AttackScenario(BaseModel):
    category: str
    severity: str
    finding: str
    attack_vector: str

class AttackSimulation(BaseModel):
    description: str
    scenarios: list[AttackScenario]

class JsonReport(BaseModel):
    report: dict[str, str]
    scan_overview: dict[str, object]
    scores: Scores
    findings_summary: dict[str, int | dict]
    findings: dict[str, list[FindingResponse]]
    recommendations: list[str]
    attack_simulation: AttackSimulation

class ReportExportResponse(BaseModel):
    format: str
    content: str | dict

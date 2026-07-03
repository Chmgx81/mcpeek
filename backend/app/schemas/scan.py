from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class TargetType(str, Enum):
    MCP_SERVER = "mcp_server"
    AGENT_SKILL = "agent_skill"
    NPM_PACKAGE = "npm_package"
    PYPI_PACKAGE = "pypi_package"


class ScanOptions(BaseModel):
    deep: bool = True
    timeout: int = 120


class ScanRequest(BaseModel):
    target_type: TargetType
    target: str
    options: ScanOptions = Field(default_factory=ScanOptions)


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

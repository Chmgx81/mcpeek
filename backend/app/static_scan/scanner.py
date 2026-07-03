"""Unified static scanner — single entry point for all content analysis."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field

from ..schemas.scan import FindingCreate
from .injection import (
    check_dangerous_permissions,
    check_exfiltration,
    check_hidden_instructions,
    check_prompt_injection,
    check_social_engineering,
)
from .parser import parse_input
from .secrets import detect_secrets
from .external import check_external_dependencies
from .shell import check_shell_execution


@dataclass
class ScanResult:
    """Structured output of a static scan."""

    scan_id: str
    target_name: str
    target_type: str  # "json", "yaml", "text"
    content_hash: str
    risk_score: int = 100
    risk_level: str = "safe"
    findings: list[FindingCreate] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_name": self.target_name,
            "target_type": self.target_type,
            "content_hash": self.content_hash,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "findings": [
                {
                    "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self.scan_id}:{i}")),
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommendation": f.remediation,
                }
                for i, f in enumerate(self.findings)
            ],
        }


# Risk scoring: start at 100, deduct per finding
SEVERITY_DEDUCTION: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def _calculate_score(findings: list[FindingCreate]) -> tuple[int, str]:
    """Start at 100, deduct per finding, floor at 0."""
    score = 100
    for f in findings:
        score -= SEVERITY_DEDUCTION.get(f.severity, 0)
    score = max(score, 0)

    if score >= 90:
        level = "safe"
    elif score >= 70:
        level = "low"
    elif score >= 50:
        level = "medium"
    elif score >= 25:
        level = "high"
    else:
        level = "critical"
    return score, level


def scan_content(
    content: str,
    target_name: str = "unknown",
    filename: str | None = None,
) -> ScanResult:
    """Run all static analysis rules against raw content.

    Accepts JSON, YAML, or plain text. Returns structured ScanResult.
    """
    text, parsed = parse_input(content, filename)

    # Determine input type
    if parsed is not None:
        try:
            json.loads(text)
            target_type = "json"
        except (json.JSONDecodeError, TypeError):
            target_type = "yaml"
    else:
        target_type = "text"

    content_hash = hashlib.sha256(text.encode()).hexdigest()[:16]

    all_findings: list[FindingCreate] = []

    # 1. Shell execution (Critical)
    all_findings.extend(check_shell_execution(text, target_name))

    # 2. Prompt injection (High)
    all_findings.extend(check_prompt_injection(text, target_name))

    # 3. Hardcoded secrets (High)
    all_findings.extend(detect_secrets(text, target_name))

    # 4. Dangerous permissions (Critical)
    all_findings.extend(check_dangerous_permissions(text, target_name))

    # 5. External dependency analysis
    all_findings.extend(check_external_dependencies(text, target_name))

    # 6. Bonus: social engineering, exfiltration, hidden instructions
    all_findings.extend(check_social_engineering(text, target_name))
    all_findings.extend(check_exfiltration(text, target_name))
    all_findings.extend(check_hidden_instructions(text, target_name))

    risk_score, risk_level = _calculate_score(all_findings)

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        target_name=target_name,
        target_type=target_type,
        content_hash=content_hash,
        risk_score=risk_score,
        risk_level=risk_level,
        findings=all_findings,
    )

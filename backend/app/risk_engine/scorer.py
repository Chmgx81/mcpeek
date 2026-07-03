from app.schemas.scan import FindingCreate

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def calculate_risk(findings: list[FindingCreate]) -> tuple[int, str]:
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = min(score, 100)

    if score <= 20:
        level = "safe"
    elif score <= 40:
        level = "low"
    elif score <= 60:
        level = "medium"
    elif score <= 80:
        level = "high"
    else:
        level = "critical"

    return score, level


def build_summary(findings: list[FindingCreate]) -> dict[str, int]:
    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1
    return summary

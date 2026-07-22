from ..schemas import FindingCreate

SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

# Risk level thresholds (aligned with report_generator.py)
_RISK_THRESHOLDS = [
    (20, "safe"),
    (40, "low"),
    (60, "medium"),
    (80, "high"),
    (101, "critical"),
]


def calculate_risk(findings: list[FindingCreate]) -> tuple[int, str]:
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = min(score, 100)

    level = "safe"
    for threshold, label in _RISK_THRESHOLDS:
        if score < threshold:
            level = label
            break

    return score, level


def _compute_trust_score(findings: list[FindingCreate]) -> int:
    """Derive trust score from findings (lower is worse)."""
    trust_cats = {
        "external_dependencies", "unpinned_packages",
        "suspicious_domain", "unofficial_source", "typosquatting",
        "supply_chain", "permissions", "scope_creep",
    }
    runtime_cats = {
        "remote_code_execution", "exfiltration", "system_modification",
        "execution", "code_execution", "tool_poisoning",
        "intent_subversion", "context_oversharing",
    }
    trust_hits = sum(1 for f in findings if f.category in trust_cats)
    runtime_hits = sum(1 for f in findings if f.category in runtime_cats)
    return max(0, 100 - trust_hits * 15 - runtime_hits * 10)


def build_summary(findings: list[FindingCreate]) -> dict[str, int]:
    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1
    summary["trust_score"] = _compute_trust_score(findings)
    return summary

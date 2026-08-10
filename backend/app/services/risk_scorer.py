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

_RISK_LABELS = {
    (0, 20): "Safe",
    (20, 40): "Low",
    (40, 60): "Medium",
    (60, 80): "High",
    (80, 101): "Critical",
}

_TRUST_LABELS = {
    (90, 101): "Trusted",
    (70, 90): "Low concern",
    (50, 70): "Moderate concern",
    (25, 50): "High concern",
    (0, 25): "Untrusted",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def calculate_risk(findings: list[FindingCreate]) -> tuple[int, str]:
    score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = min(score, 100)

    level = "safe"
    for threshold, label in _RISK_THRESHOLDS:
        if score < threshold:
            level = label
            break

    return score, level


def risk_label(score: int) -> str:
    for (lo, hi), label in _RISK_LABELS.items():
        if lo <= score < hi:
            return label
    return "Safe"


def trust_label(score: int) -> str:
    for (lo, hi), label in _TRUST_LABELS.items():
        if lo <= score < hi:
            return label
    return "Trusted"


def compute_trust_score(findings: list[FindingCreate] | list[dict]) -> int:
    """Derive trust score from findings (lower is worse).

    Accepts both FindingCreate objects and plain dicts with a 'category' key.
    """
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
    if findings and isinstance(findings[0], dict):
        trust_hits = sum(1 for f in findings if f.get("category") in trust_cats)
        runtime_hits = sum(1 for f in findings if f.get("category") in runtime_cats)
    else:
        trust_hits = sum(1 for f in findings if f.category in trust_cats)
        runtime_hits = sum(1 for f in findings if f.category in runtime_cats)
    return max(0, 100 - trust_hits * 15 - runtime_hits * 10)


def group_by_severity(findings: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    for f in findings:
        sev = f.get("severity", "info") if isinstance(f, dict) else getattr(f, "severity", "info")
        if sev in groups:
            groups[sev].append(f)
    for sev in groups:
        groups[sev].sort(key=lambda x: x.get("title", "") if isinstance(x, dict) else getattr(x, "title", ""))
    return groups


def build_summary(findings: list[FindingCreate]) -> dict[str, int]:
    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in summary:
            summary[f.severity] += 1
    summary["trust_score"] = compute_trust_score(findings)
    return summary

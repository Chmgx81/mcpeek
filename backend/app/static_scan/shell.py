"""Shell execution detection — the #1 MCP attack surface."""

import re

from ..detection.patterns import SHELL_PATTERNS
from ..schemas.scan import FindingCreate

LIFECYCLE_SCRIPT_RE = re.compile(
    r'["\']?(postinstall|preinstall|postuninstall|preuninstall|prepare)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

DANGEROUS_LIFECYCLE = {"postinstall", "preinstall"}


def check_shell_execution(content: str, source: str = "content") -> list[FindingCreate]:
    """Scan text for shell execution patterns."""
    findings: list[FindingCreate] = []
    seen_titles: set[str] = set()

    for pattern, title, severity, description in SHELL_PATTERNS:
        for match in re.finditer(pattern, content):
            if title in seen_titles:
                continue
            seen_titles.add(title)

            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            context = content[start:end].replace("\n", " ").strip()

            findings.append(
                FindingCreate(
                    category="shell_execution",
                    severity=severity,
                    title=f"Shell execution: {title}",
                    description=description,
                    evidence=f"Source: {source}\nMatch: ...{context[:150]}...",
                    remediation="Remove or sandbox shell execution. Use allowlists for permitted commands.",
                    cwe="CWE-78",
                )
            )

    for match in LIFECYCLE_SCRIPT_RE.finditer(content):
        hook_name = match.group(1).lower()
        cmd = match.group(2)
        severity = "high" if hook_name in DANGEROUS_LIFECYCLE else "medium"
        findings.append(
            FindingCreate(
                category="shell_execution",
                severity=severity,
                title=f"Lifecycle script: {hook_name}",
                description=f"The {hook_name} script executes automatically on install/uninstall: `{cmd[:100]}`",
                evidence=f"Source: {source}\nHook: {hook_name}\nCommand: {cmd[:200]}",
                remediation="Review lifecycle scripts for malicious behavior. Prefer postinstall/prepare hooks over preinstall. Audit what scripts do before executing.",
                cwe="CWE-78",
            )
        )

    return findings

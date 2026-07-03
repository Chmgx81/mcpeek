"""Shell execution detection — the #1 MCP attack surface."""

import re

from ..detection.patterns import SHELL_PATTERNS
from ..schemas.scan import FindingCreate


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
                    owasp="A03:2021",
                )
            )
    return findings

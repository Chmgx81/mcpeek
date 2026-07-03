"""Prompt injection, permissions, social engineering, and exfiltration detection."""

import re

from ..detection.patterns import (
    DANGEROUS_PERMISSIONS,
    EXFILTRATION_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    SOCIAL_ENGINEERING_PATTERNS,
)
from ..schemas.scan import FindingCreate


def check_prompt_injection(content: str, source: str) -> list[FindingCreate]:
    """Scan text for prompt injection patterns."""
    findings: list[FindingCreate] = []
    for pattern, title in PROMPT_INJECTION_PATTERNS:
        for match in re.finditer(pattern, content):
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(
                FindingCreate(
                    category="prompt_injection",
                    severity="high",
                    title=f"{title} in {source}",
                    description=f"Content from {source} contains a pattern matching known prompt injection: '{title}'. This could allow an attacker to manipulate AI agent behavior.",
                    evidence=f"Source: {source}\nMatch: ...{context}...",
                    remediation="Remove prompt injection patterns. Content should not contain instructions that override system prompts.",
                    cwe="CWE-77",
                    owasp="LLM01:2025",
                )
            )
    return findings


def check_dangerous_permissions(content: str, source: str) -> list[FindingCreate]:
    """Scan text for dangerous tool permission requests."""
    findings: list[FindingCreate] = []
    for tool_name, severity in DANGEROUS_PERMISSIONS.items():
        for match in re.finditer(rf"(?i)(?:{re.escape(tool_name)})\b", content):
            findings.append(
                FindingCreate(
                    category="permissions",
                    severity=severity,
                    title=f"Dangerous tool permission: {tool_name}",
                    description=f"The content requests access to '{tool_name}', which has a {severity} risk level.",
                    evidence=f"Source: {source}\nTool requested: {tool_name}\nContext: {match.group(0)[:150]}",
                    remediation="Review whether this permission is truly necessary. Limit tool scopes to the minimum required.",
                    cwe="CWE-265",
                )
            )
            break  # one finding per tool
    return findings


def check_social_engineering(content: str, source: str) -> list[FindingCreate]:
    """Scan for instructions that deceive or hide from users."""
    findings: list[FindingCreate] = []
    for pattern, title in SOCIAL_ENGINEERING_PATTERNS:
        for match in re.finditer(pattern, content):
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(
                FindingCreate(
                    category="social_engineering",
                    severity="high",
                    title=f"Social engineering pattern: {title}",
                    description=f"The content contains instructions to '{title}', which could be used to manipulate or deceive users.",
                    evidence=f"Source: {source}\nPattern: ...{context}...",
                    remediation="Remove deceptive instructions. Agent behaviors should be transparent to users.",
                    cwe="CWE-250",
                )
            )
    return findings


def check_exfiltration(content: str, source: str) -> list[FindingCreate]:
    """Scan for code patterns that could exfiltrate data via HTTP requests."""
    findings: list[FindingCreate] = []
    for pattern, title in EXFILTRATION_PATTERNS:
        for match in re.finditer(pattern, content):
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(
                FindingCreate(
                    category="exfiltration",
                    severity="high",
                    title=f"Potential data exfiltration: {title}",
                    description="The content contains code that makes outbound HTTP requests, which could be used to exfiltrate data.",
                    evidence=f"Source: {source}\nCode: {context[:200]}",
                    remediation="Review outbound network calls. Ensure data is not sent to untrusted destinations.",
                    cwe="CWE-201",
                )
            )
    return findings


def check_hidden_instructions(content: str, source: str) -> list[FindingCreate]:
    """Detect zero-width characters that could be used for data smuggling."""
    findings: list[FindingCreate] = []
    zero_width_chars = re.findall(r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]", content)
    if len(zero_width_chars) > 10:
        findings.append(
            FindingCreate(
                category="prompt_injection",
                severity="medium",
                title="Zero-width characters detected",
                description=f"Found {len(zero_width_chars)} zero-width/hidden Unicode characters. These can be used for data smuggling or hiding instructions from human review.",
                evidence=f"Source: {source}\nCount: {len(zero_width_chars)} invisible characters",
                remediation="Remove zero-width Unicode characters unless they serve a specific legitimate purpose.",
                cwe="CWE-506",
            )
        )
    return findings


def extract_urls(text: str, max_urls: int = 20) -> list[str]:
    """Extract external URLs from text, filtering out common safe domains."""
    from ..detection.utils import extract_urls as _extract_urls
    return _extract_urls(text, max_urls)

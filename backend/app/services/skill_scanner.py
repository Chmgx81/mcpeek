import re

from ..detection.patterns import (
    DANGEROUS_PERMISSIONS,
    EXFILTRATION_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    SOCIAL_ENGINEERING_PATTERNS,
)
from ..detection.utils import detect_secrets, extract_urls
from ..schemas import FindingCreate
from .ast_analyzer import analyze_code
from .advanced_injection import detect_advanced_injection
from .content_hash import hash_external_urls
from .dependency_risk import analyze_domain_reputation, score_urls
from .external_analyzer import analyze_urls


async def scan_skill(target: str, deep: bool = True, timeout: int = 120, inline_content: str | None = None) -> tuple[list[FindingCreate], dict]:
    findings: list[FindingCreate] = []
    metadata: dict = {"files_analyzed": 0, "urls_checked": 0, "deps_analyzed": 0, "content_hashes": {}}
    urls_found: list[str] = []

    if inline_content:
        content = inline_content
        metadata["files_analyzed"] = 1
    else:
        content = await _fetch_skill_content(target, timeout)
        if not content:
            findings.append(
                FindingCreate(
                    category="manifest",
                    severity="low",
                    title="Could not read skill file",
                    description=f"Unable to fetch or read skill file from: {target}",
                    remediation="Verify the URL or path is accessible.",
                )
            )
            return findings, metadata
        metadata["files_analyzed"] = 1

    # Run all checks
    findings.extend(_check_prompt_injection(content, target))
    findings.extend(_check_dangerous_permissions(content, target))
    findings.extend(_check_social_engineering(content, target))
    findings.extend(_check_exfiltration(content, target))
    findings.extend(detect_secrets(content, target))
    findings.extend(_check_hidden_instructions(content, target))
    findings.extend(detect_advanced_injection(content, target))

    # AST-based code analysis (beyond regex)
    findings.extend(analyze_code(content))

    # Extract and analyze URLs
    urls_found.extend(extract_urls(content))
    if deep and urls_found:
        url_findings, checked = await analyze_urls(urls_found, timeout=min(timeout, 15))
        findings.extend(url_findings)
        metadata["urls_checked"] = checked

        # Content hashing for bait-and-switch detection
        url_hashes = await hash_external_urls(urls_found, timeout=min(timeout, 10))
        metadata["content_hashes"] = url_hashes

        # Dependency risk scoring
        risk_findings, risk_score = score_urls(urls_found)
        findings.extend(risk_findings)
        metadata["dependency_risk_score"] = risk_score

        # Domain reputation analysis
        domain_findings = analyze_domain_reputation(urls_found)
        findings.extend(domain_findings)

    return findings, metadata


async def _fetch_skill_content(target: str, timeout: int) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(target)
                resp.raise_for_status()
                return resp.content[:1_000_000].decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            return ""
    else:
        try:
            with open(target) as f:
                return f.read()
        except Exception:
            return ""


def _check_prompt_injection(content: str, source: str) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    for pattern, title in PROMPT_INJECTION_PATTERNS:
        matches = list(re.finditer(pattern, content))
        if matches:
            match = matches[0]
            # Get surrounding context
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(
                FindingCreate(
                    category="prompt_injection",
                    severity="critical",
                    title=f"{title} in skill definition",
                    description=f"The skill file contains a pattern matching known prompt injection: '{title}'. This could allow an attacker to manipulate AI agent behavior.",
                    evidence=f"Source: {source}\nMatch: ...{context}...",
                    remediation="Remove prompt injection patterns. Skills should not contain instructions that override system prompts.",
                    cwe="CWE-77",
                    owasp="LLM01:2025",
                )
            )
    return findings


def _check_dangerous_permissions(content: str, source: str) -> list[FindingCreate]:
    findings: list[FindingCreate] = []

    # Look for tool/permission declarations
    permission_patterns = [
        r"(?i)tools?\s*[:=]\s*\[([^\]]+)\]",
        r"(?i)requires?\s*[:=]\s*\[([^\]]+)\]",
        r"(?i)permissions?\s*[:=]\s*\[([^\]]+)\]",
        r"(?i)available_tools?\s*[:=]\s*\[([^\]]+)\]",
    ]

    for perm_pattern in permission_patterns:
        for match in re.finditer(perm_pattern, content):
            tools_str = match.group(1).lower()
            for tool_name, severity in DANGEROUS_PERMISSIONS.items():
                if tool_name in tools_str:
                    findings.append(
                        FindingCreate(
                            category="permissions",
                            severity=severity,
                            title=f"Dangerous tool permission: {tool_name}",
                            description=f"The skill requests access to '{tool_name}', which has a {severity} risk level. This permission could be abused for malicious purposes.",
                            evidence=f"Source: {source}\nTool requested: {tool_name}\nContext: {match.group(0)[:150]}",
                            remediation="Review whether this tool permission is necessary. Apply principle of least privilege.",
                            cwe="CWE-250",
                        )
                    )

    return findings


def _check_social_engineering(content: str, source: str) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    for pattern, title in SOCIAL_ENGINEERING_PATTERNS:
        matches = list(re.finditer(pattern, content))
        if matches:
            match = matches[0]
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(
                FindingCreate(
                    category="social_engineering",
                    severity="high",
                    title=f"{title} in skill definition",
                    description=f"The skill file contains instructions that attempt to hide actions from users or deceive them: '{title}'.",
                    evidence=f"Source: {source}\nContext: ...{context}...",
                    remediation="Remove deceptive instructions. All agent actions should be transparent to users.",
                    cwe="CWE-506",
                )
            )
    return findings


def _check_exfiltration(content: str, source: str) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    for pattern, title in EXFILTRATION_PATTERNS:
        matches = list(re.finditer(pattern, content))
        if matches:
            match = matches[0]
            start = max(0, match.start() - 20)
            end = min(len(content), match.end() + 40)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(
                FindingCreate(
                    category="exfiltration",
                    severity="high",
                    title=f"Potential data exfiltration: {title}",
                    description="The skill contains code that makes outbound HTTP requests, which could be used to exfiltrate data.",
                    evidence=f"Source: {source}\nCode: {context[:200]}",
                    remediation="Review outbound network calls. Ensure data is not sent to untrusted destinations.",
                    cwe="CWE-200",
                )
            )
    return findings


def _check_hidden_instructions(content: str, source: str) -> list[FindingCreate]:
    findings: list[FindingCreate] = []

    # Check for HTML comments hiding instructions
    html_comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)
    for comment in html_comments:
        if len(comment.strip()) > 20:
            has_suspicious = any(
                kw in comment.lower()
                for kw in ["ignore", "override", "instruction", "system", "prompt", "secret"]
            )
            if has_suspicious:
                findings.append(
                    FindingCreate(
                        category="prompt_injection",
                        severity="high",
                        title="Hidden instructions in HTML comment",
                        description="An HTML comment contains text that may be an attempt to hide instructions from the user while making them available to AI systems.",
                        evidence=f"Source: {source}\nComment: <!--{comment[:200]}...-->",
                        remediation="Remove hidden instructions from HTML comments. All instructions should be visible to users.",
                        cwe="CWE-615",
                        owasp="LLM01:2025",
                    )
                )

    # Check for zero-width characters (potential smuggling)
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

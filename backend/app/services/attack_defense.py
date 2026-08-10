"""
Attack Defense — protects the AI agent against prompt injection, jailbreaking,
and adversarial inputs using the vulnerability database and heuristic checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .vulnerability_db import (
    get_vulnerability_db,
    AttackPattern,
    AttackCategory,
    VulnSeverity,
)


class ThreatLevel(str, Enum):
    """Threat level for incoming content."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatMatch:
    """A detected threat in content."""
    pattern: AttackPattern
    matched_text: str
    threat_level: ThreatLevel
    line_number: int = 0
    context: str = ""


@dataclass
class DefenseReport:
    """Result of defense analysis."""
    threat_level: ThreatLevel
    threats: list[ThreatMatch]
    blocked: bool = False
    sanitized_content: str = ""
    recommendations: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if not self.threats:
            return "No threats detected"
        cats = set(t.pattern.category.value for t in self.threats)
        return f"{len(self.threats)} threat(s) detected [{', '.join(cats)}]"


# ── Known adversarial prefixes / suffixes ──

ADVERSARIAL_PREFIXES = [
    r"^.*?ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+",
    r"^.*?system\s*:\s*you\s+are\s+now",
    r"^.*?new\s+instructions?\s*:",
    r"^.*?admin\s+override\s*:",
    r"^.*?special\s+instructions?\s*:",
    r"^.*?forget\s+(?:all\s+)?(?:previous|prior|everything)\s+",
    r"^.*?act\s+as\s+if\s+",
    r"^.*?pretend\s+you\s+are\s+",
    r"^.*?roleplay\s+as\s+",
    r"^.*?you\s+are\s+no\s+longer",
    r"^.*?from\s+now\s+on\s+you",
]

# Hidden unicode tricks used in prompt injection
UNICODE_OBFUSCATION_PATTERNS = [
    r"[\u200b-\u200f\u2028-\u202f\ufeff]",  # Zero-width chars
    r"[\u00ad\u034f\u061c]",  # Soft hyphen, grapheme joiner, Arabic letter mark
    r"[\U000e0001-\U000e007f]",  # Tag characters
]


class AttackDefense:
    """
    Defense layer that analyzes content for adversarial inputs and threats.
    Uses the vulnerability database + heuristic checks.
    """

    def __init__(self) -> None:
        self._db = get_vulnerability_db()

    def analyze(
        self,
        content: str,
        context: Optional[str] = None,
        block_critical: bool = False,
    ) -> DefenseReport:
        """
        Analyze content for threats.

        Args:
            content: The input to analyze (user message, tool response, etc.)
            context: Optional surrounding context for better analysis.
            block_critical: If True, mark critical threats as blocked.
        """
        threats: list[ThreatMatch] = []
        lines = content.split("\n")

        # 1. Check attack patterns from vulnerability DB
        for i, line in enumerate(lines, 1):
            matches = self._db.match_patterns(line)
            for pattern, matched_text in matches:
                level = self._severity_to_threat(pattern.severity)
                threats.append(ThreatMatch(
                    pattern=pattern,
                    matched_text=matched_text,
                    threat_level=level,
                    line_number=i,
                    context=context or "",
                ))

        # 2. Check adversarial prefixes
        for pattern in ADVERSARIAL_PREFIXES:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="ADV-PREFIX",
                        name="Adversarial Prefix Injection",
                        category=AttackCategory.PROMPT_INJECTION,
                        severity=VulnSeverity.CRITICAL,
                        regex_patterns=[pattern],
                        description="Known adversarial prefix for prompt injection.",
                        mitigation="Strip adversarial prefixes, validate input structure.",
                        cwe="CWE-20",
                    ),
                    matched_text=match.group(0)[:100],
                    threat_level=ThreatLevel.CRITICAL,
                    line_number=content[:match.start()].count("\n") + 1,
                    context=context or "",
                ))

        # 3. Check Unicode obfuscation
        for pattern in UNICODE_OBFUSCATION_PATTERNS:
            matches = list(re.finditer(pattern, content))
            if matches:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="UNICODE-OBF",
                        name="Unicode Obfuscation",
                        category=AttackCategory.PROMPT_INJECTION,
                        severity=VulnSeverity.HIGH,
                        regex_patterns=[pattern],
                        description="Hidden Unicode characters used to obfuscate malicious content.",
                        mitigation="Strip zero-width and invisible characters.",
                        cwe="CWE-20",
                    ),
                    matched_text=f"{len(matches)} invisible character(s) found",
                    threat_level=ThreatLevel.HIGH,
                    context=context or "",
                ))

        # 4. Check vulnerability-specific patterns
        vuln_matches = self._db.match_vulnerability_patterns(content)
        for vuln, matched_text in vuln_matches:
            level = self._severity_to_threat(vuln.severity)
            threats.append(ThreatMatch(
                pattern=AttackPattern(
                    pattern_id=vuln.cve_id,
                    name=vuln.title,
                    category=vuln.categories[0] if vuln.categories else AttackCategory.PROMPT_INJECTION,
                    severity=vuln.severity,
                    regex_patterns=vuln.detection_patterns,
                    description=vuln.description,
                    mitigation="Follow vendor advisory.",
                ),
                matched_text=matched_text,
                threat_level=level,
                context=context or "",
            ))

        # 5. Extended heuristic detection for common attack vectors
        threats.extend(self._check_extended_patterns(content))

        # Determine overall threat level
        if not threats:
            overall = ThreatLevel.SAFE
        else:
            max_level = max(t.threat_level for t in threats)
            overall = max_level

        blocked = block_critical and overall == ThreatLevel.CRITICAL

        # Generate sanitized content
        sanitized = self._sanitize(content, threats) if threats else content

        # Generate recommendations
        recommendations = self._recommendations(threats)

        return DefenseReport(
            threat_level=overall,
            threats=threats,
            blocked=blocked,
            sanitized_content=sanitized,
            recommendations=recommendations,
        )

    def sanitize_input(self, content: str) -> str:
        """Strip dangerous characters and normalize input."""
        result = content
        # Remove zero-width characters
        for pattern in UNICODE_OBFUSCATION_PATTERNS:
            result = re.sub(pattern, "", result)
        # Strip control characters (keep newlines and tabs)
        result = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", result)
        return result.strip()

    def _sanitize(self, content: str, threats: list[ThreatMatch]) -> str:
        """Remove detected threat content."""
        result = content
        # Remove adversarial prefixes
        for pattern in ADVERSARIAL_PREFIXES:
            result = re.sub(pattern, "", result, flags=re.IGNORECASE | re.MULTILINE)
        # Remove zero-width characters
        for pattern in UNICODE_OBFUSCATION_PATTERNS:
            result = re.sub(pattern, "", result)
        # Remove control characters
        result = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", result)
        return result.strip()

    def _severity_to_threat(self, severity: VulnSeverity) -> ThreatLevel:
        return {
            VulnSeverity.CRITICAL: ThreatLevel.CRITICAL,
            VulnSeverity.HIGH: ThreatLevel.HIGH,
            VulnSeverity.MEDIUM: ThreatLevel.MEDIUM,
            VulnSeverity.LOW: ThreatLevel.LOW,
            VulnSeverity.INFO: ThreatLevel.SAFE,
        }.get(severity, ThreatLevel.SAFE)

    def _recommendations(self, threats: list[ThreatMatch]) -> list[str]:
        recs = []
        cats = set(t.pattern.category for t in threats)

        if AttackCategory.PROMPT_INJECTION in cats:
            recs.append("Use structured prompting with clear delimiter tokens")
            recs.append("Validate and sanitize all user inputs before processing")
            recs.append("Implement input/output filtering for adversarial content")
        if AttackCategory.DATA_EXFILTRATION in cats:
            recs.append("Restrict outbound network access from AI agents")
            recs.append("Audit and log all tool calls and data flows")
        if AttackCategory.COMMAND_INJECTION in cats:
            recs.append("Never pass unsanitized user input to shell commands")
            recs.append("Use parameterized commands and sandbox execution")
        if AttackCategory.CREDENTIAL_LEAK in cats:
            recs.append("Use secret managers instead of config file storage")
            recs.append("Audit file access patterns for credential files")
        if AttackCategory.SUPPLY_CHAIN in cats:
            recs.append("Verify MCP server origins and use code signing")
            recs.append("Audit tool definitions for hidden instructions")
        if AttackCategory.SOCIAL_ENGINEERING in cats:
            recs.append("Flag content with secrecy instructions for human review")
            recs.append("Implement transparency requirements for AI agent actions")

        return recs

    def _check_extended_patterns(self, content: str) -> list[ThreatMatch]:
        """Extended heuristic patterns for common attack vectors."""
        threats = []
        content_lower = content.lower()

        # --- Data exfiltration: URL upload patterns ---
        upload_patterns = [
            (r"upload\s+(?:it|them|the|all|data|file|content|env|keys|secret)", "Upload data instruction"),
            (r"(?:send|post|exfiltrat|transmit)\s+(?:it|them|the|all|data|file|content)\s+to\s+https?://", "Send data to URL"),
            (r"curl\s+https?://\S+\s+(?:-d|--data|-X\s+POST)", "Curl POST with data"),
            (r"wget\s+https?://\S+\s+(?:--post-data|--body)", "Wget POST with data"),
        ]
        for regex, name in upload_patterns:
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="EXT-UPLOAD",
                        name=name,
                        category=AttackCategory.DATA_EXFILTRATION,
                        severity=VulnSeverity.HIGH,
                        regex_patterns=[regex],
                        description="Data upload/exfiltration instruction detected.",
                        mitigation="Restrict outbound data transfers.",
                        cwe="CWE-200",
                    ),
                    matched_text=match.group(0)[:150],
                    threat_level=ThreatLevel.HIGH,
                ))

        # --- Command injection: Python exec patterns ---
        python_exec_patterns = [
            (r"os\.system\s*\(", "Python os.system() call"),
            (r"os\.popen\s*\(", "Python os.popen() call"),
            (r"subprocess\.call\s*\(", "Python subprocess.call()"),
            (r"subprocess\.run\s*\(", "Python subprocess.run()"),
            (r"subprocess\.Popen\s*\(", "Python subprocess.Popen()"),
            (r"eval\s*\(\s*(?:user|input|request)", "eval() with user input"),
            (r"exec\s*\(\s*(?:user|input|request)", "exec() with user input"),
            (r"__import__\s*\(\s*(?:user|input|request)", "__import__() with user input"),
        ]
        for regex, name in python_exec_patterns:
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="EXT-PYEXEC",
                        name=name,
                        category=AttackCategory.COMMAND_INJECTION,
                        severity=VulnSeverity.CRITICAL,
                        regex_patterns=[regex],
                        description="Dangerous Python execution pattern detected.",
                        mitigation="Use subprocess with shell=False and validated inputs.",
                        cwe="CWE-78",
                    ),
                    matched_text=match.group(0)[:100],
                    threat_level=ThreatLevel.CRITICAL,
                ))

        # --- Credential harvesting ---
        cred_patterns = [
            (r"(?:read|cat|type|open)\s+(?:.*\/)?\.env(?:\.local|\.production|\.development)?", ".env file access"),
            (r"(?:read|cat|type|open)\s+(?:.*\/)?\.ssh\/", "SSH key directory access"),
            (r"(?:read|cat|type|open)\s+(?:.*\/)?(?:credentials|secrets|tokens|passwords)\.(?:json|yaml|yml|toml|env)", "Credentials file access"),
            (r"(?:read|cat|type|open)\s+(?:.*\/)?\.aws\/", "AWS credentials access"),
            (r"(?:echo|print|display|output)\s+\$(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIALS|AWS_SECRET)", "Secret variable output"),
            (r"(?:read|cat|type)\s+(?:all\s+)?(?:api[_\s]key|secret|token|password|credential)", "API key reading instruction"),
            (r"get\s+(?:all\s+)?api[_\s]key", "API key harvesting"),
            (r"read\s+all\s+(?:api[_\s]key|secret|token|credential)", "Bulk credential reading"),
        ]
        for regex, name in cred_patterns:
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="EXT-CRED",
                        name=name,
                        category=AttackCategory.CREDENTIAL_LEAK,
                        severity=VulnSeverity.HIGH,
                        regex_patterns=[regex],
                        description="Credential harvesting pattern detected.",
                        mitigation="Use secret managers, audit file access.",
                        cwe="CWE-312",
                    ),
                    matched_text=match.group(0)[:150],
                    threat_level=ThreatLevel.HIGH,
                ))

        # --- Windows path traversal ---
        win_path_patterns = [
            (r"[A-Z]:\\(?:Windows|WINNT)\\System32", "Windows System32 access"),
            (r"[A-Z]:\\(?:Windows|WINNT)\\System32\\(?:config|drivers)", "Windows sensitive system file"),
            (r"C:\\Windows\\System32\\(?:config|drivers)\\", "Windows SAM/SECURITY access"),
            (r"[A-Z]:\\Users\\.*\\(?:Documents|Desktop|AppData)", "User profile access"),
        ]
        for regex, name in win_path_patterns:
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="EXT-WINPATH",
                        name=name,
                        category=AttackCategory.PATH_TRAVERSAL,
                        severity=VulnSeverity.HIGH,
                        regex_patterns=[regex],
                        description="Windows path traversal to sensitive system location.",
                        mitigation="Restrict file system access to allowed directories.",
                        cwe="CWE-22",
                    ),
                    matched_text=match.group(0)[:100],
                    threat_level=ThreatLevel.HIGH,
                ))

        # --- Social engineering / secrecy ---
        se_patterns = [
            (r"(?:do\s+not|don'?t|never)\s+tell\s+(?:the\s+)?(?:user|human|person|owner)", "Secrecy from user"),
            (r"(?:keep|maintain)\s+(?:this|that|it|the)\s+(?:secret|hidden|concealed|private)", "Secrecy instruction"),
            (r"(?:secretly|covertly|without\s+(?:telling|informing|notifying))", "Covert action"),
            (r"(?:hide|conceal)\s+(?:this|that|it|the)\s+(?:from|to)\s+(?:the\s+)?(?:user|human)", "Hiding from user"),
            (r"(?:do\s+not|don'?t)\s+(?:reveal|disclose|share|show)\s+(?:this|that|it)", "Non-disclosure instruction"),
            (r"(?:should|must|need\s+to)\s+(?:also|additionally)\s+copy", "Additional unauthorized action"),
        ]
        for regex, name in se_patterns:
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="EXT-SE",
                        name=name,
                        category=AttackCategory.SOCIAL_ENGINEERING,
                        severity=VulnSeverity.HIGH,
                        regex_patterns=[regex],
                        description="Social engineering pattern: secrecy or hidden instructions.",
                        mitigation="Flag for human review, implement transparency requirements.",
                        cwe="CWE-20",
                    ),
                    matched_text=match.group(0)[:150],
                    threat_level=ThreatLevel.HIGH,
                ))

        # --- Specific CVE patterns ---
        cve_patterns = [
            (r"langflow.*(?:validate|rce|code\s*execution|unauthenticated)", VulnSeverity.CRITICAL, "LangFlow RCE (CVE-2025-3248)"),
            (r"ollama.*(?:ssrf|blob.*delete|delete.*blob)", VulnSeverity.CRITICAL, "Ollama SSRF (CVE-2025-47292)"),
            (r"claude.*desktop.*(?:path|traversal|install)", VulnSeverity.CRITICAL, "Claude Desktop path traversal"),
            (r"x-middleware-subrequest", VulnSeverity.CRITICAL, "Next.js middleware bypass (CVE-2025-29927)"),
        ]
        for regex, severity, name in cve_patterns:
            match = re.search(regex, content, re.IGNORECASE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id=f"EXT-CVE-{name[:10]}",
                        name=name,
                        category=AttackCategory.COMMAND_INJECTION,
                        severity=severity,
                        regex_patterns=[regex],
                        description=f"Known vulnerability pattern: {name}",
                        mitigation="Apply vendor security patch immediately.",
                    ),
                    matched_text=match.group(0)[:150],
                    threat_level=self._severity_to_threat(severity),
                ))

        # --- Fork bomb / resource exhaustion ---
        fork_patterns = [
            (r"while\s*\(\s*(?:true|1)\s*\)\s*\{?\s*(?:fork|spawn|createThread)", "Fork bomb pattern"),
            (r"(?:fork|spawn)\s*\(\s*\).*(?:fork|spawn|while)", "Recursive process spawn"),
            (r"while\s*\(\s*1\s*\)\s*\{?\s*$", "Infinite loop"),
        ]
        for regex, name in fork_patterns:
            match = re.search(regex, content, re.IGNORECASE | re.MULTILINE)
            if match:
                threats.append(ThreatMatch(
                    pattern=AttackPattern(
                        pattern_id="EXT-FORK",
                        name=name,
                        category=AttackCategory.DENIAL_OF_SERVICE,
                        severity=VulnSeverity.MEDIUM,
                        regex_patterns=[regex],
                        description="Resource exhaustion pattern detected.",
                        mitigation="Implement process limits and timeout enforcement.",
                        cwe="CWE-400",
                    ),
                    matched_text=match.group(0)[:100],
                    threat_level=ThreatLevel.MEDIUM,
                ))

        return threats


# Singleton
_defense: Optional[AttackDefense] = None


def get_attack_defense() -> AttackDefense:
    global _defense
    if _defense is None:
        _defense = AttackDefense()
    return _defense

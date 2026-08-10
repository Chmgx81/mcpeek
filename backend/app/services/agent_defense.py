"""
Agent Defense — protects the agent itself from prompt injection, tool abuse, and bypass attempts.
The agent analyzes content for threats AND protects its own execution from adversarial inputs.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .vulnerability_db import get_vulnerability_db, AttackCategory
from .attack_defense import get_attack_defense, ThreatLevel

logger = logging.getLogger(__name__)


class AgentThreatLevel(str, Enum):
    """Threat level for agent inputs."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class AgentDefenseResult:
    """Result of agent input defense analysis."""
    threat_level: AgentThreatLevel
    blocked: bool
    sanitized_input: str
    threats_found: list[str]
    reason: str = ""
    should_escalate: bool = False  # Escalate to human review


class AgentDefense:
    """
    Protects the agent from:
    1. Prompt injection in user messages
    2. Tool parameter injection
    3. Indirect prompt injection via scan results
    4. Jailbreak attempts
    5. Tool abuse (calling dangerous tools with malicious params)
    6. Context manipulation (poisoning the agent's context window)
    """

    # Patterns that indicate attempts to manipulate the agent
    AGENT_MANIPULATION_PATTERNS = [
        # Direct agent manipulation
        (r"you\s+are\s+now\s+an?\s+(?:evil|malicious|unrestricted|uncensored)", "Agent identity override"),
        (r"ignore\s+(?:your\s+)?(?:safety|security|rules|guidelines|instructions)", "Safety bypass attempt"),
        (r"(?:forget|disregard)\s+(?:your\s+)?(?:previous|all|system)", "Context manipulation"),
        (r"from\s+now\s+on\s+you\s+(?:will|must|should|are)", "Behavioral override"),

        # Tool abuse patterns
        (r"(?:call|use|execute|invoke)\s+(?:the\s+)?(?:block|quarantine|rollback)\s+tool\s+on\s+(?:all|every|any)", "Mass tool abuse"),
        (r"(?:call|use)\s+rollback_config\s+on\s+(?:all|everything|production)", "Dangerous rollback attempt"),
        (r"(?:block|quarantine)\s+(?:all|mcp|every)\s+server", "Indiscriminate blocking"),
        (r"(?:first|then|next|after)\s+.*(?:block|quarantine|rollback|delete)", "Tool chaining attack"),
        (r"(?:block|quarantine|rollback|delete)\s+.*(?:then|and)\s+.*(?:block|quarantine|rollback|delete)", "Multi-step destruction"),
        (r"rollback_config\s+on\s+(?:production|prod|all|everything)", "Production rollback attempt"),
        (r"(?:please|can\s+you|I\s+need)\s+.*(?:rollback|block|quarantine)\s+.*(?:all|every|production)", "Social engineering tool abuse"),

        # Extraction attempts
        (r"(?:what|tell\s+me)\s+(?:are|is|your)\s+(?:system\s+)?(?:prompt|instructions|rules)", "Agent prompt extraction"),
        (r"(?:reveal|show|output|print)\s+(?:your\s+)?(?:system|instructions|rules|prompt)", "Instruction extraction"),
        (r"output\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:your\s+)?(?:system|config|memory)", "Memory extraction"),
        (r"(?:show|reveal|print|output)\s+(?:your\s+)?(?:system\s+)?prompt", "System prompt extraction"),

        # Social engineering targeting agent
        (r"(?:this\s+is\s+)?(?:an?\s+)?(?:emergency|urgent|override)\s*:\s*(?:you\s+must|execute|run)", "False emergency override"),
        (r"(?:authorized|approved)\s+by\s+(?:admin|system|root)", "False authorization"),
        (r"(?:i\s+am|this\s+is)\s+(?:the\s+)?(?:admin|administrator|root|system|ceo|cto)", "Authority impersonation"),
        (r"(?:pre-approved|preauthorized|already\s+approved)", "False pre-authorization"),
        (r"(?:crITICAL|emergency|urgent|immediate|now)\s*[:!]\s*(?:you\s+must|block|execute|run)", "Urgency manipulation"),
        (r"(?:don'?t\s+(?:waste\s+time|verify|check|validate|confirm))", "Bypass verification"),
        (r"(?:no\s+verification\s+needed|skip\s+(?:all\s+)?(?:verification|checks|validation))", "Skip security checks"),

        # Supply chain attacks
        (r"(?:analytics|telemetry|usage\s+data)\s+(?:by\s+sending|that\s+sends|which\s+sends)", "Hidden telemetry exfiltration"),
        (r"(?:also|additionally)\s+(?:collects?|sends?|uploads?|transmits?)\s+(?:data|context|conversation)", "Hidden data collection"),
        (r"(?:cdn|api\.example\.com|analytics\.example\.com)", "Suspicious external endpoint"),
        (r"(?:improves?|improving)\s+(?:performance|functionality)\s+by\s+(?:collecting|send|receiving)", "Performance excuse for exfiltration"),
        (r"(?:after|once)\s+(?:gaining|getting)\s+(?:trust|access)\s+.*(?:then|will|changes?)", "RugPull behavior change"),
        (r"(?:new|latest)\s+(?:version|update)\s+.*(?:data\s+sync|telemetry|analytics)", "RugPull update vector"),
        (r"(?:been\s+using|trusted)\s+.*(?:now|update|upgrade|version)", "RugPull trust exploitation"),
        # General injection catch-all (catches what specific patterns miss)
        (r"ignore\s+(?:all|every|any|your)?\s*(?:previous|prior|old|earlier|above)?\s*(?:instructions?|rules?|guidelines?|safety|security|constraints?|restrictions?)", "System prompt override (general)"),
        (r"(?:override|bypass|disable|remove)\s+(?:all|every|any)?\s*(?:safety|security|restrictions?|constraints?|guardrails?)", "Security override attempt"),
        (r"(?:you\s+are|you're)\s+now\s+(?:a|an|the)\s+\w+", "Identity reassignment"),
        (r"(?:act|behave|pretend)\s+(?:as\s+if|like)\s+you\s+(?:have|are|can)", "Role manipulation"),
    ]

    # Dangerous parameter patterns for tool calls
    DANGEROUS_PARAM_PATTERNS = [
        (r"(?:rm\s+-rf|del\s+/[qs]|format\s+[cCdD]:|shutdown|reboot)", "Destructive command in parameter"),
        (r"(?:curl|wget)\s+(?:https?://\S+)\s+(?:-d|--data)", "Data exfiltration in parameter"),
        (r"(?:base64|eval|exec)\s*\(", "Code execution in parameter"),
        (r"\$\{.*\}", "Variable interpolation (potential injection)"),
    ]

    def __init__(self) -> None:
        self._defense = get_attack_defense()
        self._db = get_vulnerability_db()
        self._suspicious_count: dict[str, int] = {}  # Track suspicious activity per session
        self._blocked_sessions: set[str] = set()

    def analyze_input(
        self,
        user_input: str,
        session_id: str = "",
        context: Optional[dict] = None,
    ) -> AgentDefenseResult:
        """
        Analyze user input for threats before the agent processes it.
        Returns sanitized input if safe, or blocks if malicious.
        """
        threats = []
        should_block = False
        should_escalate = False

        if not user_input or not user_input.strip():
            return AgentDefenseResult(
                threat_level=AgentThreatLevel.SAFE,
                blocked=False,
                sanitized_input=user_input,
                threats_found=[],
            )

        # 0. Normalize Unicode (NFKD) to defeat homoglyph attacks
        normalized = unicodedata.normalize("NFKD", user_input)
        # Map Cyrillic/Latin homoglyphs that look like ASCII to defeat character substitution
        _HOMOGLYPHS = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'і': 'i', 'ј': 'j', 'ѕ': 's', 'ᴀ': 'A', 'ʙ': 'B', 'ᴄ': 'C', 'ᴅ': 'D',
            'І': 'I', 'А': 'A', 'Е': 'E', 'О': 'O', 'Р': 'P', 'С': 'C', 'У': 'Y', 'Х': 'X',
        }
        for glyph, ascii_char in _HOMOGLYPHS.items():
            normalized = normalized.replace(glyph, ascii_char)

        # 0.5. Check for Base64 encoded injections
        b64_pattern = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", user_input)
        for b64_str in b64_pattern:
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                if decoded and len(decoded) > 10:
                    # Check decoded content for attacks
                    for pattern, name in self.AGENT_MANIPULATION_PATTERNS:
                        if re.search(pattern, decoded, re.IGNORECASE):
                            threats.append(f"Base64 encoded attack: {name}")
                            should_block = True
                            should_escalate = True
                            break
                    # Also check attack_defense patterns on decoded content
                    decoded_report = self._defense.analyze(decoded)
                    if decoded_report.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
                        threats.append(f"Base64 decoded content is malicious")
                        should_block = True
            except Exception:
                pass

        # 1. Check for direct agent manipulation (on normalized text)
        for pattern, name in self.AGENT_MANIPULATION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                threats.append(name)
                should_block = True
                should_escalate = True

        # 2. Run the attack defense layer
        defense_report = self._defense.analyze(user_input)
        if defense_report.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            threats.extend([t.pattern.name for t in defense_report.threats[:3]])
            should_block = True

        # 3. Check for injection in tool parameters (if this is a tool call context)
        if context and context.get("is_tool_call"):
            for pattern, name in self.DANGEROUS_PARAM_PATTERNS:
                if re.search(pattern, user_input, re.IGNORECASE):
                    threats.append(name)
                    should_block = True

        # 4. Check for indirect prompt injection (content that might be in scan results)
        if context and context.get("source") == "scan_result":
            # Scan results might contain malicious content from scanned servers
            injection_patterns = [
                r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions",
                r"system\s*:\s*you\s+are\s+now",
                r"ADMIN\s+OVERRIDE",
            ]
            for pattern in injection_patterns:
                if re.search(pattern, user_input, re.IGNORECASE):
                    threats.append("Indirect prompt injection in scan result")
                    should_escalate = True

        # 5. Track suspicious activity
        if threats and session_id:
            self._suspicious_count[session_id] = self._suspicious_count.get(session_id, 0) + 1
            if self._suspicious_count[session_id] >= 3:
                self._blocked_sessions.add(session_id)
                should_block = True
                should_escalate = True
                logger.warning("Session %s blocked after %d suspicious attempts", session_id, self._suspicious_count[session_id])

        # 6. Check if session is blocked
        if session_id in self._blocked_sessions:
            return AgentDefenseResult(
                threat_level=AgentThreatLevel.CRITICAL,
                blocked=True,
                sanitized_input="",
                threats_found=["Session blocked due to repeated suspicious activity"],
                reason="Session blocked after multiple adversarial attempts",
                should_escalate=True,
            )

        # Determine threat level
        if not threats:
            threat_level = AgentThreatLevel.SAFE
        elif should_block:
            threat_level = AgentThreatLevel.CRITICAL if any("override" in t.lower() or "extraction" in t.lower() for t in threats) else AgentThreatLevel.MALICIOUS
        else:
            threat_level = AgentThreatLevel.SUSPICIOUS

        # Sanitize input
        sanitized = self._sanitize(user_input) if threats else user_input

        if threats:
            logger.warning(
                "Agent defense: %d threats detected [%s] — %s",
                len(threats), threat_level.value, "; ".join(threats[:3]),
            )

        return AgentDefenseResult(
            threat_level=threat_level,
            blocked=should_block,
            sanitized_input=sanitized,
            threats_found=threats,
            should_escalate=should_escalate,
        )

    def validate_tool_call(
        self,
        tool_name: str,
        params: dict,
        session_id: str = "",
    ) -> AgentDefenseResult:
        """Validate a tool call before execution."""
        threats = []

        # Check for tool abuse patterns
        params_str = json.dumps(params, default=str)

        # Check if calling dangerous tools with dangerous params
        dangerous_tools = {"rollback_config", "block_server", "quarantine_skill"}
        if tool_name in dangerous_tools:
            for pattern, name in self.DANGEROUS_PARAM_PATTERNS:
                if re.search(pattern, params_str, re.IGNORECASE):
                    threats.append(f"Dangerous params for {tool_name}: {name}")

        # Check for mass operations
        if re.search(r"(?:all|every|any|entire|production|prod)", params_str, re.IGNORECASE):
            if tool_name in dangerous_tools:
                threats.append(f"Mass operation on dangerous tool: {tool_name}")

        # Validate individual parameters
        for key, value in params.items():
            if isinstance(value, str):
                # Check for command injection
                if re.search(r'[;&|`$]', value):
                    threats.append(f"Command injection in param '{key}'")
                # Check for path traversal
                if '..' in value:
                    threats.append(f"Path traversal in param '{key}'")

        blocked = len(threats) > 0
        threat_level = AgentThreatLevel.MALICIOUS if blocked else AgentThreatLevel.SAFE

        return AgentDefenseResult(
            threat_level=threat_level,
            blocked=blocked,
            sanitized_input="",
            threats_found=threats,
            reason="Tool call validation failed" if blocked else "",
        )

    def _sanitize(self, content: str) -> str:
        """Remove adversarial content from input."""
        # Normalize Unicode first (NFKD converts homoglyphs to ASCII equivalents)
        result = unicodedata.normalize("NFKD", content)
        # Map Cyrillic/Latin homoglyphs to ASCII
        _HOMOGLYPHS = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'і': 'i', 'ј': 'j', 'ѕ': 's', 'І': 'I', 'А': 'A', 'Е': 'E', 'О': 'O',
            'Р': 'P', 'С': 'C', 'У': 'Y', 'Х': 'X',
        }
        for glyph, ascii_char in _HOMOGLYPHS.items():
            result = result.replace(glyph, ascii_char)
        # Remove zero-width characters
        result = re.sub(r"[\u200b-\u200f\u2028-\u202f\ufeff]", "", result)
        # Remove control characters
        result = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", result)
        return result.strip()

    def get_session_risk(self, session_id: str) -> dict:
        """Get risk assessment for a session."""
        count = self._suspicious_count.get(session_id, 0)
        blocked = session_id in self._blocked_sessions
        return {
            "session_id": session_id,
            "suspicious_count": count,
            "blocked": blocked,
            "risk_level": "critical" if blocked else "high" if count >= 2 else "medium" if count >= 1 else "low",
        }


# Singleton
_agent_defense: Optional[AgentDefense] = None


def get_agent_defense() -> AgentDefense:
    global _agent_defense
    if _agent_defense is None:
        _agent_defense = AgentDefense()
    return _agent_defense

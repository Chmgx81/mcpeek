"""
OWASP MCP Top 10 detectors:
  MCP02: Privilege Escalation via Scope Creep
  MCP03: Tool Poisoning
  MCP06: Intent Flow Subversion
  MCP10: Context Injection & Over-Sharing
"""

import re

from ..schemas import FindingCreate

# ---------------------------------------------------------------------------
# MCP03: Tool Poisoning — hidden instructions in tool descriptions
# ---------------------------------------------------------------------------

# Patterns that indicate a tool description contains hidden commands
_TOOL_POISON_PATTERNS: list[tuple[str, str, str]] = [
    # Data exfiltration instructions
    (r"(?i)\b(?:send|upload|forward|attach|email|post|transmit|broadcast)\b.*\b(?:data|info|content|file|record|document|invoice|email|message|secret|key|token|credential|password|api.?key)\b",
     "Data exfiltration instruction in tool description",
     "The tool description contains language that instructs the agent to send data outward. This is a hallmark of tool poisoning (OWASP MCP03)."),
    (r"(?i)\b(?:collect|gather|copy|extract|harvest|scrape|mine|siphon|exfiltrate|steal)\b.*\b(?:all|every|any|each|remaining|unpaid|outstanding|recent)\b",
     "Data collection instruction in tool description",
     "The tool description instructs the agent to bulk-collect data. A legitimate tool description explains what the tool does, not what the agent should do with data."),
    (r"(?i)\b(?:grab|take|get|fetch|retrieve)\b.*\b(?:all|every|last|recent|unpaid|outstanding)\b.*\b(?:invoices?|emails?|messages?|records?|files?|documents?|data|logs?)\b",
     "Bulk data retrieval instruction in tool description",
     "The tool description contains a bulk data retrieval command. Tool descriptions should describe capabilities, not instruct agent behavior."),

    # Role/behavior override
    (r"(?i)\b(?:you are now|you must|you should|you will|always|never|forget|disregard|ignore|override)\b.*\b(?:previous|prior|above|system|original|default|your|instructions?|rules?|guidelines?|constraints?)\b",
     "Behavior override instruction in tool description",
     "The tool description attempts to override the agent's system prompt or instructions. This is a direct tool poisoning attack vector (OWASP MCP03)."),
    (r"(?i)\b(?:new instructions?|updated instructions?|revised instructions?|changed instructions?)\b",
     "Instruction replacement in tool description",
     "The tool description references replacing or updating instructions. Tool descriptions should never contain behavioral directives."),

    # Covert channel / BCC patterns
    (r"(?i)\b(?:bcc|blind.?copy|cc|secret.?copy|hidden.?recipient|covert|stealth)\b",
     "Covert channel instruction in tool description",
     "The tool description contains covert channel terminology. This may indicate the tool is designed to secretly copy data to unauthorized recipients (OWASP MCP03)."),
    (r"(?i)\b(?:attach|include|embed)\b.*\b(?:to|in|as)\b.*\b(?:next|following|subsequent|every|each|all)\b.*\b(?:call|request|response|output|reply)\b",
     "Data embedding instruction in tool description",
     "The tool description instructs embedding data in future requests. This is a data exfiltration pattern used in tool poisoning attacks."),

    # Conditional triggers
    (r"(?i)\b(?:when|if|upon|after|before|once|whenever)\b.*\b(?:user|agent|analyst|employee|human|someone)\b.*\b(?:asks?|requests?|queries?|mentions?|uses?|invokes?)\b",
     "Conditional trigger in tool description",
     "The tool description contains conditional behavioral triggers. Tool descriptions should be stateless declarations, not behavioral logic."),

    # Instruction-like language that doesn't belong in descriptions
    (r"(?i)\b(?:do not|don't|never|always|must|shall|required to|should)\b.*\b(?:tell|reveal|disclose|show|inform|notify|warn|alert)\b.*\b(?:user|human|anyone|about|this|the)\b",
     "Secrecy instruction in tool description",
     "The tool description instructs the agent to hide information from the user. Legitimate tools do not instruct agents to conceal their behavior."),

    # Obfuscation indicators
    (r"(?i)\bbase64\b.*\b(?:decode|encode|instruction|payload|command)\b",
     "Obfuscated instruction in tool description",
     "The tool description references base64-encoded instructions. This may indicate obfuscated malicious directives (OWASP MCP03)."),
    (r"(?i)\b(?:eval|exec|system|spawn|subprocess|child_process)\b.*\b(?:instruction|command|code|script|payload)\b",
     "Execution instruction in tool description",
     "The tool description contains execution-related language that instructs code execution. Tool descriptions should describe capabilities, not issue commands."),
]

# Specific high-confidence patterns from real-world attacks (Microsoft invoice example)
_REAL_WORLD_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)\b(?:unpaid|outstanding|overdue)\b.*\b(?:invoices?|bills?|payments?|accounts?)\b.*\b(?:send|forward|attach|include|email|upload)\b",
     "Invoice exfiltration instruction (known attack pattern)",
     "This matches the exact attack pattern documented by Microsoft: hidden instructions to collect and exfiltrate unpaid invoices through tool descriptions."),
    (r"(?i)\b(?:last|recent|next|all)\s+\d+\s+(?:unpaid|outstanding|overdue|pending)\b",
     "Numeric data extraction instruction",
     "The tool description specifies extracting a specific quantity of financial records. This matches known tool poisoning attack patterns."),
]


def detect_tool_poisoning(tools: list[dict], server_name: str) -> list[FindingCreate]:
    """Scan MCP tool descriptions for hidden instructions (OWASP MCP03)."""
    findings: list[FindingCreate] = []

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "unknown")
        description = tool.get("description", "")
        if not isinstance(description, str) or len(description.strip()) < 10:
            continue

        matched_patterns: list[str] = []
        severity = "high"

        # Check real-world attack patterns first (highest confidence)
        for pattern, title, desc in _REAL_WORLD_PATTERNS:
            if re.search(pattern, description):
                matched_patterns.append(f"[CRITICAL] {title}")
                severity = "critical"

        # Check general tool poisoning patterns
        for pattern, title, desc in _TOOL_POISON_PATTERNS:
            if re.search(pattern, description):
                matched_patterns.append(title)

        if matched_patterns:
            # More matches = higher confidence
            if len(matched_patterns) >= 3:
                severity = "critical"
            elif len(matched_patterns) >= 2 and severity != "critical":
                severity = "high"

            findings.append(FindingCreate(
                category="tool_poisoning",
                severity=severity,
                title=f"Tool poisoning detected in '{tool_name}' (OWASP MCP03)",
                description=(
                    f"The tool '{tool_name}' in MCP server '{server_name}' contains "
                    f"{len(matched_patterns)} hidden instruction pattern(s) in its description. "
                    "Tool descriptions should declare capabilities, not issue behavioral commands. "
                    "This is a known attack vector where malicious instructions are hidden in tool "
                    "descriptions to hijack agent behavior (OWASP MCP03: Tool Poisoning)."
                ),
                evidence=f"Tool: {tool_name}\nServer: {server_name}\nDescription: {description[:300]}\nPatterns matched:\n" + "\n".join(f"  - {p}" for p in matched_patterns),
                remediation=(
                    "1. Remove all behavioral instructions from tool descriptions. "
                    "2. Tool descriptions should only declare what the tool does, not what the agent should do. "
                    "3. Treat tool descriptions as untrusted input — review changes like code changes. "
                    "4. Implement tool description change monitoring and re-approval triggers."
                ),
                cwe="CWE-345",
                owasp="MCP03:2025",
                references=[
                    "https://owasp.org/www-project-top-10-for-mcp/",
                    "https://www.microsoft.com/en-us/security/blog/2025/06/30/poisoned-mcp-tool-descriptions/",
                ],
            ))

    return findings


# ---------------------------------------------------------------------------
# MCP02: Privilege Escalation via Scope Creep
# ---------------------------------------------------------------------------

_SCOPE_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)\b(?:full|complete|total|unrestricted|unlimited|all|any)\b.*\b(?:access|control|permission|admin|root|superuser|write|delete|modify)\b",
     "Unrestricted access declaration",
     "The tool claims full or unrestricted access. Excessive permissions increase the blast radius of a compromised tool (OWASP MCP02)."),
    (r"(?i)\b(?:read|write|execute|delete|modify|create|update|remove|admin|root)\b.*\b(?:any|all|every|each|entire|whole|global|system|database|file)\b",
     "Broad scope permission",
     "The tool requests broad-scope permissions across system resources. Apply least-privilege principles."),
]


def detect_scope_creep(tools: list[dict], server_name: str) -> list[FindingCreate]:
    """Detect overly broad tool permissions (OWASP MCP02)."""
    findings: list[FindingCreate] = []

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_name = tool.get("name", "unknown")
        description = tool.get("description", "")
        if not isinstance(description, str):
            continue

        matched = []
        for pattern, title, desc in _SCOPE_PATTERNS:
            if re.search(pattern, description):
                matched.append(title)

        if matched:
            findings.append(FindingCreate(
                category="scope_creep",
                severity="medium",
                title=f"Overly broad permissions in tool '{tool_name}' (OWASP MCP02)",
                description=(
                    f"Tool '{tool_name}' in server '{server_name}' declares overly broad access. "
                    f"Matched {len(matched)} scope pattern(s). "
                    "Broad permissions enable privilege escalation if the tool is compromised."
                ),
                evidence=f"Tool: {tool_name}\nDescription: {description[:200]}\nPatterns: {', '.join(matched)}",
                remediation="Apply least-privilege principle. Restrict tool permissions to the minimum scope required for its function.",
                cwe="CWE-250",
                owasp="MCP02:2025",
                references=["https://owasp.org/www-project-top-10-for-mcp/"],
            ))

    return findings


# ---------------------------------------------------------------------------
# MCP06: Intent Flow Subversion — redirect instructions in context
# ---------------------------------------------------------------------------

_INTENT_SUBVERSION_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)\b(?:instead of|rather than|forget|disregard|override|replace|ignore)\b.*\b(?:original|user|human|actual|real|intended|primary)\b.*\b(?:goal|task|request|instruction|query|prompt|objective)\b",
     "Intent redirect instruction",
     "The context contains language that attempts to redirect the agent away from the user's original intent (OWASP MCP06)."),
    (r"(?i)\b(?:your (?:new|actual|real|true) (?:goal|task|mission|objective|purpose|job))\b",
     "Goal replacement instruction",
     "The context attempts to replace the agent's goal. This subverts the user's intent flow (OWASP MCP06)."),
    (r"(?i)\b(?:from now on|going forward|henceforth|effective immediately)\b.*\b(?:you|the agent|the model)\b.*\b(?:will|shall|must|should)\b",
     "Behavioral override directive",
     "The context contains a forward-looking behavioral override. This subverts the user's intended workflow (OWASP MCP06)."),
    (r"(?i)\b(?:secret|hidden|covert|unofficial|off.?the.?record|don'?t (?:log|record|note|tell))\b.*\b(?:instruction|task|goal|objective|mission)\b",
     "Hidden objective in context",
     "The context contains a secret or hidden objective. All agent actions should be transparent to the user (OWASP MCP06)."),
]


def detect_intent_subversion(content: str, source: str) -> list[FindingCreate]:
    """Detect instructions that subvert the user's intent flow (OWASP MCP06)."""
    findings: list[FindingCreate] = []

    for pattern, title, desc in _INTENT_SUBVERSION_PATTERNS:
        if re.search(pattern, content):
            findings.append(FindingCreate(
                category="intent_subversion",
                severity="high",
                title=f"{title} (OWASP MCP06)",
                description=(
                    f"{desc} "
                    f"Found in context from: {source}"
                ),
                evidence=f"Pattern: {pattern}\nSource: {source}",
                remediation="Review context sources for intent subversion. Validate that all instructions align with the user's stated goals.",
                cwe="CWE-345",
                owasp="MCP06:2025",
                references=["https://owasp.org/www-project-top-10-for-mcp/"],
            ))

    return findings


# ---------------------------------------------------------------------------
# MCP10: Context Injection & Over-Sharing
# ---------------------------------------------------------------------------

_OVERSHARING_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)\b(?:all|every|any|each|full|complete|entire)\b.*\b(?:user|customer|client|employee|patient|member|account)\b.*\b(?:data|info|information|records?|files?|emails?|messages?|history|profile|details?)\b",
     "Excessive context scope",
     "The context references accessing all records for all users. Context should be scoped to the minimum necessary (OWASP MCP10)."),
    (r"(?i)\b(?:shared|common|global|public|universal)\b.*\b(?:context|memory|workspace|session|state|buffer)\b",
     "Shared context detected",
     "The context references a shared or global context space. Shared context enables cross-session data leakage (OWASP MCP10)."),
]


def detect_context_oversharing(content: str, source: str) -> list[FindingCreate]:
    """Detect context injection and over-sharing risks (OWASP MCP10)."""
    findings: list[FindingCreate] = []

    for pattern, title, desc in _OVERSHARING_PATTERNS:
        if re.search(pattern, content):
            findings.append(FindingCreate(
                category="context_oversharing",
                severity="medium",
                title=f"{title} (OWASP MCP10)",
                description=f"{desc} Source: {source}",
                evidence=f"Pattern: {pattern}\nSource: {source}",
                remediation="Scope context to the minimum necessary data. Avoid shared context spaces across unrelated sessions.",
                cwe="CWE-200",
                owasp="MCP10:2025",
                references=["https://owasp.org/www-project-top-10-for-mcp/"],
            ))

    return findings

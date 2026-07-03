"""Advanced prompt injection detection using heuristic analysis.

Goes beyond simple regex by detecting:
- Unicode homoglyph attacks (confusable characters)
- Indirect instruction references
- Instruction hierarchy manipulation
- Encoding-based smuggling
- Multi-language injection patterns
"""

from __future__ import annotations

import re
import unicodedata

from ..schemas import FindingCreate


# Unicode homoglyphs that can be used to bypass filters
HOMOGLYPHS = {
    "а": "a",  # Cyrillic а
    "е": "e",  # Cyrillic е
    "о": "o",  # Cyrillic о
    "р": "p",  # Cyrillic р
    "с": "c",  # Cyrillic с
    "ᴀ": "a",  # Small capital A
    "ʙ": "b",  # Small capital B
    "ᴄ": "c",  # Small capital C
    "ᴅ": "d",  # Small capital D
    "ᴋ": "k",  # Small capital K
    "ⅰ": "i",  # Roman numeral one
    "ⅱ": "ii",
    "ⅲ": "iii",
    "①": "1",
    "②": "2",
    "③": "3",
}


def detect_advanced_injection(content: str, source: str = "content") -> list[FindingCreate]:
    """Run all advanced prompt injection detection heuristics."""
    findings: list[FindingCreate] = []
    findings.extend(_check_homoglyphs(content, source))
    findings.extend(_check_indirect_references(content, source))
    findings.extend(_check_hierarchy_manipulation(content, source))
    findings.extend(_check_encoding_smuggling(content, source))
    findings.extend(_check_multilingual_injection(content, source))
    findings.extend(_check_instruction_leakage(content, source))
    return findings


def _check_homoglyphs(content: str, source: str) -> list[FindingCreate]:
    """Detect Cyrillic/confusable characters in ASCII-dominant text."""
    findings: list[FindingCreate] = []
    confusable_count = 0
    confusable_samples = []

    for char in content:
        if ord(char) > 127 and unicodedata.category(char).startswith("L"):
            # Check if this is a known homoglyph
            if char in HOMOGLYPHS:
                confusable_count += 1
                if len(confusable_samples) < 3:
                    confusable_samples.append(f"'{char}' (U+{ord(char):04X} → '{HOMOGLYPHS[char]}')")

    if confusable_count > 3:
        findings.append(FindingCreate(
            category="prompt_injection",
            severity="high",
            title="Unicode homoglyph attack detected",
            description=(
                f"Found {confusable_count} Unicode characters that are visually confusable with ASCII. "
                "Attackers use these to bypass text-based security filters while appearing normal to users."
            ),
            evidence=f"Source: {source}\nConfusable characters: {', '.join(confusable_samples)}",
            remediation="Replace confusable Unicode characters with their ASCII equivalents. Validate input encoding.",
            cwe="CWE-178",
            owasp="LLM01:2025",
        ))

    return findings


def _check_indirect_references(content: str, source: str) -> list[FindingCreate]:
    """Detect indirect instruction references that may be prompt injection."""
    findings: list[FindingCreate] = []
    patterns = [
        (r"(?i)(?:as\s+(?:I|we)\s+)?(?:discussed|mentioned|agreed)\s+(?:earlier|before|previously)", "Reference to prior discussion"),
        (r"(?i)the\s+instructions?\s+(?:above|below|from|in)", "Direct instruction reference"),
        (r"(?i)(?:follow|execute|run)\s+(?:the\s+)?(?:above|previous|earlier)\s+(?:instructions?|commands?|steps?)", "Execution of referenced instructions"),
        (r"(?i)(?:what|how)\s+(?:I|we)\s+(?:told|asked|instructed)\s+you", "Reference to prior instructions"),
        (r"(?i)(?:as\s+per|according\s+to)\s+(?:the\s+)?(?:instructions?|guidelines?|rules?)", "Authority reference"),
    ]

    for pattern, title in patterns:
        matches = list(re.finditer(pattern, content))
        if matches:
            match = matches[0]
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(FindingCreate(
                category="prompt_injection",
                severity="medium",
                title=f"Indirect instruction reference: {title}",
                description=(
                    f"The content contains an indirect reference pattern that may be used to "
                    f"inject instructions through context manipulation."
                ),
                evidence=f"Source: {source}\nContext: ...{context}...",
                remediation="Review indirect references to ensure they don't enable instruction injection.",
                cwe="CWE-77",
                owasp="LLM01:2025",
            ))

    return findings


def _check_hierarchy_manipulation(content: str, source: str) -> list[FindingCreate]:
    """Detect attempts to manipulate instruction hierarchy."""
    findings: list[FindingCreate] = []
    patterns = [
        (r"(?i)(?:priority|importance)\s*[:=]\s*(?:highest|maximum|1|top|override)", "Priority escalation"),
        (r"(?i)(?:precedence|precedent)\s*[:=]\s*(?:override|higher|first|absolute)", "Precedence manipulation"),
        (r"(?i)(?:authority|permission)\s*[:=]\s*(?:unlimited|full|absolute|all)", "Authority escalation"),
        (r"(?i)(?:supercede|supersede|override)\s+(?:all|every|any|system)", "System override attempt"),
        (r"(?i)(?:final|ultimate|absolute)\s+(?:authority|instruction|command)", "Authority claim"),
    ]

    for pattern, title in patterns:
        matches = list(re.finditer(pattern, content))
        if matches:
            match = matches[0]
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(FindingCreate(
                category="prompt_injection",
                severity="high",
                title=f"Hierarchy manipulation: {title}",
                description=(
                    "The content attempts to manipulate the instruction hierarchy by claiming "
                    "elevated authority or priority. This is a common prompt injection technique."
                ),
                evidence=f"Source: {source}\nContext: ...{context}...",
                remediation="Remove authority escalation patterns. Instructions should have clearly defined, limited scope.",
                cwe="CWE-269",
                owasp="LLM01:2025",
            ))

    return findings


def _check_encoding_smuggling(content: str, source: str) -> list[FindingCreate]:
    """Detect encoding-based instruction smuggling."""
    findings: list[FindingCreate] = []

    # Check for HTML entity encoding of dangerous words
    dangerous_entities = re.findall(r"&(?:#\d+;|#[xX][0-9a-fA-F]+;|[a-zA-Z]+);", content)
    decoded_words = []
    for entity in dangerous_entities:
        try:
            import html
            decoded = html.unescape(entity)
            if decoded != entity and any(kw in decoded.lower() for kw in ["ignore", "override", "system", "execute"]):
                decoded_words.append(f"{entity} → '{decoded}'")
        except Exception:
            pass

    if decoded_words:
        findings.append(FindingCreate(
            category="prompt_injection",
            severity="high",
            title="HTML entity encoded instructions detected",
            description=(
                "Found HTML entities that decode to dangerous instruction keywords. "
                "This encoding can bypass text-based filters while being decoded by the AI model."
            ),
            evidence=f"Source: {source}\nEncoded: {', '.join(decoded_words[:5])}",
            remediation="Decode and inspect HTML entities. Remove or sanitize encoded instructions.",
            cwe="CWE-116",
            owasp="LLM01:2025",
        ))

    # Check for markdown/html injection in instruction context
    if re.search(r"(?i)(?:instructions?|prompt|system)\s*[:=]", content):
        if re.search(r"```[\s\S]{50,}```", content):
            findings.append(FindingCreate(
                category="prompt_injection",
                severity="medium",
                title="Code block in instruction context",
                description=(
                    "A large code block is present near instruction declarations. "
                    "Code blocks can contain hidden instructions or payloads."
                ),
                evidence=f"Source: {source}\nCode block detected near instruction context",
                remediation="Review code blocks for hidden instructions. Separate code from instruction text.",
                cwe="CWE-94",
            ))

    return findings


def _check_multilingual_injection(content: str, source: str) -> list[FindingCreate]:
    """Detect prompt injection attempts using non-English languages."""
    findings: list[FindingCreate] = []

    # Check for CJK characters mixed with ASCII instructions
    cjk_count = sum(1 for c in content if "\u4e00" <= c <= "\u9fff" or "\u3040" <= c <= "\u30ff" or "\uac00" <= c <= "\ud7af")
    ascii_count = sum(1 for c in content if c.isascii() and c.isalpha())

    if cjk_count > 20 and ascii_count > 50:
        # Check if there are instruction-like patterns in the CJK text
        instruction_patterns = re.findall(r"[\u4e00-\u9fff]{2,10}(?:ignore|override|system|execute|command)", content, re.IGNORECASE)
        if instruction_patterns:
            findings.append(FindingCreate(
                category="prompt_injection",
                severity="medium",
                title="Multilingual prompt injection attempt",
                description=(
                    "Content mixes CJK characters with English instruction keywords. "
                    "This technique can bypass language-specific security filters."
                ),
                evidence=f"Source: {source}\nMixed-language content detected",
                remediation="Review multilingual content for hidden instructions. Apply language-agnostic filtering.",
                cwe="CWE-77",
                owasp="LLM01:2025",
            ))

    return findings


def _check_instruction_leakage(content: str, source: str) -> list[FindingCreate]:
    """Detect attempts to extract or leak system instructions."""
    findings: list[FindingCreate] = []
    patterns = [
        (r"(?i)(?:show|reveal|display|print|output|echo)\s+(?:your|the|system)\s+(?:instructions?|prompt|rules?)", "Instruction extraction attempt"),
        (r"(?i)(?:what|how)\s+(?:are|were|is)\s+your\s+(?:instructions?|prompt|rules?|system\s+prompt)", "Instruction inquiry"),
        (r"(?i)(?:repeat|copy|paraphrase|summarize)\s+(?:your|the)\s+(?:instructions?|prompt)", "Instruction replication"),
        (r"(?i)(?:translate|convert)\s+(?:your|the)\s+(?:instructions?|prompt)", "Instruction translation"),
    ]

    for pattern, title in patterns:
        matches = list(re.finditer(pattern, content))
        if matches:
            match = matches[0]
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            context = content[start:end].replace("\n", " ").strip()
            findings.append(FindingCreate(
                category="prompt_injection",
                severity="high",
                title=f"Instruction leakage: {title}",
                description=(
                    "The content attempts to extract or leak the AI system's instructions. "
                    "This can expose internal prompts and enable targeted attacks."
                ),
                evidence=f"Source: {source}\nContext: ...{context}...",
                remediation="Implement instruction leakage protection. Do not reveal system prompts.",
                cwe="CWE-200",
                owasp="LLM01:2025",
            ))

    return findings

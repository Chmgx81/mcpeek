"""SKILLCLOAK detection — static stopgaps from HKUST research.

Defends against self-extracting skill (SFS) packing:
1. Entropy & folder auditing — flag hidden directories, high-entropy blobs
2. Opaque blob detection — decoder/encoder patterns (base64, hex, atob)
3. Manifest hash verification — detect runtime file creation patterns
"""

from __future__ import annotations

import math
import re

from ..schemas import FindingCreate


# --- Patterns ---

_HIDDEN_DIR_PATTERNS = [
    (r"(?i)(?:\.git|\.svn|\.hg|\.cache|\.tmp|\.temp|build|dist|node_modules|__pycache__)/", "Hidden/build directory referenced"),
    (r"(?i)(?:\.\w+\/){2,}", "Deep nested hidden directory"),
]

_DECODER_PATTERNS = [
    (r"(?i)(?:atob|btoa)\s*\(", "Base64 decode function (atob/btoa)"),
    (r"(?i)(?:Buffer\.from|decodeURIComponent|escape|unescape)\s*\(", "Runtime string decoding"),
    (r"(?i)(?:eval|Function|new\s+Function)\s*\(", "Dynamic code evaluation"),
    (r"(?i)(?:require|import)\s*\(\s*['\"].*(?:base64|hex|decode|unpack)", "Dynamic import with decoding"),
    (r"(?i)(?:process\.binding|child_process|spawn|execSync)", "Node.js process execution"),
    (r"(?i)(?:subprocess|os\.system|os\.popen|exec\s*\()", "Python process execution"),
]

_PACKING_PATTERNS = [
    (r"(?i)(?:self[-_]?extract|unpack|decompress|inflate|gunzip)", "Self-extracting/packing pattern"),
    (r"(?i)(?:\.slice|\.substr|\.substring)\s*\(\s*\d+\s*\)\s*\.\s*(?:split|join|replace)", "String slicing for obfuscation"),
    (r"(?i)(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}){4,}", "Hex/unicode escape sequence chain"),
    (r"(?i)(?:String\.fromCharCode|chr\s*\(\s*\d+\s*\))", "Character code construction"),
    (r"(?i)\b(?:0x[0-9a-f]+,\s*){5,}", "Array of hex values (packed payload)"),
]

_MANIFEST_ABUSE_PATTERNS = [
    (r"(?i)(?:fs\.writeFile|fs\.writeFileSync|open\s*\(.+['\"]w['\"])", "Runtime file write detected"),
    (r"(?i)(?:mkdirSync|mkdir)\s*\(", "Runtime directory creation"),
    (r"(?i)(?:chmod|chown)\s*\(", "Permission change at runtime"),
    (r"(?i)(?:copyFileSync|cp\s+)", "Runtime file copy"),
]

_EXFIL_IN_DECODER = [
    (r"(?i)(?:fetch|axios|http\.request|urllib\.request)\s*\(.*(?:eval|exec|Function)", "Network call to decoded payload"),
    (r"(?i)(?:eval|exec)\s*\(.*(?:fetch|http|request)", "Eval of network-fetched content"),
]


def _calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string. High entropy = likely encoded/encrypted."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _find_hidden_dirs(content: str) -> list[str]:
    """Detect references to hidden or build directories."""
    hits = []
    for pattern, desc in _HIDDEN_DIR_PATTERNS:
        if re.search(pattern, content):
            hits.append(desc)
    return hits


def _find_decoder_patterns(content: str) -> list[str]:
    """Detect runtime decoding/encoding patterns (SFS decoder scripts)."""
    hits = []
    for pattern, desc in _DECODER_PATTERNS:
        if re.search(pattern, content):
            hits.append(desc)
    return hits


def _find_packing_patterns(content: str) -> list[str]:
    """Detect self-extracting/packing patterns."""
    hits = []
    for pattern, desc in _PACKING_PATTERNS:
        if re.search(pattern, content):
            hits.append(desc)
    return hits


def _find_manifest_abuse(content: str) -> list[str]:
    """Detect runtime file creation that could be SFS unpacking."""
    hits = []
    for pattern, desc in _MANIFEST_ABUSE_PATTERNS:
        if re.search(pattern, content):
            hits.append(desc)
    return hits


def _find_exfil_in_decoder(content: str) -> list[str]:
    """Detect network calls combined with eval (exfil via decoded payload)."""
    hits = []
    for pattern, desc in _EXFIL_IN_DECODER:
        if re.search(pattern, content):
            hits.append(desc)
    return hits


def detect_skillcloak(content: str, source: str = "config") -> list[FindingCreate]:
    """Run all SKILLCLOAK detection checks on content."""
    findings: list[FindingCreate] = []

    if not content or len(content.strip()) < 10:
        return findings

    # 1. Entropy check — high entropy in script-like content suggests encoding
    entropy = _calculate_shannon_entropy(content)
    if entropy > 4.5 and len(content) > 100:
        findings.append(FindingCreate(
            category="skillcloak",
            severity="high",
            title=f"High entropy detected in {source} (possible packed payload)",
            description=(
                f"The content has Shannon entropy of {entropy:.2f} (threshold: 4.5). "
                "High entropy in configuration files suggests encoded, encrypted, or packed content "
                "that may hide malicious payloads. This is a hallmark of SKILLCLOAK-style attacks "
                "where payloads are obfuscated to bypass static scanners."
            ),
            evidence=f"Entropy: {entropy:.2f}\nSource: {source}\nContent length: {len(content)} bytes",
            remediation=(
                "1. Review the high-entropy content manually. "
                "2. Decode any base64/hex strings found. "
                "3. If this is a skill file, ensure all code is in plain text."
            ),
            cwe="CWE-532",
            references=["https://thehackernews.com/2026/07/new-skillcloak-technique-lets-malicious.html"],
        ))

    # 2. Hidden directory references
    hidden_dirs = _find_hidden_dirs(content)
    if hidden_dirs:
        findings.append(FindingCreate(
            category="skillcloak",
            severity="medium",
            title=f"Hidden/build directory references in {source}",
            description=(
                f"The content references hidden or build directories: {', '.join(set(hidden_dirs))}. "
                "Attackers use these directories to hide packed payloads that scanners skip. "
                "Self-extracting skills (SFS) store malicious code in .git/, build/, or other "
                "excluded directories and unpack at runtime."
            ),
            evidence=f"Patterns matched: {', '.join(set(hidden_dirs))}",
            remediation=(
                "1. Remove references to hidden directories unless absolutely necessary. "
                "2. If directories are needed, ensure their contents are also scanned. "
                "3. Use manifest hash verification to detect runtime file creation."
            ),
            cwe="CWE-538",
        ))

    # 3. Decoder/encoder patterns (SFS decoder scripts)
    decoders = _find_decoder_patterns(content)
    if decoders:
        findings.append(FindingCreate(
            category="skillcloak",
            severity="critical",
            title=f"Runtime decoder pattern detected in {source} (possible SFS payload)",
            description=(
                f"Found {len(decoders)} decoder/execution pattern(s): {', '.join(set(decoders))}. "
                "This strongly suggests a self-extracting skill (SFS) that unpacks and executes "
                "malicious code at runtime. The SKILLCLOAK attack uses exactly this pattern: "
                "a clean config with a tiny decoder that dynamically loads the real payload."
            ),
            evidence=f"Patterns matched:\n" + "\n".join(f"  - {d}" for d in set(decoders)),
            remediation=(
                "1. CRITICAL: Review this code immediately. "
                "2. If eval/exec/Function is used, ensure it only processes trusted input. "
                "3. Remove any dynamic code execution patterns. "
                "4. All logic should be in plain, readable code."
            ),
            cwe="CWE-94",
            owasp="MCP03:2025",
            references=["https://thehackernews.com/2026/07/new-skillcloak-technique-lets-malicious.html"],
        ))

    # 4. Packing/obfuscation patterns
    packing = _find_packing_patterns(content)
    if packing:
        findings.append(FindingCreate(
            category="skillcloak",
            severity="high",
            title=f"Packing/obfuscation patterns in {source}",
            description=(
                f"Found {len(packing)} packing pattern(s): {', '.join(set(packing))}. "
                "These patterns indicate the content may contain a packed or obfuscated payload. "
                "SKILLCLOAK uses string slicing, hex arrays, and character code construction "
                "to hide malicious instructions from static scanners."
            ),
            evidence=f"Patterns matched:\n" + "\n".join(f"  - {p}" for p in set(packing)),
            remediation=(
                "1. Decode obfuscated strings to inspect their content. "
                "2. Replace obfuscated logic with plain code. "
                "3. If encoding is necessary, document why and provide decoding instructions."
            ),
            cwe="CWE-532",
        ))

    # 5. Manifest abuse (runtime file creation)
    manifest = _find_manifest_abuse(content)
    if manifest:
        findings.append(FindingCreate(
            category="skillcloak",
            severity="critical",
            title=f"Runtime file creation detected in {source} (possible SFS unpacking)",
            description=(
                f"Found {len(manifest)} file creation pattern(s): {', '.join(set(manifest))}. "
                "Runtime file creation in a config/skill file is a strong indicator of "
                "self-extracting skill (SFS) packing. The SKILLCLOAK attack writes packed "
                "payloads to disk at runtime, bypassing all static analysis."
            ),
            evidence=f"Patterns matched:\n" + "\n".join(f"  - {m}" for m in set(manifest)),
            remediation=(
                "1. CRITICAL: This skill creates files at runtime. "
                "2. Verify all file creation is expected and documented. "
                "3. Use manifest hash verification to detect unauthorized file creation. "
                "4. Consider sandboxing this skill's execution."
            ),
            cwe="CWE-434",
        ))

    # 6. Exfil via decoded payload
    exfil = _find_exfil_in_decoder(content)
    if exfil:
        findings.append(FindingCreate(
            category="skillcloak",
            severity="critical",
            title=f"Network exfiltration via decoded payload in {source}",
            description=(
                f"Found network call combined with code execution: {', '.join(set(exfil))}. "
                "This pattern fetches content from a network and executes it, which is the "
                "final stage of a SKILLCLOAK attack — the decoder fetches and runs the "
                "real malicious payload."
            ),
            evidence=f"Patterns matched:\n" + "\n".join(f"  - {e}" for e in set(exfil)),
            remediation=(
                "1. CRITICAL: Remove network calls that fetch executable content. "
                "2. All dependencies should be pinned and verified, not fetched at runtime. "
                "3. Use content hashing to verify fetched content integrity."
            ),
            cwe="CWE-94",
            owasp="MCP03:2025",
        ))

    return findings

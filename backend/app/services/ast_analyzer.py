"""AST-based code analysis for detecting dangerous patterns in JS/Python.

Goes beyond regex by parsing actual code structure to find:
- exec/eval calls with dynamic arguments
- Obfuscated strings (hex encoding, chr() chains, string concatenation)
- Dynamic imports
- Process spawning with user-controlled input
"""

from __future__ import annotations

import ast
import re
import logging

from ..schemas import FindingCreate

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Python AST analysis
# ---------------------------------------------------------------------------

_DANGEROUS_PYTHON_CALLS = {
    "exec": ("critical", "Dynamic code execution via exec()", "CWE-95"),
    "eval": ("critical", "Expression evaluation via eval()", "CWE-95"),
    "compile": ("high", "Dynamic code compilation", "CWE-95"),
    "__import__": ("high", "Dynamic module import", "CWE-95"),
    "importlib.import_module": ("high", "Dynamic module import", "CWE-95"),
    "os.system": ("critical", "OS command execution", "CWE-78"),
    "os.popen": ("critical", "OS command pipe", "CWE-78"),
    "subprocess.run": ("critical", "Subprocess execution", "CWE-78"),
    "subprocess.Popen": ("critical", "Subprocess creation", "CWE-78"),
    "subprocess.call": ("critical", "Subprocess call", "CWE-78"),
    "subprocess.check_output": ("critical", "Subprocess output capture", "CWE-78"),
    "subprocess.check_call": ("critical", "Subprocess call", "CWE-78"),
}


def analyze_python_ast(code: str) -> list[FindingCreate]:
    """Parse Python code via AST and detect dangerous patterns."""
    findings: list[FindingCreate] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        # Detect dangerous function calls
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node)
            if call_name in _DANGEROUS_PYTHON_CALLS:
                severity, desc, cwe = _DANGEROUS_PYTHON_CALLS[call_name]
                findings.append(FindingCreate(
                    category="code_execution",
                    severity=severity,
                    title=f"AST: {desc}",
                    description=f"Static analysis detected a call to `{call_name}()` which can execute arbitrary code. {desc}.",
                    evidence=f"Function: {call_name}() at line {getattr(node, 'lineno', '?')}",
                    remediation=f"Avoid {call_name}() with dynamic arguments. Use safer alternatives.",
                    cwe=cwe,
                ))

        # Detect obfuscated string building: chr() chains
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "chr":
                # Check if this is inside a join or concatenation
                findings.append(FindingCreate(
                    category="obfuscation",
                    severity="medium",
                    title="AST: chr() string construction",
                    description="Code constructs strings using chr() calls, which is a common obfuscation technique to hide string literals from static analysis.",
                    evidence=f"chr() call at line {getattr(node, 'lineno', '?')}",
                    remediation="Deobfuscate and review the constructed string.",
                    cwe="CWE-506",
                ))

        # Detect string concatenation in dangerous contexts
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if _is_in_dangerous_context(node, tree):
                findings.append(FindingCreate(
                    category="obfuscation",
                    severity="low",
                    title="AST: String concatenation in dangerous context",
                    description="String concatenation detected in a potentially dangerous context (e.g., building a command string).",
                    evidence=f"Concatenation at line {getattr(node, 'lineno', '?')}",
                    remediation="Review if the concatenated string is used for code execution.",
                    cwe="CWE-506",
                ))

    return findings


def _get_call_name(node: ast.Call) -> str:
    """Extract the full name of a function call (e.g., 'os.system')."""
    if isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _is_in_dangerous_context(node: ast.BinOp, tree: ast.Module) -> bool:
    """Check if a string concatenation feeds into a dangerous call."""
    for parent in ast.walk(tree):
        if isinstance(parent, ast.Call):
            call_name = _get_call_name(parent)
            if call_name in ("os.system", "os.popen", "subprocess.run", "subprocess.Popen",
                             "subprocess.call", "subprocess.check_output", "exec", "eval"):
                # Check if this node is an ancestor of any argument
                for arg in parent.args + [kw.value for kw in parent.keywords]:
                    if _is_ancestor(node, arg):
                        return True
    return False


def _is_ancestor(potential_ancestor: ast.AST, node: ast.AST) -> bool:
    """Check if potential_ancestor is an ancestor of node in the AST."""
    for child in ast.walk(node):
        if child is potential_ancestor:
            return True
    return False


# ---------------------------------------------------------------------------
# JavaScript regex-based analysis (JS AST is too complex without tree-sitter)
# ---------------------------------------------------------------------------

_JS_DANGEROUS_PATTERNS = [
    (r"(?i)\beval\s*\(", "critical", "Dynamic code evaluation via eval()", "CWE-95"),
    (r"(?i)\bnew\s+Function\s*\(", "critical", "Dynamic function creation via new Function()", "CWE-95"),
    (r"(?i)\bchild_process\b", "critical", "Child process module import", "CWE-78"),
    (r"(?i)\brequire\s*\(\s*['\"]child_process['\"]", "critical", "Dynamic require of child_process", "CWE-78"),
    (r"(?i)\bimport\s*\(\s*['\"]child_process['\"]", "high", "Dynamic import of child_process", "CWE-78"),
    (r"(?i)\bprocess\.(exit|kill|abort)\s*\(", "medium", "Process lifecycle manipulation", "CWE-78"),
    (r"(?i)\bfs\.(writeFileSync|writeFile)\s*\(", "high", "Filesystem write operation", "CWE-73"),
    (r"(?i)\bfs\.(readFileSync|readFile)\s*\(", "medium", "Filesystem read operation", "CWE-73"),
    (r"(?i)\bBuffer\.from\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]", "high", "Base64 buffer construction (possible payload)", "CWE-506"),
    (r"(?i)\batob\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]", "high", "Base64 decoding of large string (possible payload)", "CWE-506"),
    (r"(?i)\bString\.fromCharCode\s*\(", "medium", "String construction from char codes (possible obfuscation)", "CWE-506"),
    (r"(?i)\bunescape\s*\(", "medium", "unescape() usage (possible obfuscation)", "CWE-506"),
    (r"(?i)\bdecodeURIComponent\s*\(\s*['\"][%20%0-9a-fA-F]{20,}['\"]", "medium", "URL-decoded obfuscated string", "CWE-506"),
]


def analyze_js_patterns(code: str) -> list[FindingCreate]:
    """Detect dangerous JavaScript patterns using structured regex.

    Uses comment-aware analysis to avoid false positives in comments.
    """
    findings: list[FindingCreate] = []
    seen: set[str] = set()

    # Strip block comments and line comments for analysis
    # but keep line numbers by replacing comment content with spaces
    cleaned = re.sub(r"//[^\n]*", lambda m: " " * len(m.group()), code)
    cleaned = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group()), cleaned, flags=re.DOTALL)

    for pattern, severity, desc, cwe in _JS_DANGEROUS_PATTERNS:
        for match in re.finditer(pattern, cleaned):
            key = f"{pattern}:{match.start()}"
            if key in seen:
                continue
            seen.add(key)

            # Get line number from original code
            line_num = code[:match.start()].count("\n") + 1
            # Get context
            start = max(0, match.start() - 30)
            end = min(len(code), match.end() + 30)
            context = code[start:end].replace("\n", " ").strip()

            findings.append(FindingCreate(
                category="code_execution" if severity == "critical" else "obfuscation",
                severity=severity,
                title=f"JS: {desc}",
                description=f"JavaScript analysis detected: {desc}. This pattern can be used to execute arbitrary code.",
                evidence=f"Line {line_num}: ...{context[:150]}...",
                remediation=f"Review and remove {desc.lower()} if not required.",
                cwe=cwe,
            ))

    return findings


# ---------------------------------------------------------------------------
# Combined analyzer
# ---------------------------------------------------------------------------

def analyze_code(content: str) -> list[FindingCreate]:
    """Analyze content for dangerous code patterns across languages.

    Detects if content contains embedded code blocks and analyzes them.
    """
    findings: list[FindingCreate] = []

    # Check for Python code blocks
    python_blocks = re.findall(r"```python\s*\n(.*?)```", content, re.DOTALL)
    python_blocks += re.findall(r"```\s*\n(.*?(?:import |def |class |exec\(|eval\()).*?```", content, re.DOTALL)
    for block in python_blocks:
        findings.extend(analyze_python_ast(block))

    # Check for JavaScript code blocks
    js_blocks = re.findall(r"```(?:javascript|js|node)\s*\n(.*?)```", content, re.DOTALL)
    for block in js_blocks:
        findings.extend(analyze_js_patterns(block))

    # Also analyze raw content for inline code patterns
    findings.extend(analyze_js_patterns(content))

    # Check for obfuscation indicators in any content
    findings.extend(_check_obfuscation(content))

    return findings


def _check_obfuscation(content: str) -> list[FindingCreate]:
    """Detect common obfuscation techniques across languages."""
    findings: list[FindingCreate] = []

    # Hex-encoded strings: \x41\x42\x43
    hex_strings = re.findall(r"(?:\\x[0-9a-fA-F]{2}){6,}", content)
    if hex_strings:
        findings.append(FindingCreate(
            category="obfuscation",
            severity="medium",
            title="Hex-encoded string detected",
            description=f"Found {len(hex_strings)} hex-encoded string(s) which may hide malicious payloads.",
            evidence=f"Sample: {hex_strings[0][:80]}...",
            remediation="Decode and inspect hex strings to verify they are benign.",
            cwe="CWE-506",
        ))

    # Unicode escape sequences: \u0041\u0042
    unicode_escapes = re.findall(r"(?:\\u[0-9a-fA-F]{4}){6,}", content)
    if unicode_escapes:
        findings.append(FindingCreate(
            category="obfuscation",
            severity="medium",
            title="Unicode escape sequence string detected",
            description=f"Found {len(unicode_escapes)} Unicode-escaped string(s) which may hide malicious content.",
            evidence=f"Sample: {unicode_escapes[0][:80]}...",
            remediation="Decode and inspect Unicode strings.",
            cwe="CWE-506",
        ))

    # Excessive string concatenation (obfuscation via fragmentation)
    # Count lines with many string concatenations
    concat_lines = re.findall(r"(?:['\"].*?['\"].*?\+.*?['\"].*?['\"]){3,}", content)
    if len(concat_lines) > 5:
        findings.append(FindingCreate(
            category="obfuscation",
            severity="low",
            title="Excessive string concatenation",
            description=f"Found {len(concat_lines)} lines with heavy string concatenation, a common obfuscation technique.",
            evidence="Strings are fragmented across many concatenation operations.",
            remediation="Review concatenated strings for hidden malicious content.",
            cwe="CWE-506",
        ))

    return findings

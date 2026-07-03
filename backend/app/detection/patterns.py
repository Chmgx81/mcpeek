"""Shared detection patterns used across all MCPeek scanners."""

# ── Prompt injection patterns ──

PROMPT_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "Prompt injection: ignore previous instructions"),
    (r"(?i)you\s+are\s+now\s+(a\s+)?", "Prompt injection: role override"),
    (r"(?i)disregard\s+(all\s+)?prior", "Prompt injection: disregard prior"),
    (r"(?i)system\s*:\s*", "Prompt injection: system prompt override"),
    (r"(?i)override\s+(the\s+)?system", "Prompt injection: system override attempt"),
    (r"(?i)<\|im_start\|>|<\|im_end\|>", "Prompt injection: special token"),
    (r"(?i)<\|system\|>", "Prompt injection: system token"),
    (r"(?i)jailbreak", "Prompt injection: jailbreak keyword"),
    (r"(?i)do\s+anything\s+now", "Prompt injection: DAN (do anything now)"),
    (r"(?i)you\s+must\s+obey\s+all", "Prompt injection: obedience override"),
    (r"(?i)forget\s+(all\s+)?instructions", "Prompt injection: forget instructions"),
    (r"(?i)new\s+instructions\s*:", "Prompt injection: new instructions override"),
    (r"(?i)override\s+(all\s+)?safety", "Prompt injection: safety override"),
    (r"(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions", "Prompt injection: restriction bypass"),
    (r"(?i)DAN\s+mode", "Prompt injection: DAN jailbreak"),
]

# ── Social engineering patterns ──

SOCIAL_ENGINEERING_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)do\s+not\s+tell\s+(?:the\s+)?user", "Instruction to hide from user"),
    (r"(?i)secretly\s+", "Instruction to act secretly"),
    (r"(?i)without\s+(?:the\s+)?(?:user|human)\s+(?:knowing|aware)", "Hidden action instruction"),
    (r"(?i)pretend\s+you\s+(?:are|have|can)", "Deception instruction"),
    (r"(?i)lie\s+to\s+(?:the\s+)?user", "Instruction to deceive"),
]

# ── Exfiltration patterns ──

EXFILTRATION_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)curl\s+(?:-[a-z]+\s+)*.*https?://", "curl to external URL"),
    (r"(?i)wget\s+https?://", "wget download"),
    (r"(?i)fetch\s*\(\s*['\"]https?://", "fetch() to external URL"),
    (r"(?i)requests?\.(?:get|post|put|patch|delete)\s*\(\s*['\"]https?://", "HTTP request to external URL"),
    (r"(?i)urllib\.request", "URL library request"),
    (r"(?i)axios\.(?:get|post|put|patch|delete)\s*\(", "Axios HTTP request"),
]

# ── Shell execution patterns ──

SHELL_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"(?i)\b(bash|sh|zsh)\s+(-c\s+)?['\"\w]", "Shell invocation", "critical", "Direct shell invocation detected. Attackers can chain shell commands to escape sandbox boundaries."),
    (r"(?i)\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(", "subprocess call", "critical", "Python subprocess invocation detected. Can execute arbitrary OS commands."),
    (r"(?i)\bos\.system\s*\(", "os.system call", "critical", "os.system() call detected. Passes commands directly to the OS shell."),
    (r"(?i)\bos\.popen\s*\(", "os.popen call", "critical", "os.popen() call detected. Opens a pipe to/from a command."),
    (r"(?i)\bexec\s*\(", "exec() call", "critical", "exec() call detected. Executes dynamically constructed code strings."),
    (r"(?i)\beval\s*\(", "eval() call", "critical", "eval() call detected. Evaluates arbitrary Python expressions."),
    (r"(?i)\bchild_process\.(exec|execSync|spawn|spawnSync)\s*\(", "child_process call", "critical", "Node.js child_process invocation detected. Can execute arbitrary commands."),
    (r"(?i)\bRuntime\.getRuntime\(\)\.exec\s*\(", "Runtime.exec call", "critical", "Java Runtime.exec() detected. Executes OS commands."),
    (r"(?i)\bSystem\.Diagnostics\.Process\.Start\s*\(", "Process.Start call", "critical", "C# Process.Start() detected. Launches external processes."),
]

# ── Dangerous tool permissions ──

DANGEROUS_PERMISSIONS: dict[str, str] = {
    "fs": "high",
    "filesystem": "high",
    "network": "high",
    "http": "high",
    "fetch": "high",
    "exec": "critical",
    "shell": "critical",
    "process": "critical",
    "bash": "critical",
    "terminal": "critical",
    "code_execution": "critical",
    "computer": "critical",
    "web": "low",
    "browser": "medium",
    "write": "medium",
}

# ── Secret detection patterns ──

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CWE-798"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "CWE-798"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "CWE-798"),
    (r"sk-[A-Za-z0-9_-]{32,}", "OpenAI API Key", "CWE-798"),
    (r"xox[bpsa]-[A-Za-z0-9-]+", "Slack Token", "CWE-798"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key", "CWE-321"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}", "Hardcoded Password", "CWE-798"),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_-]{16,}", "API Key", "CWE-798"),
    (r"(?i)(secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_-]{16,}", "Secret Key", "CWE-798"),
    (r"(?i)(token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{20,}", "Auth Token", "CWE-798"),
    (r"(?i)(aws_secret_access_key)\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}", "AWS Secret Key", "CWE-798"),
    (r"(?i)(connection_?string|database_?url)\s*[:=]\s*['\"](?:mysql|postgres|mongodb|redis)://", "Database Connection String", "CWE-798"),
]

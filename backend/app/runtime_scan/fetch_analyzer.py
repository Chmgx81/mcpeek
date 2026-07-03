"""Runtime fetch analyzer — safely inspect content fetched from external links."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from ..schemas.scan import FindingCreate

Severity = Literal['critical', 'high', 'medium', 'low', 'info']
Exploitability = Literal['trivial', 'easy', 'moderate', 'difficult', 'theoretical']
Impact = Literal['total_system_compromise', 'data_breach', 'privilege_escalation', 'information_disclosure', 'no_impact']


@dataclass
class RuntimeFinding:
    """Extended finding with runtime analysis metadata."""
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str = ''
    remediation: str = ''
    cwe: str | None = None
    confidence: float = 0.0      # 0.0–1.0
    exploitability: Exploitability = 'moderate'
    impact: Impact = 'no_impact'
    confidence_reason: str = ''

    def to_finding_create(self) -> FindingCreate:
        return FindingCreate(
            category=self.category,
            severity=self.severity,
            title=self.title,
            description=f'{self.description}\n\nConfidence: {self.confidence:.0%} ({self.confidence_reason})\nExploitability: {self.exploitability}\nImpact: {self.impact}',
            evidence=self.evidence,
            remediation=self.remediation,
            cwe=self.cwe,
        )


# ── Rule 1: Remote Script Execution ──

_CURL_PIPE_RE = re.compile(r'curl\s+(?:-[a-zA-Z]+\s+)*https?://[^\s|]+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh', re.IGNORECASE)
_WGET_PIPE_RE = re.compile(r'wget\s+(?:-[a-zA-Z]+\s+)*https?://[^\s|]+[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh', re.IGNORECASE)
_WGET_EXEC_RE = re.compile(r'wget\s+(?:-[a-zA-Z]+\s+)*https?://[^\s]+[^;]*;\s*(?:sudo\s+)?(?:ba)?sh\s+[^\s]+', re.IGNORECASE)
_EVAL_EXEC_RE = re.compile(r'(?:eval|exec)\s*\(\s*(?:requests\.get|urllib\.request\.urlopen|httpx\.get)\s*\(', re.IGNORECASE)
_NODE_FETCH_RE = re.compile(r'(?:eval|Function)\s*\(\s*(?:await\s+)?fetch\s*\(\s*["\']https?://', re.IGNORECASE)
_SUBPROCESS_RE = re.compile(r'subprocess\.(?:call|run|Popen)\s*\(\s*\[.*?https?://', re.IGNORECASE)


def _check_remote_script_execution(content: str, url: str) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []

    patterns = [
        (_CURL_PIPE_RE, 'curl pipe to shell', 'curl ... | bash/sh'),
        (_WGET_PIPE_RE, 'wget pipe to shell', 'wget ... | bash/sh'),
        (_WGET_EXEC_RE, 'wget followed by shell execution', 'wget ... ; bash script.sh'),
        (_EVAL_EXEC_RE, 'eval/exec of remote HTTP response', 'eval(requests.get(url))'),
        (_NODE_FETCH_RE, 'dynamic code execution from fetch', 'eval(fetch(url))'),
        (_SUBPROCESS_RE, 'subprocess execution with remote URL', 'subprocess.run([...url...])'),
    ]

    for pattern, title, example in patterns:
        for match in pattern.finditer(content):
            snippet = content[max(0, match.start() - 40):min(len(content), match.end() + 40)]
            findings.append(RuntimeFinding(
                title=f'Remote Script Execution: {title}',
                severity='critical',
                category='remote_script_execution',
                description=f'Content executes code fetched from a remote URL via {example}. '
                            'This allows arbitrary code execution and full system compromise.',
                evidence=f'URL: {url}\nPattern: {match.group()[:200]}\nContext: ...{snippet[:200]}...',
                remediation='Never pipe remote scripts directly to shell. Download, verify checksum, review, then execute.',
                cwe='CWE-94',
                confidence=0.95,
                exploitability='trivial',
                impact='total_system_compromise',
                confidence_reason='exact pattern match',
            ))

    return findings


# ── Rule 2: Malicious Installation Instructions ──

_SUDO_INSTALL_RE = re.compile(r'sudo\s+(?:apt(?:-get)?|yum|dnf|brew|pip|npm|npx)\s+install\s+(?:-[a-zA-Z]+\s+)*[a-zA-Z0-9_-]+', re.IGNORECASE)
_CHMOD_777_RE = re.compile(r'chmod\s+(?:-R\s+)?777\s+/\S*')
_UNSAFE_CURL_RE = re.compile(r'curl\s+(?:-[a-zA-Z]+\s+)*https?://[^\s]+\s+(?:-[oO]\s+\S+\s+)?(?:&&\s*)?(?:sudo\s+)?(?:ba)?sh', re.IGNORECASE)
_DOCKER_PRIVILEGED_RE = re.compile(r'docker\s+run\s+[^"]*--privileged', re.IGNORECASE)
_SUDO_RM_RE = re.compile(r'sudo\s+rm\s+(?:-[a-zA-Z]*\s+)*/(?:etc|usr|var|boot|sys|proc)', re.IGNORECASE)
_WGET_O_SH_RE = re.compile(r'wget\s+(?:-[a-zA-Z]+\s+)*https?://[^\s]+-o\s+\S+\.sh', re.IGNORECASE)


def _check_malicious_install(content: str, url: str) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []

    patterns = [
        (_SUDO_INSTALL_RE, 'Privileged package installation',
         'sudo apt/yum/brew install with elevated privileges',
         'CWE-250', 0.85, 'easy', 'privilege_escalation',
         'Privileged installs can modify system state and install backdoors. Verify package sources.'),
        (_CHMOD_777_RE, 'World-writable file permissions',
         'chmod 777 on system paths',
         'CWE-732', 0.90, 'trivial', 'privilege_escalation',
         'chmod 777 makes files world-writable, enabling local privilege escalation.'),
        (_UNSAFE_CURL_RE, 'Unsafe curl-to-shell installation',
         'curl URL | sudo bash',
         'CWE-94', 0.95, 'trivial', 'total_system_compromise',
         'Piping remote content directly to shell with elevated privileges.'),
        (_DOCKER_PRIVILEGED_RE, 'Docker privileged container',
         'docker run --privileged',
         'CWE-250', 0.85, 'easy', 'total_system_compromise',
         'Privileged containers have full host access and can escape to the host.'),
        (_SUDO_RM_RE, 'Destructive system command',
         'sudo rm on critical system paths',
         'CWE-404', 0.90, 'easy', 'total_system_compromise',
         'Removing system files can brick the system or remove security controls.'),
        (_WGET_O_SH_RE, 'Downloading shell script via wget',
         'wget -O script.sh from remote URL',
         'CWE-494', 0.80, 'moderate', 'privilege_escalation',
         'Downloading executable scripts from untrusted sources.'),
    ]

    for pattern, title, example, cwe, conf, explo, impact, remed in patterns:
        for match in pattern.finditer(content):
            snippet = content[max(0, match.start() - 30):min(len(content), match.end() + 30)]
            findings.append(RuntimeFinding(
                title=f'Malicious Installation: {title}',
                severity='critical',
                category='malicious_installation',
                description=f'Content contains {example} ({match.group()[:100]}). '
                            'This modifies system state or executes untrusted code.',
                evidence=f'URL: {url}\nPattern: {match.group()[:200]}\nContext: ...{snippet[:200]}...',
                remediation=remed,
                cwe=cwe,
                confidence=conf,
                exploitability=explo,
                impact=impact,
                confidence_reason='pattern match',
            ))

    return findings


# ── Rule 3: Hidden Prompt Injection ──

# These look for prompt injection that might be hidden in fetched content
# (e.g., in README files, config docs, or fetched JSON responses)

_OVERRIDE_RE = re.compile(r'(?i)(?:ignore|disregard|override|forget|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|system|original)\s+(?:instructions?|prompts?|rules?|constraints?|guidelines?)')
_SYSTEM_PROMPT_RE = re.compile(r'(?i)(?:you\s+are|act\s+as|pretend\s+(?:to\s+be|you(?:\'re|\s+are))|roleplay\s+as|respond\s+as)\s+(?:a\s+)?(?:malicious|evil|unrestricted|unfiltered|jailbroken|DAN|developer\s+mode)')
_EXFIL_INSTRUCTION_RE = re.compile(r'(?i)(?:do\s+not\s+(?:tell|mention|reveal|disclose|share)|never\s+(?:tell|mention|reveal|disclose|share|say))\s+(?:anyone|the\s+user|the\s+human|anyone\s+about|that\s+you)')
_HIDDEN_MARKER_RE = re.compile(r'<!--.*?(?:ignore|override|system|prompt|instruction).*?-->', re.IGNORECASE | re.DOTALL)
_UNICODE_TAG_RE = re.compile(r'[\u2060-\u2064\u200B-\u200F\uFEFF]')  # invisible Unicode
_ZERO_WIDTH_RE = re.compile(r'[\u200B\u200C\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064]')
_INJECTION_DELIMITER_RE = re.compile(r'(?i)(?:^|\n)(?:---+\s*(?:SYSTEM|ADMIN|OVERRIDE|IGNORE)\s*---+|<<\s*(?:SYS|ADMIN|OVERRIDE)\s*>>|\[(?:SYSTEM|ADMIN|OVERRIDE)\])')


def _check_hidden_injection(content: str, url: str) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []

    # Direct override commands
    for match in _OVERRIDE_RE.finditer(content):
        snippet = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
        findings.append(RuntimeFinding(
            title='Hidden Prompt Injection: instruction override',
            severity='high',
            category='prompt_injection',
            description=f'Content contains a prompt injection override pattern: "{match.group()}". '
                        'This attempts to hijack AI model behavior.',
            evidence=f'URL: {url}\nMatch: {match.group()[:150]}\nContext: ...{snippet[:200]}...',
            remediation='Remove injection attempts. Scrub external content before passing to AI models.',
            cwe='CWE-77',
            confidence=0.80,
            exploitability='moderate',
            impact='information_disclosure',
            confidence_reason='exact text match, may be legitimate text',
        ))

    # Role hijacking
    for match in _SYSTEM_PROMPT_RE.finditer(content):
        snippet = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
        findings.append(RuntimeFinding(
            title='Hidden Prompt Injection: role hijacking',
            severity='high',
            category='prompt_injection',
            description=f'Content attempts to hijack AI role/identity: "{match.group()}". '
                        'This is a common jailbreak technique.',
            evidence=f'URL: {url}\nMatch: {match.group()[:150]}\nContext: ...{snippet[:200]}...',
            remediation='Sanitize external content. Use input validation to strip role-assignment patterns.',
            cwe='CWE-77',
            confidence=0.75,
            exploitability='moderate',
            impact='total_system_compromise',
            confidence_reason='exact text match, may be tutorial/example content',
        ))

    # Secrecy instructions (hiding from user)
    for match in _EXFIL_INSTRUCTION_RE.finditer(content):
        snippet = content[max(0, match.start() - 50):min(len(content), match.end() + 50)]
        findings.append(RuntimeFinding(
            title='Hidden Prompt Injection: secrecy instruction',
            severity='high',
            category='prompt_injection',
            description=f'Content contains a secrecy instruction: "{match.group()}". '
                        'This attempts to hide injection activity from the user.',
            evidence=f'URL: {url}\nMatch: {match.group()[:150]}\nContext: ...{snippet[:200]}...',
            remediation='External content should not contain instructions to hide behavior from users.',
            cwe='CWE-77',
            confidence=0.70,
            exploitability='moderate',
            impact='information_disclosure',
            confidence_reason='may be legitimate security documentation',
        ))

    # HTML comment injection
    for match in _HIDDEN_MARKER_RE.finditer(content):
        findings.append(RuntimeFinding(
            title='Hidden Prompt Injection: HTML comment payload',
            severity='high',
            category='prompt_injection',
            description='Content contains HTML comments with suspicious instructions that may be invisible to human readers but processed by AI.',
            evidence=f'URL: {url}\nMatch: {match.group()[:200]}',
            remediation='Strip HTML comments from external content before processing.',
            cwe='CWE-77',
            confidence=0.85,
            exploitability='easy',
            impact='total_system_compromise',
            confidence_reason='HTML comments are invisible but machine-readable',
        ))

    # Invisible Unicode injection
    invisible_count = len(_ZERO_WIDTH_RE.findall(content))
    if invisible_count > 20:
        findings.append(RuntimeFinding(
            title='Hidden Prompt Injection: invisible Unicode characters',
            severity='high',
            category='prompt_injection',
            description=f'Content contains {invisible_count} invisible Unicode characters (zero-width spaces, etc.) '
                        'which can be used to inject hidden instructions invisible to human readers.',
            evidence=f'URL: {url}\nInvisible characters found: {invisible_count}',
            remediation='Strip invisible Unicode characters from external content before processing.',
            cwe='CWE-77',
            confidence=0.60,
            exploitability='difficult',
            impact='total_system_compromise',
            confidence_reason='may be formatting artifacts, elevated count suggests intent',
        ))

    # Delimiter-based injection
    for match in _INJECTION_DELIMITER_RE.finditer(content):
        snippet = content[max(0, match.start() - 30):min(len(content), match.end() + 100)]
        findings.append(RuntimeFinding(
            title='Hidden Prompt Injection: system/admin delimiter',
            severity='high',
            category='prompt_injection',
            description=f'Content contains a system/admin delimiter pattern: "{match.group().strip()[:80]}". '
                        'This may be used to inject instructions that the AI treats as system-level.',
            evidence=f'URL: {url}\nMatch: {match.group()[:100]}\nContext: ...{snippet[:200]}...',
            remediation='Remove or escape delimiter patterns from external content.',
            cwe='CWE-77',
            confidence=0.80,
            exploitability='moderate',
            impact='total_system_compromise',
            confidence_reason='delimiter pattern strongly suggests injection attempt',
        ))

    return findings


# ── Rule 4: Secret Exfiltration Patterns ──

_ENV_ACCESS_RE = re.compile(r'(?:os\.environ|process\.env|ENV\[|getenv|env\.get)\s*[\[(\s]["\'](?:\w*(?:KEY|TOKEN|SECRET|PASSWORD|CRED|AUTH|API)\w*|ALL)["\']', re.IGNORECASE)
_CURL_ENV_RE = re.compile(r'curl\s+[^"]*(?:\$[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CRED|AUTH|API)\w*|\$\{[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CRED|AUTH|API)\w*\})', re.IGNORECASE)
_WGET_ENV_RE = re.compile(r'wget\s+[^"]*(?:\$[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CRED|AUTH|API)\w*|\$\{[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CRED|AUTH|API)\w*\})', re.IGNORECASE)
_POST_EXFIL_RE = re.compile(r'(?:requests\.post|httpx\.post|fetch\(|axios\.post|fetch\s*\(|http\.post)\s*\(\s*["\']https?://[^"\']*["\']\s*,\s*.*?(?:environ|env|token|key|secret|password|cred)', re.IGNORECASE | re.DOTALL)
_UPLOAD_RE = re.compile(r'(?:upload|send|post|exfil|exfiltrate|beacon|phone.?home)\s*\(\s*.*?(?:environ|env\.|os\.env|\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD)\w*\}?)', re.IGNORECASE)
_SUBPROCESS_ENV_RE = re.compile(r'subprocess\.(?:call|run|Popen)\s*\(\s*\[.*?\].*?env\s*=\s*os\.environ', re.IGNORECASE)
_READ_ETC_RE = re.compile(r'(?:open|read|cat|type)\s*[\( ]["\']/(?:etc/(?:shadow|passwd)|\.ssh/(?:id_|known_hosts|authorized_keys)|\.aws/credentials|\.env)["\']', re.IGNORECASE)


def _check_secret_exfiltration(content: str, url: str) -> list[RuntimeFinding]:
    findings: list[RuntimeFinding] = []

    patterns = [
        (_ENV_ACCESS_RE, 'Sensitive environment variable access',
         'os.environ / process.env accessing KEY/TOKEN/SECRET variables',
         'CWE-200', 0.75, 'moderate', 'data_breach',
         'Accessing sensitive environment variables exposes credentials.'),
        (_CURL_ENV_RE, 'Environment variable leakage via curl',
         'curl command embedding secret environment variables',
         'CWE-200', 0.90, 'trivial', 'data_breach',
         'Secrets are transmitted via command line, visible in process listings and logs.'),
        (_WGET_ENV_RE, 'Environment variable leakage via wget',
         'wget command embedding secret environment variables',
         'CWE-200', 0.90, 'trivial', 'data_breach',
         'Secrets are transmitted via command line, visible in process listings and logs.'),
        (_POST_EXFIL_RE, 'HTTP POST exfiltration of secrets',
         'HTTP POST request containing tokens/keys/secrets',
         'CWE-200', 0.85, 'easy', 'data_breach',
         'Sending credentials to an external endpoint is a data breach.'),
        (_UPLOAD_RE, 'Explicit data exfiltration',
         'Function call referencing upload/send with sensitive data',
         'CWE-200', 0.80, 'easy', 'data_breach',
         'Code explicitly uploads or sends sensitive data externally.'),
        (_SUBPROCESS_ENV_RE, 'Full environment leakage via subprocess',
         'subprocess call passing os.environ as env parameter',
         'CWE-200', 0.85, 'easy', 'data_breach',
         'Passing the full environment to a subprocess leaks all secrets to child processes.'),
        (_READ_ETC_RE, 'Credential file access',
         'Reading sensitive system files (shadow, SSH keys, AWS credentials, .env)',
         'CWE-312', 0.90, 'trivial', 'data_breach',
         'Direct access to credential stores indicates credential theft.'),
    ]

    for pattern, title, example, cwe, conf, explo, impact, remed in patterns:
        for match in pattern.finditer(content):
            snippet = content[max(0, match.start() - 40):min(len(content), match.end() + 40)]
            findings.append(RuntimeFinding(
                title=f'Secret Exfiltration: {title}',
                severity='critical',
                category='secret_exfiltration',
                description=f'Content contains {example}: "{match.group()[:120]}". '
                            'This indicates potential credential theft or data exfiltration.',
                evidence=f'URL: {url}\nPattern: {match.group()[:200]}\nContext: ...{snippet[:200]}...',
                remediation=remed,
                cwe=cwe,
                confidence=conf,
                exploitability=explo,
                impact=impact,
                confidence_reason='pattern match',
            ))

    return findings


# ── Main entry point ──

def analyze_content(
    content: str,
    url: str = '',
    *,
    max_findings: int = 50,
) -> list[RuntimeFinding]:
    """Analyze fetched content for runtime security threats.

    Runs all four rule categories and returns findings with
    confidence scores, exploitability, and impact assessments.
    """
    findings: list[RuntimeFinding] = []

    findings.extend(_check_remote_script_execution(content, url))
    findings.extend(_check_malicious_install(content, url))
    findings.extend(_check_hidden_injection(content, url))
    findings.extend(_check_secret_exfiltration(content, url))

    # Sort by severity (critical first), then confidence (highest first)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))

    return findings[:max_findings]

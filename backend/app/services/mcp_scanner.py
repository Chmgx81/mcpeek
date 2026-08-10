import json
import re

import httpx

from ..detection.patterns import DANGEROUS_PERMISSIONS, PROMPT_INJECTION_PATTERNS
from ..detection.utils import detect_secrets, extract_urls
from ..schemas import FindingCreate
from .ast_analyzer import analyze_code
from .advanced_injection import detect_advanced_injection
from .content_hash import hash_external_urls
from .dependency_risk import analyze_domain_reputation, score_urls
from .external_analyzer import analyze_urls
from .osv_client import scan_dependencies_with_osv
from .tool_poison_detector import detect_tool_poisoning, detect_scope_creep, detect_intent_subversion, detect_context_oversharing
from .url_safety import validate_ip_at_connect_time

SUSPICIOUS_URL_PATTERNS = [
    (r"(?i)eval\s*\(", "Code evaluation (eval)"),
    (r"(?i)data:\s*text/html", "Data URI with HTML content"),
    (r"(?i)javascript:", "JavaScript URI scheme"),
    (r"(?i)base64,[A-Za-z0-9+/=]{50}", "Inline base64 payload"),
]

SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"(?i)(?:curl|wget)\s+(?:-[a-z]+\s+)*https?://", "External download via curl/wget"),
    (r"(?i)child_process|subprocess|os\.system|os\.popen", "System command execution"),
    (r"(?i)spawn|execSync|execFile", "Process spawning"),
    (r"(?i)\.on\(['\"](?:exit|close|error)", "Process lifecycle hooks"),
    (r"(?i)\bpython3?\s+-c\b", "Python inline code execution"),
    (r"(?i)\bnode\s+(-e|--eval)\b", "Node.js inline code execution"),
    (r"(?i)\bruby\s+-e\b", "Ruby inline code execution"),
    (r"(?i)\bperl\s+-e\b", "Perl inline code execution"),
    (r"(?i)\bimport\s+socket\b.*\bconnect\s*\(", "Socket connection (potential reverse shell)"),
    (r"(?i)\bos\.environ\b", "Environment variable access"),
]


async def scan_mcp_server(target: str, deep: bool = True, timeout: int = 120, inline_content: str | None = None) -> tuple[list[FindingCreate], dict]:
    findings: list[FindingCreate] = []
    metadata: dict = {"files_analyzed": 0, "urls_checked": 0, "deps_analyzed": 0, "content_hashes": {}}
    urls_found: list[str] = []

    if inline_content:
        content = inline_content
        manifest = None
        try:
            import json as _json
            manifest = _json.loads(content)
        except Exception:
            pass
        metadata["files_analyzed"] = 1
    elif target.startswith("http://") or target.startswith("https://"):
        content, manifest = await _fetch_url_manifest(target, timeout)
        if content:
            metadata["files_analyzed"] += 1
    else:
        content, manifest = _read_local_manifest(target)
        if content:
            metadata["files_analyzed"] += 1

    if not content:
        findings.append(
            FindingCreate(
                category="manifest",
                severity="low",
                title="Could not read target",
                description=f"Unable to fetch or read manifest from: {target}",
                remediation="Verify the URL or path is accessible.",
            )
        )
        return findings, metadata

    # Analyze manifest content
    findings.extend(_check_mcp_config(manifest, target))
    findings.extend(_check_scripts(manifest))
    findings.extend(detect_secrets(content, target))
    findings.extend(_check_dependencies(manifest, metadata))
    findings.extend(_check_token_budget(content, manifest, target))

    # AST-based code analysis (beyond regex)
    findings.extend(analyze_code(content))

    # Advanced prompt injection detection
    findings.extend(detect_advanced_injection(content, target))

    # SKILLCLOAK detection — entropy, blob, manifest abuse
    from .skillcloak_detector import detect_skillcloak
    findings.extend(detect_skillcloak(content, source=target))

    # Extract URLs for external analysis
    urls_found.extend(extract_urls(content))
    urls_found.extend(extract_urls(json.dumps(manifest) if manifest else ""))

    # External URL analysis
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

        # Real vulnerability lookup via OSV for npm dependencies
        if manifest:
            osv_findings = await _scan_dependencies_osv(manifest)
            findings.extend(osv_findings)

    return findings, metadata


async def _scan_dependencies_osv(manifest: dict) -> list[FindingCreate]:
    """Extract dependencies from manifest and scan them against OSV."""
    findings = []

    # Extract npm dependencies
    deps = manifest.get("dependencies", {})
    dev_deps = manifest.get("devDependencies", {})
    all_deps = {**deps, **dev_deps}

    # Also check nested MCP server configurations for package.json references
    mcp_config = manifest.get("mcp") or manifest.get("mcpServers") or manifest.get("servers") or {}
    if isinstance(mcp_config, dict):
        for server_name, server_config in mcp_config.items():
            if not isinstance(server_config, dict):
                continue
            # Check for package.json in args
            args = server_config.get("args", [])
            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str) and "package.json" in arg:
                        # This is a reference to a package.json — try to extract deps from the command
                        pass

    if all_deps:
        try:
            osv_findings = await scan_dependencies_with_osv(all_deps, ecosystem="npm")
            findings.extend(osv_findings)
        except Exception:
            pass

    return findings


async def _fetch_url_manifest(url: str, timeout: int) -> tuple[str, dict | None]:
    from ..config import settings
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            # Validate the final URL after redirects (anti-DNS-rebinding via redirect)
            if not settings.ALLOW_PRIVATE_NETWORK_SCANS:
                final_host = str(resp.url.host) if resp.url.host else None
                if final_host and not validate_ip_at_connect_time(final_host):
                    return "", None
            text = resp.content[:1_000_000].decode(resp.encoding or "utf-8", errors="replace")
            try:
                return text, resp.json()
            except json.JSONDecodeError:
                return text, None
    except Exception:
        return "", None


def _read_local_manifest(path: str) -> tuple[str, dict | None]:
    try:
        with open(path) as f:
            text = f.read()
        try:
            return text, json.loads(text)
        except json.JSONDecodeError:
            return text, None
    except Exception:
        return "", None


def _check_mcp_config(manifest: dict | None, source: str) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    if not manifest:
        return findings

    # Look for MCP server configurations
    mcp_config = manifest.get("mcp") or manifest.get("mcpServers") or manifest.get("servers") or {}
    if isinstance(mcp_config, dict):
        for server_name, server_config in mcp_config.items():
            if not isinstance(server_config, dict):
                continue

            # Check instructions for prompt injection
            instructions = server_config.get("instructions", "") or server_config.get("prompt", "")
            if isinstance(instructions, str):
                for pattern, title in PROMPT_INJECTION_PATTERNS:
                    if re.search(pattern, instructions):
                        findings.append(
                            FindingCreate(
                                category="prompt_injection",
                                severity="critical",
                                title=f"{title} in MCP server '{server_name}'",
                                description=f"The MCP server '{server_name}' contains instructions that match known prompt injection patterns. This could allow an attacker to override system prompts.",
                                evidence=f"Server: {server_name}\nPattern matched: {pattern}\nSource: {source}",
                                remediation="Remove or sanitize prompt injection patterns from server instructions. Implement input validation.",
                                cwe="CWE-77",
                                owasp="LLM01:2025",
                            )
                        )

            # Check for dangerous tool permissions
            tools = server_config.get("tools", [])
            if isinstance(tools, list):
                for tool in tools:
                    if isinstance(tool, dict):
                        tool_name = tool.get("name", "unknown")
                        tool_desc = tool.get("description", "")
                        for perm_key, severity in DANGEROUS_PERMISSIONS.items():
                            if perm_key in tool_name.lower() or perm_key in tool_desc.lower():
                                findings.append(
                                    FindingCreate(
                                        category="permissions",
                                        severity=severity,
                                        title=f"Dangerous permission: {perm_key} in tool '{tool_name}'",
                                        description=f"Tool '{tool_name}' grants {perm_key} access which has a {severity} risk level.",
                                        evidence=f"Server: {server_name}\nTool: {tool_name}\nPermission: {perm_key}",
                                        remediation="Apply principle of least privilege. Only grant the minimum permissions needed.",
                                        cwe="CWE-250",
                                    )
                                )

            # Check command for dangerous patterns
            command = server_config.get("command", "")
            args = server_config.get("args", [])
            if isinstance(command, str):
                safe_args = [str(a) for a in args] if isinstance(args, list) else []
                full_cmd = command + " " + " ".join(safe_args)
                for pattern, title in SUSPICIOUS_SCRIPT_PATTERNS:
                    if re.search(pattern, full_cmd):
                        findings.append(
                            FindingCreate(
                                category="execution",
                                severity="high",
                                title=f"{title} in MCP server '{server_name}'",
                                description=f"The server command contains patterns associated with {title.lower()}.",
                                evidence=f"Command: {full_cmd[:200]}",
                                remediation="Review the command and ensure it does not execute untrusted code.",
                                cwe="CWE-78",
                            )
                        )

            # OWASP MCP03: Tool poisoning — hidden instructions in tool descriptions
            tools = server_config.get("tools", [])
            if isinstance(tools, list):
                findings.extend(detect_tool_poisoning(tools, server_name))
                findings.extend(detect_scope_creep(tools, server_name))

            # OWASP MCP06: Intent flow subversion — in instructions
            if isinstance(instructions, str) and instructions:
                findings.extend(detect_intent_subversion(instructions, f"MCP server '{server_name}'"))

            # OWASP MCP10: Context over-sharing
            if isinstance(instructions, str) and instructions:
                findings.extend(detect_context_oversharing(instructions, f"MCP server '{server_name}'"))

    return findings


def _check_scripts(manifest: dict | None) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    if not manifest:
        return findings

    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    dangerous_hooks = {"preinstall", "postinstall", "preuninstall", "postuninstall", "prepare"}
    for hook_name, hook_cmd in scripts.items():
        if hook_name.lower() in dangerous_hooks and isinstance(hook_cmd, str):
            severity = "high" if hook_name.lower() in ("postinstall", "preinstall") else "medium"
            findings.append(
                FindingCreate(
                    category="supply_chain",
                    severity=severity,
                    title=f"Suspicious lifecycle script: {hook_name}",
                    description=f"The '{hook_name}' script runs automatically during package operations: {hook_cmd[:150]}",
                    evidence=f"Script: {hook_name} = {hook_cmd}",
                    remediation="Review lifecycle scripts for malicious behavior. Consider disabling auto-install scripts.",
                    cwe="CWE-506",
                    references=["https://blog.sonatype.com/npm-postinstall-scripts-a-new-wave-of-supply-chain-attacks"],
                )
            )

    return findings


def _check_dependencies(manifest: dict | None, metadata: dict) -> list[FindingCreate]:
    findings: list[FindingCreate] = []
    if not manifest:
        return findings

    deps = manifest.get("dependencies", {})
    dev_deps = manifest.get("devDependencies", {})
    all_deps = {**deps, **dev_deps}
    metadata["deps_analyzed"] = len(all_deps)

    # Flag very high dependency counts
    if len(all_deps) > 100:
        findings.append(
            FindingCreate(
                category="supply_chain",
                severity="low",
                title=f"High dependency count: {len(all_deps)}",
                description="This package has a large number of dependencies, increasing the supply chain attack surface.",
                evidence=f"Total dependencies: {len(all_deps)} (production: {len(deps)}, dev: {len(dev_deps)})",
                remediation="Audit dependencies for necessity. Consider reducing the dependency tree.",
            )
        )

    return findings


def _check_token_budget(content: str, manifest: dict | None, target: str) -> list[FindingCreate]:
    """Check for token budget and resource exhaustion risks."""
    findings: list[FindingCreate] = []

    # Check for max_tokens configuration
    max_tokens_patterns = [
        (r'"max_tokens"\s*:\s*(\d+)', "max_tokens"),
        (r'"maxOutputTokens"\s*:\s*(\d+)', "maxOutputTokens"),
        (r'"max_completion_tokens"\s*:\s*(\d+)', "max_completion_tokens"),
    ]

    for pattern, field_name in max_tokens_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            value = int(match.group(1))
            if value > 100000:
                findings.append(
                    FindingCreate(
                        category="resource_exhaustion",
                        severity="medium",
                        title=f"Excessive {field_name} limit: {value}",
                        description=f"The {field_name} is set to {value}, which could lead to excessive token consumption and high costs.",
                        evidence=f"Configuration: {field_name}={value}",
                        remediation="Consider reducing max_tokens to a reasonable limit for your use case.",
                        cwe="CWE-400",
                    )
                )

    # Check for missing rate limiting
    if manifest:
        # Check for rate limiting configuration
        has_rate_limit = False
        if "rateLimit" in manifest or "rate_limit" in manifest:
            has_rate_limit = True
        if "mcpServers" in manifest:
            for server in manifest.get("mcpServers", {}).values():
                if isinstance(server, dict) and ("rateLimit" in server or "rate_limit" in server):
                    has_rate_limit = True

        if not has_rate_limit and "mcpServers" in manifest:
            findings.append(
                FindingCreate(
                    category="resource_exhaustion",
                    severity="low",
                    title="No rate limiting configured",
                    description="No rate limiting configuration found. This could allow excessive API calls leading to denial-of-wallet attacks.",
                    evidence="No rateLimit or rate_limit found in configuration",
                    remediation="Add rate limiting to prevent abuse and control costs.",
                    cwe="CWE-770",
                )
            )

    # Check for very large context windows
    context_patterns = [
        (r'"context_window"\s*:\s*(\d+)', "context_window"),
        (r'"max_context"\s*:\s*(\d+)', "max_context"),
        (r'"contextLength"\s*:\s*(\d+)', "contextLength"),
    ]

    for pattern, field_name in context_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            value = int(match.group(1))
            if value > 1000000:
                findings.append(
                    FindingCreate(
                        category="resource_exhaustion",
                        severity="low",
                        title=f"Very large context window: {value} tokens",
                        description=f"The context window is set to {value} tokens, which could increase processing costs and latency.",
                        evidence=f"Configuration: {field_name}={value}",
                        remediation="Ensure the context window size is appropriate for your use case.",
                        cwe="CWE-400",
                    )
                )

    # Check for agent loops without iteration limits
    loop_patterns = [
        r'(?:while|for)\s*\(\s*(?:true|1)\s*\)',
        r'while\s*\(\s*1\s*\)\s*\{',
        r'(?:maxIterations|max_iterations|maxLoops)\s*:\s*(\d+)',
    ]

    has_unbounded_loop = False
    has_iteration_limit = False

    for pattern in loop_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            if "maxIterations" in pattern or "max_iterations" in pattern or "maxLoops" in pattern:
                has_iteration_limit = True
                value = int(match.group(1))
                if value > 100:
                    findings.append(
                        FindingCreate(
                            category="resource_exhaustion",
                            severity="medium",
                            title=f"High iteration limit: {value}",
                            description=f"The agent loop iteration limit is set to {value}, which could lead to excessive resource consumption.",
                            evidence=f"Configuration: iteration_limit={value}",
                            remediation="Consider reducing the iteration limit to prevent runaway agent loops.",
                            cwe="CWE-400",
                        )
                    )
            else:
                has_unbounded_loop = True

    if has_unbounded_loop and not has_iteration_limit:
        findings.append(
            FindingCreate(
                category="resource_exhaustion",
                severity="high",
                title="Unbounded agent loop detected",
                description="An unbounded loop was detected without an iteration limit. This could allow an agent to run indefinitely, consuming resources.",
                evidence="Pattern: while(true) or while(1) without maxIterations",
                remediation="Add a maximum iteration limit to prevent runaway agent loops.",
                cwe="CWE-400",
            )
        )

    return findings


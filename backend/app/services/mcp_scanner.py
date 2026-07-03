import json
import re

import httpx

from ..detection.patterns import DANGEROUS_PERMISSIONS, PROMPT_INJECTION_PATTERNS
from ..detection.utils import detect_secrets, extract_urls
from ..schemas import FindingCreate
from .external_analyzer import analyze_urls

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
]


async def scan_mcp_server(target: str, deep: bool = True, timeout: int = 120, inline_content: str | None = None) -> tuple[list[FindingCreate], dict]:
    findings: list[FindingCreate] = []
    metadata: dict = {"files_analyzed": 0, "urls_checked": 0, "deps_analyzed": 0}
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

    # Extract URLs for external analysis
    urls_found.extend(extract_urls(content))
    urls_found.extend(extract_urls(json.dumps(manifest) if manifest else ""))

    # External URL analysis
    if deep and urls_found:
        url_findings, checked = await analyze_urls(urls_found, timeout=min(timeout, 15))
        findings.extend(url_findings)
        metadata["urls_checked"] = checked

    return findings, metadata


async def _fetch_url_manifest(url: str, timeout: int) -> tuple[str, dict | None]:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
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
                            if perm_key in str(tool).lower() or perm_key in tool_desc.lower():
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
                full_cmd = command + " " + " ".join(args if isinstance(args, list) else [])
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


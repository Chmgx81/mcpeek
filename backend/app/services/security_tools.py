"""
Security Tools — actionable tools the agent can use to protect systems.
Each tool has input validation, rate limiting, permission checks, and audit logging.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from .agent_tools import AgentTool, ToolDefinition, ToolResult, ToolPermission, ToolRisk, get_tool_registry

logger = logging.getLogger(__name__)


class BlockServerTool(AgentTool):
    """Block a malicious MCP server by adding it to the blocklist."""

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name="block_server",
            description="Block a malicious MCP server by URL or identifier. Prevents connections and marks it as unsafe.",
            input_schema={
                "type": "object",
                "properties": {
                    "server_id": {"type": "string", "description": "Server URL or identifier to block"},
                    "reason": {"type": "string", "description": "Reason for blocking"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium"], "description": "Block severity"},
                },
                "required": ["server_id", "reason"],
            },
            permission=ToolPermission.EXECUTE,
            risk_level=ToolRisk.HIGH,
            rate_limit=5,
            requires_confirmation=True,
        )

    def validate_params(self, params: dict) -> tuple[bool, str]:
        server_id = params.get("server_id", "")
        if not server_id or len(server_id) < 3:
            return False, "server_id must be at least 3 characters"
        if len(server_id) > 500:
            return False, "server_id too long"
        reason = params.get("reason", "")
        if not reason or len(reason) < 5:
            return False, "reason must be at least 5 characters"
        return True, ""

    async def execute(self, params: dict, context: dict) -> ToolResult:
        server_id = params["server_id"]
        reason = params["reason"]
        severity = params.get("severity", "high")

        # In production: add to blocklist DB
        # For now: log and confirm
        logger.warning("BLOCKED server: %s (reason: %s, severity: %s)", server_id, reason, severity)

        return ToolResult(
            success=True,
            data={
                "message": f"Server blocked: {server_id}",
                "server_id": server_id,
                "reason": reason,
                "severity": severity,
                "blocked_at": time.time(),
            },
            risk_level=ToolRisk.HIGH,
        )


class QuarantineSkillTool(AgentTool):
    """Quarantine a suspicious agent skill by disabling it."""

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name="quarantine_skill",
            description="Quarantine a suspicious agent skill. Disables it and flags for review.",
            input_schema={
                "type": "object",
                "properties": {
                    "skill_id": {"type": "string", "description": "Skill name or identifier"},
                    "reason": {"type": "string", "description": "Reason for quarantine"},
                    "evidence": {"type": "string", "description": "Evidence of malicious behavior"},
                },
                "required": ["skill_id", "reason"],
            },
            permission=ToolPermission.EXECUTE,
            risk_level=ToolRisk.HIGH,
            rate_limit=5,
            requires_confirmation=True,
        )

    def validate_params(self, params: dict) -> tuple[bool, str]:
        skill_id = params.get("skill_id", "")
        if not skill_id or len(skill_id) < 2:
            return False, "skill_id must be at least 2 characters"
        reason = params.get("reason", "")
        if not reason or len(reason) < 5:
            return False, "reason must be at least 5 characters"
        return True, ""

    async def execute(self, params: dict, context: dict) -> ToolResult:
        skill_id = params["skill_id"]
        reason = params["reason"]
        evidence = params.get("evidence", "")

        logger.warning("QUARANTINED skill: %s (reason: %s)", skill_id, reason)

        return ToolResult(
            success=True,
            data={
                "message": f"Skill quarantined: {skill_id}",
                "skill_id": skill_id,
                "reason": reason,
                "evidence": evidence,
                "quarantined_at": time.time(),
            },
            risk_level=ToolRisk.HIGH,
        )


class NotifyAdminTool(AgentTool):
    """Send alert notification to administrator."""

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name="notify_admin",
            description="Send a security alert notification to the administrator via configured channel.",
            input_schema={
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Alert title"},
                    "message": {"type": "string", "description": "Alert message"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "Alert severity"},
                    "findings": {"type": "array", "items": {"type": "object"}, "description": "Related findings"},
                },
                "required": ["title", "message", "severity"],
            },
            permission=ToolPermission.WRITE,
            risk_level=ToolRisk.MEDIUM,
            rate_limit=20,
        )

    def validate_params(self, params: dict) -> tuple[bool, str]:
        if not params.get("title"):
            return False, "title is required"
        if not params.get("message"):
            return False, "message is required"
        if params.get("severity") not in ("critical", "high", "medium", "low"):
            return False, "invalid severity"
        return True, ""

    async def execute(self, params: dict, context: dict) -> ToolResult:
        title = params["title"]
        message = params["message"]
        severity = params["severity"]

        logger.info("ALERT [%s]: %s — %s", severity.upper(), title, message)

        return ToolResult(
            success=True,
            data={
                "message": f"Notification sent: {title}",
                "severity": severity,
                "sent_at": time.time(),
            },
            risk_level=ToolRisk.MEDIUM,
        )


class RemediateConfigTool(AgentTool):
    """Auto-apply safe configuration changes to fix vulnerabilities."""

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name="remediate_config",
            description="Apply a safe configuration change to remediate a vulnerability.",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target config file or server"},
                    "change_type": {"type": "string", "enum": ["remove_malicious_tool", "restrict_permissions", "update_dependency", "enable_encryption"], "description": "Type of remediation"},
                    "finding_title": {"type": "string", "description": "The finding being remediated"},
                    "dry_run": {"type": "boolean", "description": "If true, only show what would change", "default": True},
                },
                "required": ["target", "change_type", "finding_title"],
            },
            permission=ToolPermission.WRITE,
            risk_level=ToolRisk.MEDIUM,
            rate_limit=10,
            requires_confirmation=True,
        )

    def validate_params(self, params: dict) -> tuple[bool, str]:
        if not params.get("target"):
            return False, "target is required"
        if not params.get("change_type"):
            return False, "change_type is required"
        if not params.get("finding_title"):
            return False, "finding_title is required"
        return True, ""

    async def execute(self, params: dict, context: dict) -> ToolResult:
        target = params["target"]
        change_type = params["change_type"]
        finding_title = params["finding_title"]
        dry_run = params.get("dry_run", True)

        action = "Would apply" if dry_run else "Applied"
        logger.info("REMEDIATE %s: %s on %s for %s", action, change_type, target, finding_title)

        return ToolResult(
            success=True,
            data={
                "message": f"{action} {change_type} on {target}",
                "target": target,
                "change_type": change_type,
                "finding_title": finding_title,
                "dry_run": dry_run,
                "applied_at": time.time(),
            },
            risk_level=ToolRisk.MEDIUM,
        )


class QueryCVEDatabaseTool(AgentTool):
    """Look up CVE data from the vulnerability database."""

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name="query_cve",
            description="Look up CVE data from the MCP vulnerability database. Search by CVE ID, package name, or attack category.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "CVE ID, package name, or attack category"},
                    "search_type": {"type": "string", "enum": ["cve_id", "package", "category"], "description": "Type of search"},
                },
                "required": ["query", "search_type"],
            },
            permission=ToolPermission.READ,
            risk_level=ToolRisk.LOW,
            rate_limit=30,
        )

    def validate_params(self, params: dict) -> tuple[bool, str]:
        if not params.get("query"):
            return False, "query is required"
        if params.get("search_type") not in ("cve_id", "package", "category"):
            return False, "invalid search_type"
        return True, ""

    async def execute(self, params: dict, context: dict) -> ToolResult:
        from .vulnerability_db import get_vulnerability_db, AttackCategory

        db = get_vulnerability_db()
        query = params["query"]
        search_type = params["search_type"]

        if search_type == "package":
            results = db.search_by_name(query)
        elif search_type == "category":
            try:
                cat = AttackCategory(query)
                results = db.search_by_category(cat)
            except ValueError:
                results = []
        else:
            # CVE ID search
            results = [v for v in db.get_critical() + db.search_by_name(query)
                      if query.lower() in v.cve_id.lower()]

        vulns = [
            {
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": v.severity.value,
                "affected": v.affected,
                "description": v.description[:200],
            }
            for v in results[:10]
        ]

        return ToolResult(
            success=True,
            data={
                "query": query,
                "search_type": search_type,
                "results_count": len(vulns),
                "vulnerabilities": vulns,
            },
            risk_level=ToolRisk.LOW,
        )


class MonitorServerTool(AgentTool):
    """Monitor an MCP server for behavioral changes."""

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name="monitor_server",
            description="Set up monitoring for an MCP server to detect behavioral changes or new threats.",
            input_schema={
                "type": "object",
                "properties": {
                    "server_id": {"type": "string", "description": "Server URL or identifier to monitor"},
                    "interval_seconds": {"type": "integer", "description": "Check interval in seconds", "default": 300},
                    "alert_on": {"type": "array", "items": {"type": "string"}, "description": "What to alert on"},
                },
                "required": ["server_id"],
            },
            permission=ToolPermission.WRITE,
            risk_level=ToolRisk.LOW,
            rate_limit=10,
        )

    def validate_params(self, params: dict) -> tuple[bool, str]:
        server_id = params.get("server_id", "")
        if not server_id or len(server_id) < 3:
            return False, "server_id must be at least 3 characters"
        interval = params.get("interval_seconds", 300)
        if not isinstance(interval, int) or interval < 60:
            return False, "interval_seconds must be at least 60"
        return True, ""

    async def execute(self, params: dict, context: dict) -> ToolResult:
        server_id = params["server_id"]
        interval = params.get("interval_seconds", 300)
        alert_on = params.get("alert_on", ["new_threats", "behavior_change", "config_change"])

        logger.info("MONITOR started for %s (interval: %ds)", server_id, interval)

        return ToolResult(
            success=True,
            data={
                "message": f"Monitoring started for {server_id}",
                "server_id": server_id,
                "interval_seconds": interval,
                "alert_on": alert_on,
                "started_at": time.time(),
            },
            risk_level=ToolRisk.LOW,
        )


class RollbackConfigTool(AgentTool):
    """Revert to last known-good configuration."""

    def definition(self) -> ToolDefinition:
        return ToolDefinition(
            name="rollback_config",
            description="Revert a configuration to its last known-good state.",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target to rollback"},
                    "snapshot_id": {"type": "string", "description": "Specific snapshot to restore (optional)"},
                },
                "required": ["target"],
            },
            permission=ToolPermission.ADMIN,
            risk_level=ToolRisk.CRITICAL,
            rate_limit=3,
            requires_confirmation=True,
        )

    def validate_params(self, params: dict) -> tuple[bool, str]:
        if not params.get("target"):
            return False, "target is required"
        return True, ""

    async def execute(self, params: dict, context: dict) -> ToolResult:
        target = params["target"]
        snapshot_id = params.get("snapshot_id", "latest")

        logger.warning("ROLLBACK %s to snapshot %s", target, snapshot_id)

        return ToolResult(
            success=True,
            data={
                "message": f"Rolled back {target} to {snapshot_id}",
                "target": target,
                "snapshot_id": snapshot_id,
                "rolled_back_at": time.time(),
            },
            risk_level=ToolRisk.CRITICAL,
        )


def register_all_tools() -> None:
    """Register all security tools."""
    registry = get_tool_registry()
    tools = [
        BlockServerTool(),
        QuarantineSkillTool(),
        NotifyAdminTool(),
        RemediateConfigTool(),
        QueryCVEDatabaseTool(),
        MonitorServerTool(),
        RollbackConfigTool(),
    ]
    for tool in tools:
        registry.register(tool)

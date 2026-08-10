"""
Agent Tool System — MCP-style tools the agent can call.
Every tool has: input validation, rate limiting, permission checks, audit logging, and defense against abuse.
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ToolPermission(str, Enum):
    """Permission levels required to use a tool."""
    READ = "read"           # Read-only operations
    WRITE = "write"         # Modify configurations
    EXECUTE = "execute"     # Execute actions (block, quarantine)
    ADMIN = "admin"         # Admin operations (delete, emergency)


class ToolRisk(str, Enum):
    """Risk level of a tool's actions."""
    LOW = "low"           # Read-only, no side effects
    MEDIUM = "medium"     # Config changes, reversible
    HIGH = "high"         # Blocking, quarantine, irreversible
    CRITICAL = "critical" # Emergency actions, system-wide impact


@dataclass
class ToolResult:
    """Result of a tool execution."""
    success: bool
    data: dict = field(default_factory=dict)
    error: str = ""
    audit_log: str = ""
    risk_level: ToolRisk = ToolRisk.LOW

    @property
    def summary(self) -> str:
        if self.success:
            return self.data.get("message", "Tool executed successfully")
        return f"Error: {self.error}"


@dataclass
class ToolDefinition:
    """MCP-style tool definition."""
    name: str
    description: str
    input_schema: dict
    permission: ToolPermission
    risk_level: ToolRisk
    rate_limit: int = 10  # max calls per minute
    requires_confirmation: bool = False  # require user confirmation before execution


class ToolRateLimiter:
    """Per-tool rate limiter."""

    def __init__(self) -> None:
        self._calls: dict[str, list[float]] = {}

    def check(self, tool_name: str, limit: int) -> bool:
        """Check if tool call is within rate limit. Returns True if allowed."""
        now = time.time()
        window = 60.0  # 1 minute window

        if tool_name not in self._calls:
            self._calls[tool_name] = []

        # Remove old entries
        self._calls[tool_name] = [
            t for t in self._calls[tool_name] if now - t < window
        ]

        if len(self._calls[tool_name]) >= limit:
            return False

        self._calls[tool_name].append(now)
        return True


class AgentTool(ABC):
    """Base class for all agent tools."""

    @abstractmethod
    def definition(self) -> ToolDefinition:
        """Return the tool's MCP-style definition."""
        ...

    @abstractmethod
    async def execute(self, params: dict, context: dict) -> ToolResult:
        """Execute the tool with validated parameters."""
        ...

    def validate_params(self, params: dict) -> tuple[bool, str]:
        """Validate input parameters. Override for custom validation."""
        return True, ""


class ToolRegistry:
    """Registry of all available tools with defense mechanisms."""

    def __init__(self) -> None:
        self._tools: dict[str, AgentTool] = {}
        self._rate_limiter = ToolRateLimiter()
        self._audit_log: list[dict] = []
        self._blocked_tools: set[str] = set()  # Tools blocked by agent defense

    def register(self, tool: AgentTool) -> None:
        """Register a tool."""
        defn = tool.definition()
        self._tools[defn.name] = tool
        logger.info("Registered tool: %s (risk=%s, perm=%s)", defn.name, defn.risk_level.value, defn.permission.value)

    def get_tool(self, name: str) -> Optional[AgentTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        """List all tool definitions."""
        return [tool.definition() for tool in self._tools.values()]

    def is_rate_limited(self, tool_name: str) -> bool:
        """Check if a tool call would be rate limited."""
        tool = self._tools.get(tool_name)
        if not tool:
            return True
        defn = tool.definition()
        return not self._rate_limiter.check(tool_name, defn.rate_limit)

    def execute_tool(
        self,
        tool_name: str,
        params: dict,
        context: dict,
    ) -> ToolResult:
        """Execute a tool with full defense checks."""

        # 1. Check if tool exists
        tool = self._tools.get(tool_name)
        if not tool:
            return ToolResult(success=False, error=f"Unknown tool: {tool_name}")

        # 2. Check if tool is blocked by agent defense
        if tool_name in self._blocked_tools:
            self._audit("blocked", tool_name, params, "Tool blocked by agent defense")
            return ToolResult(success=False, error=f"Tool blocked by security policy: {tool_name}")

        defn = tool.definition()

        # 3. Check rate limit
        if not self._rate_limiter.check(tool_name, defn.rate_limit):
            self._audit("rate_limited", tool_name, params, "Rate limit exceeded")
            return ToolResult(success=False, error=f"Rate limit exceeded for {tool_name}")

        # 4. Check permissions
        required_perm = defn.permission
        context_perm = context.get("permission", ToolPermission.READ)
        if not self._has_permission(context_perm, required_perm):
            self._audit("permission_denied", tool_name, params, f"Need {required_perm.value}, have {context_perm}")
            return ToolResult(success=False, error=f"Permission denied: requires {required_perm.value}")

        # 5. Validate parameters
        valid, error = tool.validate_params(params)
        if not valid:
            self._audit("validation_failed", tool_name, params, error)
            return ToolResult(success=False, error=f"Validation failed: {error}")

        # 6. Check for injection attempts in parameters
        injection_check = self._check_injection(params)
        if injection_check:
            self._audit("injection_blocked", tool_name, params, injection_check)
            logger.warning("Tool injection attempt blocked: %s — %s", tool_name, injection_check)
            return ToolResult(success=False, error=f"Security: {injection_check}")

        # 7. Execute
        try:
            result = tool.execute(params, context)
            self._audit("executed", tool_name, params, result.summary)
            return result
        except Exception as e:
            self._audit("error", tool_name, params, str(e))
            logger.exception("Tool execution failed: %s", tool_name)
            return ToolResult(success=False, error=f"Execution failed: {e}")

    def block_tool(self, tool_name: str) -> None:
        """Block a tool (called by agent defense)."""
        self._blocked_tools.add(tool_name)
        self._audit("tool_blocked", tool_name, {}, "Tool blocked by security policy")
        logger.warning("Tool blocked: %s", tool_name)

    def unblock_tool(self, tool_name: str) -> None:
        """Unblock a tool."""
        self._blocked_tools.discard(tool_name)
        self._audit("tool_unblocked", tool_name, {}, "Tool unblocked")

    def _has_permission(self, have: ToolPermission, need: ToolPermission) -> bool:
        """Check if current permission level satisfies requirement."""
        levels = {ToolPermission.READ: 0, ToolPermission.WRITE: 1, ToolPermission.EXECUTE: 2, ToolPermission.ADMIN: 3}
        return levels.get(have, 0) >= levels.get(need, 0)

    def _check_injection(self, params: dict) -> str:
        """Check for injection attempts in tool parameters."""
        import re
        for key, value in params.items():
            if not isinstance(value, str):
                continue
            # Check for command injection
            if re.search(r'[;&|`$]', value):
                return f"Potential command injection in parameter '{key}'"
            # Check for path traversal
            if '..' in value and ('/' in value or '\\' in value):
                return f"Potential path traversal in parameter '{key}'"
            # Check for prompt injection
            if re.search(r'ignore\s+(?:all\s+)?(?:previous|prior|system)', value, re.IGNORECASE):
                return f"Potential prompt injection in parameter '{key}'"
        return ""

    def _audit(self, action: str, tool_name: str, params: dict, detail: str) -> None:
        """Log tool execution for audit trail."""
        import hashlib
        entry = {
            "timestamp": time.time(),
            "action": action,
            "tool": tool_name,
            "params_hash": hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest()[:16],
            "detail": detail,
        }
        self._audit_log.append(entry)
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-500:]

    def get_audit_log(self, limit: int = 50) -> list[dict]:
        """Get recent audit log entries."""
        return self._audit_log[-limit:]


# Singleton
_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry

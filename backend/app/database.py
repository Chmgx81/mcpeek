"""Async Turso database client via HTTP API (replaces SQLAlchemy for Vercel)."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import settings

logger = logging.getLogger(__name__)

_client: httpx.AsyncClient | None = None


def _http_base_url() -> str:
    url = settings.TURSO_DATABASE_URL
    return url.replace("libsql://", "https://").replace("libsqls://", "https://")


async def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=_http_base_url(),
            headers={
                "Authorization": f"Bearer {settings.TURSO_AUTH_TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
    return _client


async def execute(sql: str, args: list[Any] | None = None) -> dict:
    """Execute a single SQL statement and return the raw result."""
    client = await _get_client()
    payload = {
        "statements": [{"q": sql, "params": args or []}]
    }
    resp = await client.post("", content=json.dumps(payload))
    resp.raise_for_status()
    data = resp.json()
    if data and isinstance(data, list) and len(data) > 0:
        return data[0].get("results", {})
    return {}


async def execute_batch(statements: list[dict[str, Any]]) -> dict:
    """Execute multiple SQL statements in a batch."""
    client = await _get_client()
    stmts = [{"q": s["sql"], "params": s.get("args", [])} for s in statements]
    payload = {"statements": stmts}
    resp = await client.post("", content=json.dumps(payload))
    resp.raise_for_status()
    return resp.json()


async def fetch_one(sql: str, args: list[Any] | None = None) -> dict[str, Any] | None:
    """Execute SQL and return the first row as a dict, or None."""
    result = await execute(sql, args)
    cols = result.get("columns", [])
    rows = result.get("rows", [])
    if not rows:
        return None
    return dict(zip(cols, rows[0]))


async def fetch_all(sql: str, args: list[Any] | None = None) -> list[dict[str, Any]]:
    """Execute SQL and return all rows as dicts."""
    result = await execute(sql, args)
    cols = result.get("columns", [])
    rows = result.get("rows", [])
    return [dict(zip(cols, row)) for row in rows]


async def fetch_val(sql: str, args: list[Any] | None = None) -> Any:
    """Execute SQL and return the first column of the first row."""
    row = await fetch_one(sql, args)
    if row is None:
        return None
    return list(row.values())[0]


async def record_audit_event(
    event_type: str,
    *,
    scan_id: str | None = None,
    workspace_id: str | None = None,
    target: str | None = None,
    request_id: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    payload = details or {}
    await execute(
        """INSERT INTO audit_events (id, event_type, scan_id, workspace_id, target, request_id, client_ip, user_agent, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            str(uuid.uuid4()),
            event_type,
            scan_id,
            workspace_id or "public",
            target,
            request_id,
            client_ip,
            user_agent,
            json.dumps(payload),
            datetime.now(timezone.utc).isoformat(),
        ],
    )


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    label TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    scopes_json TEXT NOT NULL DEFAULT '["workspace:scan"]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL DEFAULT 'public',
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    overall_risk INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'safe',
    summary_json TEXT NOT NULL DEFAULT '{}',
    scan_duration_ms INTEGER NOT NULL DEFAULT 0,
    files_analyzed INTEGER NOT NULL DEFAULT 0,
    urls_checked INTEGER NOT NULL DEFAULT 0,
    deps_analyzed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    error_message TEXT,
    content_hashes_json TEXT NOT NULL DEFAULT '{}',
    rescan_of TEXT,
    inline_content TEXT,
    request_id TEXT,
    client_ip TEXT,
    user_agent TEXT,
    ai_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    scan_id TEXT,
    workspace_id TEXT NOT NULL DEFAULT 'public',
    target TEXT,
    request_id TEXT,
    client_ip TEXT,
    user_agent TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id),
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    cwe TEXT,
    owasp TEXT,
    references_json TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'heuristic'
);
"""


async def init_db() -> None:
    """Create tables if they don't exist."""
    statements = [s.strip() for s in SCHEMA_SQL.strip().split(";") if s.strip()]
    for stmt in statements:
        await execute(stmt)
    try:
        await execute("INSERT INTO workspaces (id, name) VALUES (?, ?)", ["public", "Public Workspace"])
    except Exception:
        pass
    # Migration: add source column to findings table if missing
    try:
        await execute("ALTER TABLE findings ADD COLUMN source TEXT NOT NULL DEFAULT 'heuristic'")
    except Exception:
        pass  # Column already exists
    for stmt in (
        "ALTER TABLE scans ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'public'",
        "ALTER TABLE scans ADD COLUMN request_id TEXT",
        "ALTER TABLE scans ADD COLUMN client_ip TEXT",
        "ALTER TABLE scans ADD COLUMN user_agent TEXT",
        "ALTER TABLE audit_events ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'public'",
    ):
        try:
            await execute(stmt)
        except Exception:
            pass
    for stmt in (
        "UPDATE scans SET workspace_id = 'public' WHERE workspace_id IS NULL OR workspace_id = ''",
        "UPDATE audit_events SET workspace_id = 'public' WHERE workspace_id IS NULL OR workspace_id = ''",
    ):
        try:
            await execute(stmt)
        except Exception:
            pass
    logger.info("Database tables initialized")

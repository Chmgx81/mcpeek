"""Async Turso database client via HTTP API (replaces SQLAlchemy for Vercel)."""

from __future__ import annotations

import json
import logging
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


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
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
    ai_json TEXT NOT NULL DEFAULT '{}'
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
    references_json TEXT NOT NULL DEFAULT '[]'
);
"""


async def init_db() -> None:
    """Create tables if they don't exist."""
    statements = [s.strip() for s in SCHEMA_SQL.strip().split(";") if s.strip()]
    for stmt in statements:
        await execute(stmt)
    logger.info("Database tables initialized")

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, Request

from .config import settings
from .database import execute, fetch_one

PUBLIC_WORKSPACE_ID = "public"


@dataclass(slots=True)
class WorkspaceContext:
    workspace_id: str
    workspace_name: str
    authenticated: bool = False
    api_key_id: str | None = None


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _extract_api_key(request: Request) -> str | None:
    auth_header = (request.headers.get("authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if token:
            return token
    for header_name in ("x-mcpeek-api-key", "x-api-key"):
        value = (request.headers.get(header_name) or "").strip()
        if value:
            return value
    return None


async def ensure_public_workspace() -> None:
    await execute("INSERT INTO workspaces (id, name) VALUES (?, ?)", [PUBLIC_WORKSPACE_ID, "Public Workspace"])


async def resolve_workspace(request: Request) -> WorkspaceContext:
    api_key = _extract_api_key(request)
    if not api_key:
        row = await fetch_one("SELECT id, name FROM workspaces WHERE id = ?", [PUBLIC_WORKSPACE_ID])
        if not row:
            await ensure_public_workspace()
            row = {"id": PUBLIC_WORKSPACE_ID, "name": "Public Workspace"}
        return WorkspaceContext(workspace_id=row["id"], workspace_name=row["name"], authenticated=False)

    row = await fetch_one(
        """SELECT ak.id AS api_key_id, w.id AS workspace_id, w.name AS workspace_name
        FROM api_keys ak
        JOIN workspaces w ON w.id = ak.workspace_id
        WHERE ak.key_hash = ? AND ak.revoked_at IS NULL""",
        [_hash_api_key(api_key)],
    )
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    await execute(
        "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
        [datetime.now(timezone.utc).isoformat(), row["api_key_id"]],
    )
    return WorkspaceContext(
        workspace_id=row["workspace_id"],
        workspace_name=row["workspace_name"],
        authenticated=True,
        api_key_id=row["api_key_id"],
    )


async def require_admin(request: Request) -> None:
    if not settings.ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Admin API key is not configured")
    provided = (
        request.headers.get("x-mcpeek-admin-key")
        or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    )
    if provided != settings.ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")


async def create_workspace(name: str) -> tuple[str, str, str]:
    workspace_id = str(uuid.uuid4())
    api_key = secrets.token_urlsafe(32)
    key_hash = _hash_api_key(api_key)
    key_prefix = api_key[:8]
    await execute("INSERT INTO workspaces (id, name) VALUES (?, ?)", [workspace_id, name])
    await execute(
        "INSERT INTO api_keys (id, workspace_id, label, key_hash, key_prefix, scopes_json) VALUES (?, ?, ?, ?, ?, ?)",
        [str(uuid.uuid4()), workspace_id, "default", key_hash, key_prefix, '["workspace:scan","workspace:read"]'],
    )
    return workspace_id, api_key, key_prefix
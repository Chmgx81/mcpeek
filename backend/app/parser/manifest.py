from __future__ import annotations

import json

import httpx



async def fetch_url_manifest(url: str, timeout: int) -> tuple[str, dict | None]:
    """Fetch a manifest from a URL and attempt JSON parse."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "MCPeek/0.1"})
            resp.raise_for_status()
            text = resp.text
        try:
            return text, json.loads(text)
        except json.JSONDecodeError:
            return text, None
    except Exception:
        return "", None


def read_local_manifest(path: str) -> tuple[str, dict | None]:
    """Read and optionally parse a local manifest file."""
    try:
        with open(path) as f:
            text = f.read()
        try:
            return text, json.loads(text)
        except json.JSONDecodeError:
            return text, None
    except Exception:
        return "", None

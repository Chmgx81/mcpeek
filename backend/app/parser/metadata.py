from __future__ import annotations

import httpx


async def fetch_npm_package(name: str) -> dict | None:
    """Fetch npm package metadata from the registry."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://registry.npmjs.org/{name}",
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return None


async def fetch_pypi_package(name: str) -> dict | None:
    """Fetch PyPI package metadata from the JSON API."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://pypi.org/pypi/{name}/json",
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return None

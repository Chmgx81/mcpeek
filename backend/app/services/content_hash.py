"""URL content hashing for bait-and-switch detection.

Stores SHA-256 of fetched external content. On re-scan, compares against
the previous hash to detect if the payload has changed.
"""

from __future__ import annotations

import hashlib
import json
import logging
from urllib.parse import urlparse

import httpx
from httpx import URL

from .url_safety import is_safe_public_url

logger = logging.getLogger(__name__)


def compute_content_hash(content: str | bytes) -> str:
    """Compute SHA-256 hash of content."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


async def hash_external_urls(
    urls: list[str], timeout: int = 15
) -> dict[str, str]:
    """Fetch each URL and return {url: sha256_hash} mapping.

    Caps at 20 URLs. Only hashes http/https URLs that return text content.
    """
    hashes: dict[str, str] = {}

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "MCPeek/0.1 Content-Hash"},
    ) as client:
        for url in urls[:20]:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not is_safe_public_url(url):
                continue
            try:
                resp = await client.get(url, follow_redirects=False)
                if 300 <= resp.status_code < 400 and "location" in resp.headers:
                    redirected = str(URL(url).join(resp.headers["location"]))
                    if not is_safe_public_url(redirected):
                        continue
                    resp = await client.get(redirected, follow_redirects=False)
                resp.raise_for_status()
                # Hash the raw bytes (not decoded) to catch encoding tricks
                raw = resp.content[:1_000_000]
                hashes[url] = compute_content_hash(raw)
            except Exception:
                pass

    return hashes


def compare_hashes(
    old_hashes: dict[str, str], new_hashes: dict[str, str]
) -> list[dict]:
    """Compare old vs new URL hashes. Returns list of changes detected.

    Each change dict has: url, old_hash, new_hash, status
    status is "changed", "added", or "removed"
    """
    changes = []

    all_urls = set(old_hashes) | set(new_hashes)
    for url in sorted(all_urls):
        old = old_hashes.get(url)
        new = new_hashes.get(url)
        if old and not new:
            changes.append({"url": url, "old_hash": old, "new_hash": None, "status": "removed"})
        elif not old and new:
            changes.append({"url": url, "old_hash": None, "new_hash": new, "status": "added"})
        elif old != new:
            changes.append({"url": url, "old_hash": old, "new_hash": new, "status": "changed"})

    return changes


def hashes_to_json(hashes: dict[str, str]) -> str:
    """Serialize hashes to JSON string for DB storage."""
    return json.dumps(hashes)


def hashes_from_json(raw: str) -> dict[str, str]:
    """Deserialize hashes from JSON string."""
    try:
        return json.loads(raw) if raw else {}
    except (json.JSONDecodeError, TypeError):
        return {}

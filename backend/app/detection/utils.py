"""Shared detection utilities used across all MCPeek scanners."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..schemas import FindingCreate
from .patterns import SECRET_PATTERNS


def detect_secrets(content: str, source_name: str = "content") -> list[FindingCreate]:
    """Detect hardcoded secrets and credentials in content."""
    findings: list[FindingCreate] = []
    seen: set[str] = set()

    for pattern, name, cwe in SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            matched_text = match.group(0)
            key = f"{name}:{matched_text[:8]}"
            if key in seen:
                continue
            seen.add(key)

            redacted = (
                matched_text[:4] + "*" * (len(matched_text) - 8) + matched_text[-4:]
                if len(matched_text) > 12
                else matched_text[:2] + "***"
            )

            findings.append(
                FindingCreate(
                    category="secrets",
                    severity="high",
                    title=f"{name} detected in {source_name}",
                    description=f"A {name.lower()} was found in the scanned content. Hardcoded credentials can be extracted by anyone with access to the source.",
                    evidence=f"Pattern: {redacted}\nLocation: {source_name}",
                    remediation="Move secrets to environment variables or a secrets manager. Rotate the exposed credential immediately.",
                    cwe=cwe,
                    references=["https://cwe.mitre.org/data/definitions/798.html"],
                )
            )

    return findings


def extract_urls(text: str, max_urls: int = 20) -> list[str]:
    """Extract external URLs from text, filtering out common safe domains."""
    url_pattern = re.compile(r"https?://[^\s<>\"')\]]+")
    urls = url_pattern.findall(text)
    skip_domains = {"github.com", "npmjs.com", "pypi.org", "python.org", "docs.python.org", "nodejs.org"}
    filtered = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc and not any(d in parsed.netloc for d in skip_domains):
            filtered.append(url.rstrip(".,;:"))
    return list(set(filtered))[:max_urls]

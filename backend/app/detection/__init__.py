"""Shared detection patterns and utilities for MCPeek scanners."""

from .patterns import (
    DANGEROUS_PERMISSIONS,
    EXFILTRATION_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    SECRET_PATTERNS,
    SHELL_PATTERNS,
    SOCIAL_ENGINEERING_PATTERNS,
)
from .utils import detect_secrets, extract_urls

__all__ = [
    "DANGEROUS_PERMISSIONS",
    "EXFILTRATION_PATTERNS",
    "PROMPT_INJECTION_PATTERNS",
    "SECRET_PATTERNS",
    "SHELL_PATTERNS",
    "SOCIAL_ENGINEERING_PATTERNS",
    "detect_secrets",
    "extract_urls",
]

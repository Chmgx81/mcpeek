"""Static analysis scanner for MCP configs, skills, and packages."""

from .scanner import ScanResult, scan_content

__all__ = ["ScanResult", "scan_content"]

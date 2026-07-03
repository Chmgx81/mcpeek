"""CLI: python -m app.static_scan <file> [--fail-on high]"""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser
from pathlib import Path

from .scanner import scan_content

RISK_ORDER = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main() -> None:
    parser = ArgumentParser(description="Scan an MCP config, package manifest, or agent skill file.")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument(
        "--fail-on",
        choices=RISK_ORDER.keys(),
        default=None,
        help="Exit with code 2 when risk level is at or above this threshold",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print a compact human-readable summary before JSON output",
    )
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    content = path.read_text(encoding="utf-8")
    result = scan_content(content, target_name=path.name, filename=path.name)

    if args.summary:
        print(
            f"MCPeek: {path} -> {result.risk_level.upper()} "
            f"(score {result.risk_score}, findings {len(result.findings)})"
        )

    print(json.dumps(result.to_dict(), indent=2))

    if args.fail_on and RISK_ORDER[result.risk_level] >= RISK_ORDER[args.fail_on]:
        print(
            f"MCPeek policy failed: risk level {result.risk_level} >= {args.fail_on}",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()

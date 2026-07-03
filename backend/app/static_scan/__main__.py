"""CLI: python -m app.static_scan <file>"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .scanner import scan_content


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m app.static_scan <file>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    content = path.read_text()
    result = scan_content(content, target_name=path.name, filename=path.name)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()

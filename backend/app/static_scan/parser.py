"""Parse MCP config inputs: JSON, YAML, or plain text."""

from __future__ import annotations

import json

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


def parse_input(raw: str, filename: str | None = None) -> tuple[str, dict | None]:
    """Parse raw content into (text, structured_dict_or_None).

    Returns the raw text always, plus parsed dict if JSON/YAML.
    """
    text = raw.strip()

    # Try JSON
    try:
        data = json.loads(text)
        return text, data if isinstance(data, dict) else {"_root": data}
    except (json.JSONDecodeError, TypeError):
        pass

    # Try YAML
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return text, data
        except Exception:
            pass

    # Plain text config
    return text, None

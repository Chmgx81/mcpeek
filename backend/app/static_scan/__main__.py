"""CLI: python -m app.static_scan <file> [--fail-on high] [--format json|sarif]"""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser
from pathlib import Path

from .scanner import scan_content

RISK_ORDER = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _to_sarif(result, file_path: str) -> dict:
    """Convert scan result to SARIF 2.1.0 format."""
    rules = []
    results = []
    rule_index = {}

    for finding in result.findings:
        rule_id = finding.category
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": finding.category.replace("_", " ").title(),
                "shortDescription": {"text": finding.title},
                "helpUri": "https://mcpeek.dev/docs/rules",
                "properties": {"tags": ["security"]},
            })

        level_map = {
            "critical": "error", "high": "error",
            "medium": "warning", "low": "note", "info": "note",
        }

        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "message": {"text": finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }],
            "level": level_map.get(finding.severity, "warning"),
            "properties": {
                "severity": finding.severity,
                "cwe": finding.cwe or "",
                "evidence": finding.evidence[:500],
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MCPeek",
                    "version": "0.1.0",
                    "informationUri": "https://mcpeek.dev",
                    "rules": rules,
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "risk_score": result.risk_score,
                    "risk_level": result.risk_level,
                },
            }],
        }],
    }


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
    parser.add_argument(
        "--format",
        choices=["json", "sarif"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write output to file instead of stdout",
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

    if args.format == "sarif":
        output = json.dumps(_to_sarif(result, path.name), indent=2)
    else:
        output = json.dumps(result.to_dict(), indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.fail_on and RISK_ORDER[result.risk_level] >= RISK_ORDER[args.fail_on]:
        print(
            f"MCPeek policy failed: risk level {result.risk_level} >= {args.fail_on}",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()

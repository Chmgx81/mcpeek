# Hackathon Demo Script

## 90-Second Flow

1. Open the landing page and state the problem:
   "AI agents are starting to run tools through MCP servers and skills. Traditional scanners inspect source code, but MCP risk often lives in runtime config, tool permissions, install scripts, external URLs, and hidden instructions."

2. Open Dashboard and scan `examples/safe-mcp.json` with `Paste Config`.
   Expected result: low-risk or no severe findings.

3. Scan `examples/vulnerable-mcp-curl-shell.json`.
   Expected result: critical/high findings for curl-to-shell, prompt injection, dangerous tools, lifecycle scripts, and secrets.

4. Scan `examples/vulnerable-agent-skill.md`.
   Expected result: prompt injection, hidden instructions, exfiltration, and dangerous tool permissions.

5. Show CI blocking behavior:

```bash
cd backend
python -m app.static_scan ../examples/vulnerable-mcp-curl-shell.json --summary --fail-on high
```

This exits with code `2`, which is how the GitHub Action blocks a pull request.

## Judge-Friendly Pitch

MCPeek is a runtime-aware security scanner for MCP servers and AI agent skills. It catches risks that traditional source scanners miss: hidden prompt injection, dangerous tool permissions, curl-to-shell installs, hardcoded secrets, external resource loading, and AI-specific supply-chain issues. It works as a web scanner and as a CI gate for pull requests.

## Best Themes

- Trust, Identity & Security
- Developer Tools & Software Infrastructure

## Production Path

- Keep the current scanner API and UI.
- Move from SQLite to Postgres.
- Replace FastAPI background tasks with a durable worker queue.
- Run scanner workers in isolated containers.
- Add per-user auth, scan ownership, and organization workspaces.
- Add scheduled scans and PR comments.

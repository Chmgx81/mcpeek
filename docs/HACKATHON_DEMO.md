# HACKHAZARDS '26 — MCPeek

## Tracks

- **Trust, Identity & Security** — MCPeek detects threats that compromise AI agent trust: tool poisoning, prompt injection, bait-and-switch attacks, and supply chain risks in MCP configurations.
- **Developer Tools & Software Infrastructure** — MCPeek is a security scanner that integrates into CI/CD pipelines via GitHub Action, blocking unsafe configs before they reach production.

## Links

| Resource | URL |
|----------|-----|
| Live Demo | https://frontend-lake-eight-70.vercel.app |
| API | https://mcpeek-api-production.up.railway.app/docs |
| GitHub | https://github.com/Chmgx81/mcpeek |
| Demo Video | https://youtu.be/mQXrpGpstA8 |
| Blog Post | https://rootmazex.hashnode.com/mcpeek-catching-security-threats-in-mcp-servers-before-they-execute |

## Team Code

```
AQIR69AK
```

## What It Does

MCPeek scans MCP server configurations and AI agent skills for security risks before they execute. It catches 15+ threat categories including:

- **Shell execution** — `curl | sh`, `bash -c`, `eval`, lifecycle scripts
- **Tool poisoning (OWASP MCP03)** — hidden instructions in tool descriptions
- **Prompt injection** — role override, hierarchy manipulation
- **Hardcoded secrets** — AWS, OpenAI, Stripe keys, database credentials
- **Bait-and-switch** — content hash comparison across rescans
- **SKILLCLOAK** — self-extracting skills with entropy analysis

## Demo Script (90 seconds)

### 1. Open the landing page
State the problem: "AI agents run tools through MCP servers configured via JSON files. These configs can hide shell commands, inject instructions that hijack AI behavior, and expose secrets. Traditional scanners miss these threats because they only look at source code."

### 2. Scan a safe config
Go to Dashboard → Paste Config → paste `examples/safe-mcp.json`
Result: **Safe** (score 100) — demonstrates zero false positives.

### 3. Scan a vulnerable config
Paste `examples/vulnerable-mcp-curl-shell.json`
Result: **Critical** (score 0) — 14 findings including shell execution, prompt injection, hardcoded secrets, and lifecycle scripts.

### 4. Scan an agent skill
Paste `examples/vulnerable-agent-skill.md`
Result: **Critical** — prompt injection, hidden instructions, exfiltration patterns.

### 5. Show CI blocking
```bash
cd backend && source .venv/bin/activate
python -m app.static_scan ../examples/vulnerable-mcp-curl-shell.json --summary --fail-on high
```
Exits with code 2 — this is how the GitHub Action blocks pull requests.

### 6. Show AI analysis (optional)
Point out the AI-generated attack scenarios and remediation suggestions on the scan results page.

## Judge-Friendly Pitch

MCPeek is a runtime-aware security scanner for MCP servers and AI agent skills. It catches risks that traditional source code scanners miss: hidden prompt injection, dangerous tool permissions, curl-to-shell installs, hardcoded secrets, external resource loading, and AI-specific supply chain issues. It works as a web app, a CLI tool, and a GitHub Action for CI/CD pipelines.

## What Makes It Different

1. **Scans configs, not code** — MCP risk lives in runtime configurations, not source files
2. **Bait-and-switch detection** — SHA-256 content hashing catches URL swaps across rescans
3. **SKILLCLOAK defense** — entropy analysis catches self-extracting skills that bypass static scanners
4. **OWASP MCP Top 10** — purpose-built detection for MCP-specific vulnerability classes
5. **CI/CD integration** — GitHub Action blocks unsafe configs in pull requests

## Stats

- **110 unit tests**, all passing
- **15+ threat categories** detected
- **4 scan targets**: MCP Server, Agent Skill, npm Package, PyPI Package
- **AI analysis** via free OpenRouter models (no credit card required)
- **< 1 second** CLI scan time

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, SQLAlchemy, SQLite |
| Frontend | Next.js, React, Tailwind CSS |
| AI | OpenRouter (free models) |
| Deployment | Railway (API) + Vercel (frontend) |
| CI/CD | GitHub Actions |

## Production Path

- Move from SQLite to PostgreSQL
- Replace FastAPI background tasks with a durable worker queue
- Run scanner workers in isolated containers
- Add per-user auth, scan ownership, and organization workspaces
- Add scheduled scans and PR comments

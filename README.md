<p align="center">
  <img src="frontend/public/logo.svg" width="80" alt="MCPeek logo">
</p>

<h1 align="center">MCPeek</h1>

<p align="center">
  <strong>Peek beyond the manifest.</strong><br>
  Runtime-aware security scanner for MCP servers and AI agent skills.
</p>

<p align="center">
  <a href="https://frontend-lake-eight-70.vercel.app">Live Demo</a> ·
  <a href="https://mcpeek-api-production.up.railway.app/docs">API</a> ·
  <a href="https://github.com/Chmgx81/mcpeek">GitHub</a> ·
  <a href="https://youtu.be/mQXrpGpstA8">Video</a> ·
  <a href="https://rootmazex.hashnode.com/mcpeek-catching-security-threats-in-mcp-servers-before-they-execute">Blog</a>
</p>

---

## TL;DR

AI agents run tools through MCP servers configured via JSON files. These configs can hide shell commands that execute on startup, inject instructions that hijack your AI's behavior, and expose hardcoded secrets. Traditional security tools scan source code — they miss these threats entirely. MCPeek scans the configs, not the code, and catches what matters.

---

## The Problem

MCP (Model Context Protocol) is an open standard that lets AI assistants connect to external tools. The configuration files that define these connections are the real attack surface:

- **Shell execution** — `curl | sh`, `bash -c`, `eval` hidden in install scripts
- **Tool poisoning** — malicious instructions embedded in tool descriptions that override AI behavior
- **Hardcoded secrets** — AWS keys, API tokens, database credentials in plaintext
- **Bait-and-switch** — clean code served initially, swapped for malicious payloads after approval
- **Supply chain risks** — unpinned dependencies, lifecycle scripts, external resource loading

MCPeek detects **15+ threat categories** including all OWASP MCP Top 10 vulnerabilities.

---

## Demo

<p align="center">
  <a href="https://youtu.be/mQXrpGpstA8?autoplay=1">
    <img src="https://img.youtube.com/vi/mQXrpGpstA8/0.jpg" alt="MCPeek Demo" width="600">
  </a>
</p>

<p align="center">
  <em>90-second walkthrough: paste a config → scan → review findings → AI analysis</em>
</p>

---

## Quick Start

### Try It Online

Visit **[mcpeek.dev](https://frontend-lake-eight-70.vercel.app)** — no account required.

### Run Locally

```bash
git clone https://github.com/Chmgx81/mcpeek.git
cd mcpeek

# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000**

### CLI Scanner

```bash
cd backend && source .venv/bin/activate

# Scan a config file
python -m app.static_scan path/to/config.json

# CI gate (exits non-zero if risk >= threshold)
python -m app.static_scan config.json --fail-on high --summary
```

---

## Features

### What MCPeek Detects

| Category | Threats |
|----------|---------|
| **Shell Execution** | `curl \| sh`, `bash -c`, `eval`, `os.system`, `subprocess`, lifecycle scripts (`postinstall`, `preinstall`) |
| **Prompt Injection** | Role override, instruction leakage, hierarchy manipulation, homoglyphs |
| **Tool Poisoning (OWASP MCP03)** | Hidden instructions in tool descriptions, exfiltration commands, behavioral overrides |
| **Hardcoded Secrets** | AWS, OpenAI, Stripe, GitHub tokens, private keys, database credentials |
| **Scope Creep (OWASP MCP02)** | Overly broad tool permissions, unrestricted access patterns |
| **External Dependencies** | Unpinned packages, suspicious domains, typosquatting, remote script loading |
| **Bait-and-Switch** | Content hash comparison, URL change detection, dependency risk scoring |
| **SKILLCLOAK** | Self-extracting skills with entropy analysis, hidden directory auditing, decoder detection |

### AI-Powered Analysis

Optional deep analysis using free OpenRouter models (no credit card required):

- **Attack Scenarios** — context-specific attack narratives from your actual findings
- **Risk Narrative** — plain-English executive summary with approve/reject verdict
- **Remediation** — specific config fixes for each issue
- **Threat Intelligence** — CVE mapping and MITRE ATT&CK technique matching

---

## Supported Targets

| Target Type | What Gets Scanned |
|-------------|-------------------|
| **MCP Server** | GitHub URLs, local files, inline JSON configs |
| **Agent Skill** | `.cursorrules`, `AGENTS.md`, `SKILL.md` files |
| **npm Package** | Registry metadata, lifecycle scripts, dependency analysis |
| **PyPI Package** | Registry metadata, classifiers, dependency analysis |

---

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Submit a scan |
| `GET` | `/api/v1/scan/{id}` | Get scan results |
| `POST` | `/api/v1/scan/{id}/rescan` | Re-scan for bait-and-switch |
| `GET` | `/api/v1/report/{id}/full` | Full structured report |
| `GET` | `/api/v1/report/{id}/export?format=json` | Export as JSON |
| `GET` | `/api/v1/scans` | List scans (paginated) |
| `GET` | `/api/v1/stats` | Dashboard statistics |

Full interactive docs at **[/docs](https://mcpeek-api-production.up.railway.app/docs)**.

---

## CI/CD Integration

Block unsafe MCP configs in pull requests with the GitHub Action:

```yaml
name: MCPeek
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Chmgx81/mcpeek@main
        with:
          path: config/mcp-server.json
          fail-on: high
```

The action exits with code 2 when findings exceed the threshold, blocking the merge.

---

## Architecture

```
Input (URL / Paste / Package)
    ↓
Fetch & Parse (HTTP GET, JSON parse, registry lookup)
    ↓
Static Analysis (regex patterns, AST parsing, config inspection)
    ↓
Advanced Detection (OWASP MCP, injection, tool poisoning)
    ↓
SKILLCLOAK Defense (entropy, blobs, decoder patterns, manifest abuse)
    ↓
Trust Scoring (domain reputation, dependency risk, supply chain)
    ↓
AI Analysis (optional: attack scenarios, remediation, narrative)
    ↓
Report (risk score, findings, export in JSON/Markdown/Text)
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, SQLAlchemy, SQLite |
| Frontend | Next.js, React, Tailwind CSS |
| AI Analysis | OpenRouter (free models) |
| Deployment | Railway (API) + Vercel (frontend) |
| CI/CD | GitHub Actions |

---

## Security

- Rate limiting (10 scans/min/IP)
- SSRF protection (blocks private/reserved IPs, DNS rebinding defense)
- Input validation and size limits (500KB inline, 2MB remote)
- No code execution — static analysis only
- SHA-256 content hashing for tamper detection
- AI prompt sanitization (control character stripping, truncation)

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPEEK_CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins |
| `MCPEEK_RATE_LIMIT_PER_MINUTE` | `10` | Max scans per IP per minute |
| `MCPEEK_ALLOW_LOCAL_PATH_SCANS` | `false` | Allow local file path scanning |
| `MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS` | `false` | Allow private network targets |
| `MCPEEK_OPENROUTER_API_KEY` | — | OpenRouter API key for AI analysis |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend API URL for frontend |

---

## Testing

```bash
cd backend && source .venv/bin/activate
python -m pytest tests/ -v        # 110 tests
python -m ruff check app/         # Lint
cd ../frontend && npx tsc --noEmit # Type check
```

---

## License

MIT

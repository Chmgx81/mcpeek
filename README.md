<p align="center">
  <img src="frontend/public/logo.svg" width="80" alt="MCPeek logo">
</p>

<h1 align="center">MCPeek</h1>

<p align="center">
  <strong>Peek beyond the manifest.</strong><br>
  Runtime-aware security scanner for MCP servers and AI agent skills.
</p>

<p align="center">
  <a href="https://frontend-lake-eight-70.vercel.app">Live Demo</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#features">Features</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#api">API</a> •
  <a href="#license">License</a>
</p>

---

## What is MCPeek?

MCPeek scans **MCP server configurations** and **AI agent skills** for security risks before they run. Unlike traditional security tools that analyze source code, MCPeek inspects the runtime configurations — the manifests, install scripts, tool permissions, and external URLs — that actually determine what your AI agent does.

### The Problem

AI agent ecosystems like MCP (Model Context Protocol) rely on configuration files that define server behavior, tool permissions, and external dependencies. These files can contain:

- **Hidden shell commands** that execute arbitrary code on startup
- **Tool poisoning** — malicious instructions embedded in tool descriptions that hijack AI agent behavior
- **Hardcoded secrets** exposed in configuration
- **Bait-and-switch attacks** — clean code served initially, then swapped for malicious payloads after approval

Traditional scanners miss these threats because they only look at source code, not runtime behavior.

### The Solution

MCPeek analyzes the full attack surface of MCP configurations: shell execution patterns, prompt injection vectors, OWASP MCP Top 10 vulnerabilities, dependency risks, and external URL integrity. It catches threats before they execute.

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

## Features

### Core Detection

| Category | What MCPeek Detects |
|----------|-------------------|
| **Shell Execution** | `curl \| sh`, `bash -c`, `eval`, `os.system`, `subprocess` |
| **Prompt Injection** | Basic patterns, homoglyphs, hierarchy manipulation, instruction leakage |
| **Dangerous Permissions** | Filesystem, network, exec access in tool definitions |
| **Hardcoded Secrets** | AWS, OpenAI, Stripe, GitHub tokens, private keys |
| **Suspicious URLs** | External resource loading, data URIs, base64 payloads |
| **Code Execution** | `eval()`, `new Function()`, `child_process`, dynamic imports |

### OWASP MCP Top 10

| ID | Name | Detection |
|----|------|-----------|
| MCP02 | Scope Creep | Overly broad tool permissions (`full access`, `unrestricted database`) |
| MCP03 | Tool Poisoning | Hidden instructions in tool descriptions (exfiltration, role override, covert channels) |
| MCP06 | Intent Subversion | Redirect instructions (`instead of user's goal`, `your new mission`) |
| MCP10 | Context Over-Sharing | Shared context spaces, bulk data access patterns |

### Bait-and-Switch Defense

MCPeek's key differentiator: it detects when an attacker swaps a clean configuration for a malicious one after initial approval.

1. **Content Hashing** — SHA-256 hashes of all external URLs stored with each scan
2. **Re-scanning** — Compare current content against original hashes
3. **Change Detection** — Flag any URL serving different content as critical
4. **Dependency Risk Scoring** — URL shorteners, suspicious TLDs, obfuscated URLs

### AI-Powered Analysis

Optional deep analysis using free OpenRouter models (no credit card required):

- **Attack Scenarios** — Context-specific attack narratives generated from your actual findings
- **Risk Narrative** — Plain-English executive summary with approve/reject verdict
- **Remediation** — Specific config/code fixes for each issue
- **Threat Intelligence** — CVE mapping and MITRE ATT&CK technique matching

---

## Quickstart

### Try It Online

Visit **[mcpeek.dev](https://frontend-lake-eight-70.vercel.app)** — no account required.

### Run Locally

```bash
git clone https://github.com/Chmgx81/mcpeek.git
cd mcpeek

# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
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

# Scan with CI gate (exits non-zero if risk >= high)
python -m app.static_scan config.json --fail-on high --summary
```

---

## How It Works

```
Input (URL / Paste / Package)
    ↓
Fetch & Parse (HTTP GET, JSON parse, registry lookup)
    ↓
Static Analysis (regex patterns, AST parsing, config inspection)
    ↓
Advanced Detection (OWASP MCP, injection, tool poisoning)
    ↓
Trust Scoring (domain reputation, dependency risk, supply chain)
    ↓
AI Analysis (optional: attack scenarios, remediation, narrative)
    ↓
Report (risk score, findings, export in JSON/Markdown/Text)
```

---

## Supported Targets

| Target Type | What Gets Scanned |
|-------------|-------------------|
| **MCP Server** | `package.json` MCP configs, `pyproject.toml`, inline JSON |
| **Agent Skill** | `SKILL.md` files with tool definitions |
| **npm Package** | Registry metadata, lifecycle scripts, dependency analysis |
| **PyPI Package** | Registry metadata, classifiers, dependency analysis |

---

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Submit a scan |
| `GET` | `/api/v1/scan/{id}` | Get scan results |
| `POST` | `/api/v1/scan/{id}/rescan` | Re-scan for bait-and-switch |
| `DELETE` | `/api/v1/scan/{id}` | Delete a scan |
| `GET` | `/api/v1/report/{id}/full` | Full structured report |
| `GET` | `/api/v1/report/{id}/export?format=json` | Export as JSON |
| `GET` | `/api/v1/scans` | List scans (paginated) |
| `GET` | `/api/v1/stats` | Dashboard statistics |

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
      - uses: ./
        with:
          path: config/mcp-server.json
          fail-on: high
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLAlchemy, SQLite |
| Frontend | Next.js, React, Tailwind CSS |
| AI Analysis | OpenRouter (free models) |
| Deployment | Railway (API) + Vercel (frontend) |

---

## Security

- Rate limiting (10 scans/min/IP)
- SSRF protection (blocks private/reserved IPs)
- Input validation and size limits
- No code execution — static analysis only
- SHA-256 content hashing for tamper detection

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPEEK_CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins |
| `MCPEEK_RATE_LIMIT_PER_MINUTE` | `10` | Max scans per IP per minute |
| `MCPEEK_ALLOW_LOCAL_PATH_SCANS` | `false` | Allow local file path scanning |
| `MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS` | `false` | Allow private network targets |
| `MCPEEK_OPENROUTER_API_KEY` | — | OpenRouter API key for AI analysis |

---

## License

MIT

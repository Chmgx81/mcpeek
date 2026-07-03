<p align="center">
  <img src="frontend/public/logo.svg" width="80" alt="MCPeek logo">
</p>

<h1 align="center">MCPeek</h1>

<p align="center">
  <strong>Peek beyond the manifest.</strong><br>
  Runtime-aware security scanner for MCP servers, AI agent skills, and AI toolchains.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> •
  <a href="#features">Features</a> •
  <a href="#api">API</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#license">License</a>
</p>

---

## Why MCPeek?

Traditional security scanners analyze source code. MCPeek scans **runtime configurations** — the manifests, install scripts, and trust signals that determine what actually runs when your MCP server starts.

Static scanners miss threats that only appear after `npm install` or when the server connects to external URLs. MCPeek catches them before they execute.

## Features

**Detection**
- Shell execution patterns (`curl | sh`, `bash -c`, `eval`)
- Prompt injection in skill definitions
- Dangerous tool permissions (filesystem, network, exec)
- Hardcoded secrets (AWS, OpenAI, Stripe, GitHub tokens)
- Suspicious URLs and external resource loading
- Environment variable exfiltration
- Remote code execution vectors

**Trust scoring**
- Repository metadata analysis (stars, contributors, commit activity)
- Domain reputation (Tier 1–4 classification, TLD risk)
- Trust mismatch detection (high stars + suspicious domain = astroturfing)
- Supply chain signals (typosquatting, mutable URLs)

**Attack simulation**
- Realistic attack scenarios for each finding category
- Executive summary with risk verdict (HIGH RISK / ELEVATED / MODERATE / LOW RISK)

**Supported targets**
- MCP server configs (`package.json` MCP configs, `pyproject.toml`)
- AI agent skill files (`SKILL.md`)
- npm packages
- PyPI packages

## Quickstart

```bash
# Clone
git clone https://github.com/yourname/mcpeek.git
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

Scan a config file directly without the web UI:

```bash
cd backend && source .venv/bin/activate
python -m app.static_scan path/to/config.json
```

## Stack

| Layer | Tech |
|-------|------|
| Backend | Python 3.14, FastAPI, SQLAlchemy (async), SQLite |
| Frontend | Next.js 15, React 19, Tailwind CSS 4 |
| Design | Dark-mode only, sharp geometry, `#22c55e` accent |

## Architecture

```
mcpeek/
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI, CORS, rate limiting
│   │   ├── config.py             # Settings
│   │   ├── schemas.py            # Pydantic API schemas
│   │   ├── detection/            # Shared detection patterns
│   │   │   ├── patterns.py       # Consolidated regex patterns
│   │   │   └── utils.py          # detect_secrets(), extract_urls()
│   │   ├── services/             # Scanner orchestration
│   │   ├── static_scan/          # Static analysis pipeline
│   │   │   ├── scanner.py        # Entry point + risk scoring
│   │   │   ├── shell.py          # Shell execution detection
│   │   │   ├── injection.py      # Prompt injection + permissions
│   │   │   ├── secrets.py        # Hardcoded credentials
│   │   │   └── external.py       # External dependencies
│   │   └── runtime_scan/         # Runtime content analysis
│   │       ├── fetch_analyzer.py # RCE, exfil, C2 patterns
│   │       └── trust_analyzer.py # Repo, domain, trust signals
├── frontend/
│   ├── src/app/                  # Pages (landing, dashboard, scan, history, contact)
│   ├── src/components/           # UI components
│   │   ├── ui/                   # Reusable primitives (gooey-filter, pixel-trail)
│   │   ├── Sidebar.tsx           # Navigation + user section
│   │   ├── ScanForm.tsx          # URL / paste config input
│   │   ├── CookieBanner.tsx      # Consent banner
│   │   └── Skeleton.tsx          # Loading states
│   └── src/lib/                  # API client, types, utils
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/scan` | Submit a scan |
| `GET` | `/api/v1/scan/{id}` | Scan status + findings |
| `GET` | `/api/v1/report/{id}/full` | Full report |
| `GET` | `/api/v1/report/{id}/export?format=json\|text\|markdown` | Export |
| `GET` | `/api/v1/scans` | List scans (paginated) |
| `GET` | `/api/v1/stats` | Dashboard stats |

## Scan Pipeline

```
Input → Parser → Static Scanner → Runtime Analyzer → Trust Analyzer → Report
                ├─ shell.py      ├─ RCE patterns    ├─ repo metadata
                ├─ injection.py  ├─ exfil patterns   ├─ domain reputation
                ├─ secrets.py    ├─ C2 patterns      ├─ trust mismatch
                └─ external.py   └─ sys modification └─ activity analysis
```

## Security

- **Rate limiting:** 10 scans/min/IP (configurable)
- **CORS:** Configurable origins
- **SSRF protection:** Blocks private/reserved IPs
- **URL validation:** http/https only

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPEEK_CORS_ORIGINS` | `http://localhost:3000` | Allowed origins |
| `MCPEEK_RATE_LIMIT_PER_MINUTE` | `10` | Max scans per IP/min |

## License

MIT

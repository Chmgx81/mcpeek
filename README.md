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
  <a href="#bait-and-switch-defense">Bait-and-Switch Defense</a> •
  <a href="#ci-gate">CI Gate</a> •
  <a href="#demo-fixtures">Demo Fixtures</a> •
  <a href="#api">API</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#license">License</a>
</p>

---

## Why MCPeek?

Traditional security scanners analyze source code. MCPeek scans **runtime configurations** — the manifests, install scripts, and trust signals that determine what actually runs when your MCP server starts.

Static scanners miss threats that only appear after `npm install` or when the server connects to external URLs. MCPeek catches them before they execute.

### The Problem: Bait-and-Switch Attacks

Attackers host clean AI skills that pass automated scanners. After thousands of users install them, the attacker swaps the external URL to serve malicious code. MCPeek defends against this with content hashing, re-scanning, and dependency risk scoring.

## Features

**Detection**
- Shell execution patterns (`curl | sh`, `bash -c`, `eval`)
- Prompt injection in skill definitions (basic + advanced: homoglyphs, hierarchy manipulation, instruction leakage)
- Dangerous tool permissions (filesystem, network, exec)
- Hardcoded secrets (AWS, OpenAI, Stripe, GitHub tokens)
- Suspicious URLs and external resource loading
- Environment variable exfiltration
- Remote code execution vectors

**OWASP MCP Top 10**
- **MCP02: Scope Creep** — overly broad tool permissions (`full access`, `unrestricted database`)
- **MCP03: Tool Poisoning** — hidden instructions in tool descriptions (data exfiltration, role override, covert channels, conditional triggers, obfuscation)
- **MCP06: Intent Flow Subversion** — redirect instructions in context (`instead of user's goal`, `your new mission`)
- **MCP10: Context Over-Sharing** — shared context spaces, bulk data access patterns

**Bait-and-Switch Defense**
- SHA-256 content hashing of external URLs
- Re-scan with automatic payload change detection
- External dependency risk scoring (URL shorteners, suspicious TLDs, obfuscated URLs)
- Domain reputation analysis (IP-instead-of-domain, subdomain depth, non-standard ports)

**AST-Based Code Analysis**
- Python AST parsing: `exec`, `eval`, `os.system`, `subprocess`, dynamic imports
- JavaScript pattern analysis: `eval`, `new Function`, `child_process`, `Buffer.from(base64)`
- Obfuscation detection: hex strings, unicode escapes, chr() chains

**Trust Scoring**
- Repository metadata analysis (stars, contributors, commit activity)
- Domain reputation (Tier 1–4 classification, TLD risk)
- Trust mismatch detection (high stars + suspicious domain = astroturfing)
- Supply chain signals (typosquatting, mutable URLs)

**Attack Simulation**
- Realistic attack scenarios for each finding category
- OWASP MCP Top 10 mapping (MCP02, MCP03, MCP06, MCP10)
- Executive summary with risk verdict (HIGH RISK / ELEVATED / MODERATE / LOW RISK)

**Supported Targets**
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

Block CI when the risk level reaches a threshold:

```bash
python -m app.static_scan ../examples/vulnerable-mcp-curl-shell.json --summary --fail-on high
```

`--fail-on` accepts `safe`, `low`, `medium`, `high`, or `critical`. A policy failure exits with code `2`.

## Bait-and-Switch Defense

MCPeek's key differentiator is defending against the **bait-and-switch attack** — where a skill serves clean code initially, then swaps to malicious code after approval.

### How It Works

1. **Content Hashing:** Every external URL is fetched and its SHA-256 hash is stored with the scan result.
2. **Re-scanning:** Use the "Re-scan" button to re-check a previously scanned skill. MCPeek compares the new content hashes against the original.
3. **Change Detection:** If any external URL now serves different content, MCPeek flags it as a critical finding with a clear "Bait-and-switch detected" alert.
4. **Dependency Risk Scoring:** Skills with many external URLs, URL shorteners, or suspicious domains get flagged automatically.

### Detection Categories

| Check | What It Catches |
|-------|----------------|
| Content Hash Mismatch | External URL now serves different code |
| URL Shortener Detection | bit.ly, tinyurl, etc. hiding real destinations |
| Suspicious TLD Flagging | .xyz, .tk, .top domains commonly used for phishing |
| Obfuscated URL Detection | Base64/hex encoding in URL paths |
| IP Address Usage | Raw IPs bypassing DNS security controls |
| Excessive Subdomains | Deep nesting obscuring domain ownership |

## CI Gate

MCPeek ships as a composite GitHub Action. Add this to a workflow to block unsafe MCP configs in pull requests:

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
          path: examples/vulnerable-mcp-curl-shell.json
          fail-on: high
```

## Demo Fixtures

Use these files to verify that MCPeek catches real AI-agent supply-chain risks:

| File | Purpose |
|------|---------|
| `examples/safe-mcp.json` | Low-risk control sample |
| `examples/vulnerable-mcp-curl-shell.json` | MCP config with curl-to-shell, prompt injection, dangerous tools, and secrets |
| `examples/vulnerable-agent-skill.md` | Agent skill with hidden instructions, exfiltration, and dangerous permissions |
| `examples/prompt-injection-skill.md` | Focused prompt-injection sample |
| `examples/secret-leak-config.json` | Hardcoded token sample |

Hackathon demo notes are in [`docs/HACKATHON_DEMO.md`](docs/HACKATHON_DEMO.md).

## Stack

| Layer | Tech |
|-------|------|
| Backend | Python 3.12+, FastAPI, SQLAlchemy (async), SQLite |
| Frontend | Next.js 15, React 19, Tailwind CSS 4 |
| Design | Dark-mode only, sharp geometry, `#22c55e` accent |

## Architecture

```
mcpeek/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI, CORS, rate limiting
│   │   ├── config.py                # Settings (env-configurable)
│   │   ├── schemas/                 # Pydantic API schemas
│   │   │   └── scan.py              # ScanRequest, ScanResponse, etc.
│   │   ├── models/                  # SQLAlchemy models
│   │   │   └── scan.py              # Scan, Finding tables
│   │   ├── routers/
│   │   │   └── scan.py              # API endpoints (scan, rescan, report)
│   │   ├── detection/               # Shared detection patterns
│   │   │   ├── patterns.py          # Consolidated regex patterns
│   │   │   └── utils.py             # detect_secrets(), extract_urls()
│   │   ├── services/
│   │   │   ├── scanner.py           # Background scan orchestration
│   │   │   ├── mcp_scanner.py       # MCP server config scanner
│   │   │   ├── skill_scanner.py     # AI agent skill scanner
│   │   │   ├── package_scanner.py   # npm/PyPI package scanner
│   │   │   ├── content_hash.py      # SHA-256 URL content hashing
│   │   │   ├── dependency_risk.py   # External dependency risk scoring
│   │   │   ├── ast_analyzer.py      # Python/JS AST analysis
│   │   │   ├── advanced_injection.py# Advanced prompt injection detection
│   │   │   ├── external_analyzer.py # External URL analysis + code scanning
│   │   │   ├── risk_scorer.py       # Risk score calculation
│   │   │   └── report_generator.py  # Report generation
│   │   └── static_scan/             # CLI static analysis pipeline
│   │       ├── __main__.py          # CLI entry point (--fail-on)
│   │       ├── scanner.py           # Unified static scanner
│   │       ├── parser.py            # Input parser (JSON/YAML/text)
│   │       ├── shell.py             # Shell execution detection
│   │       ├── injection.py         # Prompt injection detection
│   │       ├── secrets.py           # Hardcoded credential detection
│   │       └── external.py          # External dependency analysis
├── frontend/
│   ├── src/app/
│   │   ├── page.tsx                 # Landing page
│   │   ├── dashboard/page.tsx       # Dashboard with scan form
│   │   ├── scan/[id]/page.tsx       # Scan results + re-scan
│   │   ├── history/page.tsx         # Scan history
│   │   ├── contact/page.tsx         # Contact form
│   │   └── blog/                    # Blog posts
│   ├── src/components/
│   │   ├── ui/                      # Reusable primitives (gooey-filter, pixel-trail)
│   │   ├── Sidebar.tsx              # Navigation + user section
│   │   ├── ScanForm.tsx             # URL / paste config input
│   │   ├── FindingCard.tsx          # Expandable finding details
│   │   ├── RiskScore.tsx            # Risk gauge SVGs
│   │   ├── SeverityBadge.tsx        # Severity labels
│   │   ├── OnboardingTour.tsx       # 3-step tooltip tour
│   │   ├── CookieBanner.tsx         # Consent banner
│   │   └── Logo.tsx                 # Logo component
│   └── src/lib/
│       ├── api.ts                   # API client (scan, rescan, changes)
│       ├── types.ts                 # TypeScript interfaces
│       ├── utils.ts                 # cn() helper
│       └── theme.tsx                # ThemeProvider (dark-only)
```

## Scan Pipeline

```
Input → Parser → Static Scanner → Advanced Analysis → Trust Analyzer → Report
                ├─ shell.py      ├─ AST analysis       ├─ repo metadata
                ├─ injection.py  ├─ advanced injection  ├─ domain reputation
                ├─ secrets.py    ├─ dependency risk     ├─ trust mismatch
                └─ external.py   ├─ content hashing     └─ activity analysis
                                 └─ domain reputation
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/v1/scan` | Submit a scan |
| `POST` | `/api/v1/scan/{id}/rescan` | Re-scan (bait-and-switch detection) |
| `GET` | `/api/v1/scan/{id}` | Scan status + findings |
| `GET` | `/api/v1/scan/{id}/changes` | Content change comparison |
| `GET` | `/api/v1/report/{id}/full` | Full report |
| `GET` | `/api/v1/report/{id}/export?format=json\|text\|markdown` | Export |
| `GET` | `/api/v1/scans` | List scans (paginated) |
| `GET` | `/api/v1/stats` | Dashboard stats |

## Security

- **Rate limiting:** 10 scans/min/IP (configurable)
- **CORS:** Configurable origins
- **SSRF protection:** Blocks private/reserved IPs
- **URL validation:** http/https only
- **Input limits:** target, inline config, and remote content size limits
- **Content hashing:** SHA-256 of external URLs for tamper detection

Production deployment notes are in [`docs/PRODUCTION.md`](docs/PRODUCTION.md).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCPEEK_CORS_ORIGINS` | `http://localhost:3000` | Allowed origins |
| `MCPEEK_RATE_LIMIT_PER_MINUTE` | `10` | Max scans per IP/min |
| `MCPEEK_ALLOW_LOCAL_PATH_SCANS` | `false` | Allow scanning local backend paths |
| `MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS` | `false` | Allow scanning private/reserved network targets |
| `MCPEEK_MAX_INLINE_CONTENT_BYTES` | `500000` | Max inline config size |
| `MCPEEK_MAX_REMOTE_BYTES` | `1000000` | Max remote content size |

## License

MIT

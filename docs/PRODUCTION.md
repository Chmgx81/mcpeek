# Production Deployment Guide

MCPeek is a public-facing scanner. Every scan target is untrusted input.

## Live Deployment

| Service | URL | Status |
|---------|-----|--------|
| Frontend | https://frontend-lake-eight-70.vercel.app | Vercel |
| API | https://mcpeek-backend.vercel.app | Vercel Serverless |

## Environment Variables

### Backend (Vercel)

```bash
MCPEEK_TURSO_DATABASE_URL=libsql://your-db-name.turso.io
MCPEEK_TURSO_AUTH_TOKEN=your-turso-auth-token
MCPEEK_CORS_ORIGINS=https://frontend-lake-eight-70.vercel.app
MCPEEK_RATE_LIMIT_PER_MINUTE=10
MCPEEK_SCAN_TIMEOUT=120
MCPEEK_ALLOW_LOCAL_PATH_SCANS=false
MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS=false
MCPEEK_NVIDIA_NIM_API_KEY=nvapi-...       # Optional: enables AI threat detection
MCPEEK_OPENROUTER_API_KEY=sk-or-v1-...    # Optional: enables AI analysis
```

### Frontend (Vercel)

```bash
NEXT_PUBLIC_API_URL=https://mcpeek-backend.vercel.app
NEXT_PUBLIC_SITE_URL=https://frontend-lake-eight-70.vercel.app
```

## Security Defaults

- Local file path scans are disabled
- Private, loopback, link-local, multicast, and documentation IPs are blocked
- Hostnames resolved server-side before scanning (DNS rebinding defense)
- Scan targets and inline content have size limits
- Public API errors do not return Python tracebacks
- Scan submission rate-limited per client IP
- AI prompts sanitized (control character stripping, truncation)

## Deployment Checklist

- [ ] Set `MCPEEK_CORS_ORIGINS` to exact production frontend origin
- [ ] Set `NEXT_PUBLIC_API_URL` before building frontend
- [ ] Set `MCPEEK_TURSO_DATABASE_URL` and `MCPEEK_TURSO_AUTH_TOKEN` for database
- [ ] Keep `MCPEEK_ALLOW_LOCAL_PATH_SCANS=false` for public deployments
- [ ] Keep `MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS=false` for public deployments
- [ ] Optionally set `MCPEEK_NVIDIA_NIM_API_KEY` for AI threat detection
- [ ] Optionally set `MCPEEK_OPENROUTER_API_KEY` for AI analysis

## Vercel Deployment

### Backend

The backend deploys as a Vercel serverless function via `api/index.py` with Mangum:

```bash
cd backend && vercel --yes --prod
```

Key: Vercel Hobby plan has a 60-second function timeout. All scans run synchronously within this limit.

### Frontend

```bash
cd frontend && vercel --yes --prod
```

## Verification

```bash
# Backend health
curl https://mcpeek-backend.vercel.app/health

# Frontend
curl -sI https://frontend-lake-eight-70.vercel.app

# Tests
cd backend && source .venv/bin/activate && python -m pytest tests/ -v

# Lint
cd backend && python -m ruff check app/
cd frontend && npx tsc --noEmit
```

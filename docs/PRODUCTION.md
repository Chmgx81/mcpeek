# Production Deployment Guide

MCPeek is a public-facing scanner. Every scan target is untrusted input.

## Live Deployment

| Service | URL | Status |
|---------|-----|--------|
| Frontend | https://frontend-lake-eight-70.vercel.app | Vercel |
| API | https://mcpeek-api-production.up.railway.app | Railway |

## Environment Variables

### Backend

```bash
MCPEEK_DATABASE_URL=sqlite+aiosqlite:///./mcpeek.db
MCPEEK_CORS_ORIGINS=https://frontend-lake-eight-70.vercel.app
MCPEEK_RATE_LIMIT_PER_MINUTE=10
MCPEEK_SCAN_TIMEOUT=120
MCPEEK_MAX_CONCURRENT_SCANS=10
MCPEEK_MAX_TARGET_LENGTH=2048
MCPEEK_MAX_INLINE_CONTENT_BYTES=500000
MCPEEK_MAX_REMOTE_BYTES=1000000
MCPEEK_ALLOW_LOCAL_PATH_SCANS=false
MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS=false
MCPEEK_OPENROUTER_API_KEY=sk-or-v1-...       # Optional: enables AI analysis
```

### Frontend

```bash
NEXT_PUBLIC_API_URL=https://mcpeek-api-production.up.railway.app
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
- [ ] Run backend behind a reverse proxy that forwards real client IP
- [ ] Keep `MCPEEK_ALLOW_LOCAL_PATH_SCANS=false` for public deployments
- [ ] Keep `MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS=false` for public deployments
- [ ] Store database files outside git workspace
- [ ] Set `MCPEEK_OPENROUTER_API_KEY` for AI analysis (optional)

## Railway Deployment

The backend deploys via Dockerfile:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app/ app/
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
```

Key: Railway assigns `PORT` at runtime. The Dockerfile uses shell form for `$PORT` expansion.

## Vercel Deployment

Frontend deploys from `frontend/` directory:

```bash
cd frontend && vercel --yes --prod
```

SSO protection should be disabled for public access:

```bash
vercel project protection disable mcpeek-frontend --sso
```

## Verification

```bash
# Backend
curl https://mcpeek-api-production.up.railway.app/health

# Frontend
curl -sI https://frontend-lake-eight-70.vercel.app

# Tests
cd backend && source .venv/bin/activate && python -m pytest tests/ -v

# Lint
cd backend && python -m ruff check app/
cd frontend && npx tsc --noEmit
```

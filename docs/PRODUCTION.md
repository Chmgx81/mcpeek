# Production Readiness

MCPeek is a public-facing scanner. Treat every scan target as untrusted input.

## Required Environment

Backend:

```bash
MCPEEK_DATABASE_URL=sqlite+aiosqlite:///./mcpeek.db
MCPEEK_CORS_ORIGINS=https://your-frontend.example
MCPEEK_RATE_LIMIT_PER_MINUTE=10
MCPEEK_SCAN_TIMEOUT=120
MCPEEK_MAX_CONCURRENT_SCANS=10
MCPEEK_MAX_TARGET_LENGTH=2048
MCPEEK_MAX_INLINE_CONTENT_BYTES=500000
MCPEEK_MAX_REMOTE_BYTES=1000000
MCPEEK_ALLOW_LOCAL_PATH_SCANS=false
MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS=false
```

Frontend:

```bash
NEXT_PUBLIC_API_URL=https://your-api.example
NEXT_PUBLIC_SITE_URL=https://your-frontend.example
```

## Security Defaults

- Local file path scans are disabled by default.
- Private, loopback, link-local, multicast, and documentation IP ranges are blocked by default.
- Hostnames are resolved server-side before scanning to reduce DNS-rebinding SSRF risk.
- Scan targets and inline content have size limits.
- Public API errors do not return Python tracebacks.
- Scan submission is rate-limited per client IP.

## Deployment Checklist

- Set `MCPEEK_CORS_ORIGINS` to the exact production frontend origin.
- Set `NEXT_PUBLIC_API_URL` to the deployed backend origin before building the frontend.
- Set `NEXT_PUBLIC_SITE_URL` to the deployed frontend origin for correct Open Graph image URLs.
- Run the backend behind a reverse proxy that forwards the real client IP.
- Use PostgreSQL or a managed database for multi-instance deployments.
- Put workers behind a queue before raising `MCPEEK_MAX_CONCURRENT_SCANS`.
- Keep `MCPEEK_ALLOW_LOCAL_PATH_SCANS=false` for public deployments.
- Keep `MCPEEK_ALLOW_PRIVATE_NETWORK_SCANS=false` for public deployments.
- Store generated reports and database files outside the git workspace.

## Verification

```bash
cd frontend && npm run build
cd ../backend && python -m compileall app
curl http://localhost:8000/health
```

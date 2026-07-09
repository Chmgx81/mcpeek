import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .config import settings
from .database import init_db
from .routers.scan import router

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)

STALE_SCAN_TIMEOUT_SECONDS = 600  # 10 minutes


async def _cleanup_stale_scans() -> None:
    """Periodically mark orphaned pending/running scans as failed."""
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import select
    from .database import async_session
    from .models import Scan

    while True:
        try:
            await asyncio.sleep(300)  # Run every 5 minutes
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=STALE_SCAN_TIMEOUT_SECONDS)
            async with async_session() as db:
                result = await db.execute(
                    select(Scan).where(
                        Scan.status.in_(["pending", "running"]),
                        Scan.created_at < cutoff,
                    )
                )
                stale_scans = result.scalars().all()
                if stale_scans:
                    for scan in stale_scans:
                        scan.status = "failed"
                        scan.error_message = "Scan timed out: exceeded maximum execution time"
                    await db.commit()
                    logger.warning("Cleaned up %d stale scan(s)", len(stale_scans))
        except Exception:
            logger.exception("Stale scan cleanup failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    cleanup_task = asyncio.create_task(_cleanup_stale_scans())
    yield
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="MCPeek",
    description="Runtime-aware security scanner for MCP servers, AI agent skills, and AI toolchains",
    version="0.1.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
@limiter.exempt
async def root():
    return {"name": "mcpeek", "version": "0.1.0", "tagline": "Peek beyond the manifest."}


@app.get("/health")
@limiter.exempt
async def health():
    return {"status": "ok", "service": "mcpeek"}

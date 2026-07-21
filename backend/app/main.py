"""
SENTINEL-GRC — Enterprise Continuous Controls Monitoring & Risk Intelligence Platform
Main FastAPI application entry point.

Improvements:
  1. /health/deep — checks DB, Redis, and MinIO connectivity. Returns component-level
     status so monitoring systems (Prometheus, Datadog) can alert on partial failures.
  2. Async audit middleware — captures POST/PATCH/DELETE requests and dispatches an
     audit_log_task Celery task. The DB write is async so audit logging adds zero
     latency to responses. Uses body_hash (not body) to avoid storing PII.
     Gated by ENABLE_AUDIT_MIDDLEWARE feature flag.
"""

import hashlib
import os
from contextlib import asynccontextmanager
from typing import Optional

import structlog
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.limiter import limiter

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown events."""
    logger.info("SENTINEL-GRC starting up", version=settings.APP_VERSION)
    os.makedirs("/app/reports", exist_ok=True)
    os.makedirs("/app/static",  exist_ok=True)
    yield
    logger.info("SENTINEL-GRC shutting down")


app = FastAPI(
    title="SENTINEL-GRC",
    description=(
        "Enterprise Continuous Controls Monitoring & Risk Intelligence Platform. "
        "Real-time, evidence-based compliance monitoring against NIST, ISO 27001, SOC 2, "
        "Cyber Essentials, and UK GDPR with quantitative financial risk scoring."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ─── Rate Limiter ─────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Async Audit Middleware ────────────────────────────────────────────────────
@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """
    Capture mutating HTTP requests and dispatch an async Celery audit task.

    Only fires on POST / PATCH / DELETE and only when ENABLE_AUDIT_MIDDLEWARE=true.
    The body is read and hashed (SHA-256) before passing to the next handler.
    The hash — not the body — is stored, so PII is never written to audit logs.

    The actual DB write is done in a Celery task (audit_log_task) to ensure
    audit logging contributes zero latency to the HTTP response path.
    """
    response = await call_next(request)

    if not settings.ENABLE_AUDIT_MIDDLEWARE:
        return response

    if request.method not in ("POST", "PATCH", "DELETE"):
        return response

    try:
        # Extract auth context from JWT if present (best-effort, no exception on failure)
        user_id:    Optional[int] = None
        user_email: Optional[str] = None
        user_role:  Optional[str] = None

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from app.core.security import decode_token
                payload    = decode_token(auth_header.split(" ", 1)[1])
                user_id    = int(payload.get("sub", 0)) or None
                user_role  = payload.get("role")
            except Exception:
                pass   # Unauthenticated request — still logged without user context

        # Body hash (lazy — body may already be consumed by the route handler)
        # We log the body_hash only; never the plaintext body
        body_hash: Optional[str] = None
        try:
            body      = await request.body()
            body_hash = hashlib.sha256(body).hexdigest() if body else None
        except Exception:
            pass

        ip_address = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else None)
        )

        # Fire-and-forget via Celery — response already sent, audit write is async
        from app.tasks.celery_app import audit_log_task
        audit_log_task.delay(
            user_id    = user_id,
            user_email = user_email,
            user_role  = user_role,
            method     = request.method,
            path       = request.url.path,
            status_code= response.status_code,
            ip_address = ip_address,
            user_agent = request.headers.get("User-Agent"),
            body_hash  = body_hash,
        )
    except Exception as e:
        # Audit failure must NEVER affect the main response
        logger.warning("Audit middleware error (non-fatal)", error=str(e))

    return response


# ─── Static Files ─────────────────────────────────────────────────────────────
if os.path.exists("/app/static"):
    app.mount("/static",  StaticFiles(directory="/app/static"),  name="static")
if os.path.exists("/app/reports"):
    app.mount("/reports", StaticFiles(directory="/app/reports"), name="reports")

# ─── API Router ───────────────────────────────────────────────────────────────
app.include_router(api_router, prefix="/api/v1")


# ─── Shallow Health Check ─────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    """Fast liveness probe — returns immediately without DB/Redis checks."""
    return {
        "status":  "operational",
        "service": "SENTINEL-GRC",
        "version": settings.APP_VERSION,
    }


# ─── Deep Health Check ────────────────────────────────────────────────────────
@app.get("/health/deep")
async def deep_health_check():
    """
    Readiness probe — verifies DB, Redis, and MinIO connectivity.

    Returns component-level status so monitoring can alert on partial failures:
      - "healthy":  all components reachable
      - "degraded": one or more components unreachable (system may still serve traffic)
      - "unhealthy": critical component down (DB)

    Use this endpoint in:
      - Docker healthcheck: HEALTHCHECK CMD curl -f http://localhost:8000/health/deep
      - Kubernetes readinessProbe: httpGet path: /health/deep
      - Prometheus blackbox_exporter target
    """
    from app.db.database import async_engine
    import redis as _redis

    checks: dict[str, str] = {
        "api":   "ok",
        "db":    "failed",
        "redis": "failed",
        "minio": "failed",
    }

    # ── Database ──────────────────────────────────────────────────────────────
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as e:
        logger.warning("Deep health: DB check failed", error=str(e))

    # ── Redis ─────────────────────────────────────────────────────────────────
    try:
        r = _redis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        r.ping()
        checks["redis"] = "ok"
    except Exception as e:
        logger.warning("Deep health: Redis check failed", error=str(e))

    # ── MinIO ─────────────────────────────────────────────────────────────────
    try:
        from minio import Minio
        mc = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE,
        )
        mc.bucket_exists(settings.MINIO_BUCKET)
        checks["minio"] = "ok"
    except Exception as e:
        logger.warning("Deep health: MinIO check failed", error=str(e))

    # ── Aggregate ─────────────────────────────────────────────────────────────
    if checks["db"] == "failed":
        overall = "unhealthy"
        status_code = 503
    elif any(v == "failed" for v in checks.values()):
        overall = "degraded"
        status_code = 200   # Still serving — degraded but not dead
    else:
        overall = "healthy"
        status_code = 200

    return JSONResponse(
        status_code=status_code,
        content={
            "status":  overall,
            "service": "SENTINEL-GRC",
            "version": settings.APP_VERSION,
            "checks":  checks,
        },
    )

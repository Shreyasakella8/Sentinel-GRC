"""
SENTINEL-GRC — Enterprise Continuous Controls Monitoring & Risk Intelligence Platform
Main FastAPI application entry point.
"""

from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.api.v1.router import api_router
from app.core.config import settings

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown events."""
    logger.info("SENTINEL-GRC starting up", version=settings.APP_VERSION)
    # Ensure static/reports dirs exist
    os.makedirs("/app/reports", exist_ok=True)
    os.makedirs("/app/static", exist_ok=True)
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

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Static Files ─────────────────────────────────────────────────────────────
if os.path.exists("/app/static"):
    app.mount("/static", StaticFiles(directory="/app/static"), name="static")
if os.path.exists("/app/reports"):
    app.mount("/reports", StaticFiles(directory="/app/reports"), name="reports")

# ─── API Router ───────────────────────────────────────────────────────────────
app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {
        "status": "operational",
        "service": "SENTINEL-GRC",
        "version": settings.APP_VERSION,
    }

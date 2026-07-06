"""SENTINEL-GRC — API v1 Router"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth, dashboard, risks, controls,
    evidence, governance, reports, threats, users, ai_security,
)

api_router = APIRouter()

api_router.include_router(auth.router,         prefix="/auth",         tags=["Authentication"])
api_router.include_router(dashboard.router,    prefix="/dashboard",    tags=["Dashboard"])
api_router.include_router(risks.router,        prefix="/risks",        tags=["Risk Register"])
api_router.include_router(controls.router,     prefix="/controls",     tags=["Controls"])
api_router.include_router(evidence.router,     prefix="/evidence",     tags=["Evidence Vault"])
api_router.include_router(governance.router,   prefix="/governance",   tags=["Governance"])
api_router.include_router(reports.router,      prefix="/reports",      tags=["Reports"])
api_router.include_router(threats.router,      prefix="/threats",      tags=["Threat Intelligence"])
api_router.include_router(users.router,        prefix="/users",        tags=["Users"])
api_router.include_router(ai_security.router,  prefix="/ai-security",  tags=["AI Security"])

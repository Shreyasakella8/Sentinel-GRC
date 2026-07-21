"""
SENTINEL-GRC — Authentication Endpoints
FIX: explicit db.commit() added — audit log entries were being added
to the session but never committed (get_db no longer auto-commits as of v2).
"""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from app.core.security import verify_password, create_access_token, get_current_user
from app.core.limiter import limiter
from app.db.database import get_db
from app.models.user import User
from app.models.threat import AuditLog

router = APIRouter()


class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    email: str
    full_name: str
    role: str


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    department: Optional[str]
    is_active: bool
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and return JWT access token."""
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        db.add(AuditLog(
            user_email=form_data.username,
            action="LOGIN_FAILED",
            resource_type="auth",
            success=False,
            error_message="Invalid credentials",
        ))
        await db.commit()   # FIX: was missing — failed login attempts were never persisted
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account is disabled")

    user.last_login = datetime.utcnow()

    db.add(AuditLog(
        user_id=user.id,
        user_email=user.email,
        user_role=user.role,
        action="LOGIN_SUCCESS",
        resource_type="auth",
        success=True,
    ))

    token = create_access_token(data={"sub": str(user.id), "role": user.role})

    await db.commit()   # FIX: was missing — last_login update and audit log were silently discarded

    return Token(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
    )


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user profile."""
    return current_user

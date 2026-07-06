"""
SENTINEL-GRC — Security Module
JWT authentication, password hashing, and RBAC enforcement.
ai-security permission added to CISO and internal_auditor roles.
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from enum import Enum

from app.core.config import settings
from app.db.database import get_db

pwd_context   = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


class UserRole(str, Enum):
    CISO             = "ciso"
    BOARD_MEMBER     = "board_member"
    RISK_OWNER       = "risk_owner"
    INTERNAL_AUDITOR = "internal_auditor"
    READ_ONLY        = "read_only"


ROLE_PERMISSIONS: dict[UserRole, set[str]] = {
    UserRole.CISO: {
        "dashboard", "risks", "controls", "evidence", "governance",
        "reports", "threats", "admin", "audit", "users", "ai-security",
    },
    UserRole.BOARD_MEMBER: {
        "dashboard", "reports",
    },
    UserRole.RISK_OWNER: {
        "dashboard", "risks", "governance",
    },
    UserRole.INTERNAL_AUDITOR: {
        "dashboard", "evidence", "audit", "controls", "reports", "ai-security",
    },
    UserRole.READ_ONLY: {
        "dashboard",
    },
}


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire    = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    from app.models.user import User
    from sqlalchemy import select

    payload = decode_token(token)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate credentials")

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user   = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Could not validate credentials")
    return user


def require_permission(permission: str):
    """FastAPI dependency factory: enforce RBAC permission check."""
    async def checker(current_user=Depends(get_current_user)):
        user_permissions = ROLE_PERMISSIONS.get(UserRole(current_user.role), set())
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission}. Your role: {current_user.role}",
            )
        return current_user
    return checker


def require_role(role: UserRole):
    """FastAPI dependency factory: enforce exact role."""
    async def checker(current_user=Depends(get_current_user)):
        if current_user.role not in (role.value, UserRole.CISO.value):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {role.value} required. Your role: {current_user.role}",
            )
        return current_user
    return checker

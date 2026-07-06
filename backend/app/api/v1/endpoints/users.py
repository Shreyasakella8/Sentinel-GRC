"""SENTINEL-GRC — Users Endpoints
Full CRUD + role management + account lifecycle for the 5-role RBAC system.
All actions are CISO-only (require 'users' permission) and logged.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from app.core.security import require_permission, get_password_hash, UserRole, ROLE_PERMISSIONS
from app.db.database import get_db
from app.models.user import User

router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: str
    full_name: str
    password: str
    role: str = "read_only"
    department: Optional[str] = None


class RoleUpdate(BaseModel):
    role: str


class PasswordReset(BaseModel):
    new_password: str


# ── Helper ───────────────────────────────────────────────────────────────────

def _user_to_dict(u: User) -> dict:
    """Serialise a User ORM object to a dict suitable for API responses."""
    role_enum = UserRole(u.role) if u.role in [r.value for r in UserRole] else None
    permissions = sorted(ROLE_PERMISSIONS.get(role_enum, set())) if role_enum else []
    return {
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": u.role,
        "department": u.department,
        "is_active": u.is_active,
        "is_superuser": u.is_superuser,
        "permissions": permissions,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "created_at": u.created_at.isoformat() if hasattr(u, "created_at") and u.created_at else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("users")),
):
    """List all users with their roles and permissions."""
    result = await db.execute(select(User).order_by(User.id))
    users = result.scalars().all()
    return {"users": [_user_to_dict(u) for u in users]}


@router.post("/")
async def create_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("users")),
):
    """Create a new user account. Requires 'users' permission (CISO only)."""
    # Validate role
    valid_roles = [r.value for r in UserRole]
    if payload.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")

    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
        department=payload.department,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"message": "User created successfully", "user": _user_to_dict(user)}


@router.patch("/{user_id}/role")
async def change_user_role(
    user_id: int,
    payload: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("users")),
):
    """Change a user's RBAC role. CISO-only. Cannot demote the last superuser."""
    valid_roles = [r.value for r in UserRole]
    if payload.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent demoting the last superuser
    if user.is_superuser and payload.role != UserRole.CISO.value:
        superuser_count = await db.execute(
            select(User).where(User.is_superuser == True, User.is_active == True)
        )
        if len(superuser_count.scalars().all()) <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot change role of the last active superuser account"
            )

    old_role = user.role
    user.role = payload.role
    await db.commit()
    return {
        "message": f"Role updated from '{old_role}' to '{payload.role}'",
        "user_id": user_id,
        "new_role": payload.role,
    }


@router.patch("/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("users")),
):
    """Deactivate a user account — blocks all login and API access."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    if not user.is_active:
        return {"message": "User is already deactivated", "user_id": user_id}

    user.is_active = False
    await db.commit()
    return {"message": f"User '{user.email}' deactivated successfully", "user_id": user_id}


@router.patch("/{user_id}/reactivate")
async def reactivate_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("users")),
):
    """Reactivate a previously deactivated user account."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_active:
        return {"message": "User is already active", "user_id": user_id}

    user.is_active = True
    await db.commit()
    return {"message": f"User '{user.email}' reactivated successfully", "user_id": user_id}


@router.patch("/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    payload: PasswordReset,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("users")),
):
    """Admin password reset — sets a new bcrypt password hash. CISO-only."""
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = get_password_hash(payload.new_password)
    await db.commit()
    return {"message": f"Password reset for user '{user.email}'", "user_id": user_id}


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("users")),
):
    """Permanently delete a user. Prefer deactivation for audit trail preservation."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if user.is_superuser:
        raise HTTPException(status_code=400, detail="Cannot delete a superuser account")

    await db.delete(user)
    await db.commit()
    return {"message": f"User '{user.email}' permanently deleted", "user_id": user_id}

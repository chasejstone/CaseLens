from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import append_audit
from ..auth import AdminUser, hash_password
from ..database import get_db
from ..models import User
from ..schemas import UserCreate, UserSummary


router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserSummary])
def list_users(_admin: AdminUser, db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.display_name)).all()


@router.post("", response_model=UserSummary, status_code=status.HTTP_201_CREATED)
def create_user(
    data: UserCreate,
    request: Request,
    admin: AdminUser,
    db: Session = Depends(get_db),
):
    existing = db.scalar(select(User).where(func.lower(User.email) == data.email.lower()))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
    user = User(
        email=data.email.lower(),
        display_name=data.display_name.strip(),
        password_hash=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    db.flush()
    append_audit(
        db,
        actor_id=admin.id,
        action="user.created",
        object_type="user",
        object_id=str(user.id),
        payload={"email": user.email, "role": user.role.value},
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(user)
    return user

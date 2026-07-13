from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import append_audit
from ..auth import CurrentUser, create_access_token, verify_password
from ..config import get_settings
from ..database import get_db
from ..models import User
from ..schemas import LoginRequest, UserSummary


router = APIRouter(prefix="/api/auth", tags=["authentication"])
settings = get_settings()


@router.post("/login", response_model=UserSummary)
def login(data: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(func.lower(User.email) == data.email.lower()))
    if not user or not user.is_active or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user)
    response.set_cookie(
        "caselens_session",
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.access_token_minutes * 60,
        path="/",
    )
    append_audit(
        db,
        actor_id=user.id,
        action="auth.login",
        object_type="user",
        object_id=str(user.id),
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response, request: Request, user: CurrentUser, db: Session = Depends(get_db)):
    response.delete_cookie("caselens_session", path="/")
    append_audit(
        db,
        actor_id=user.id,
        action="auth.logout",
        object_type="user",
        object_id=str(user.id),
        ip_address=request.client.host if request.client else None,
    )
    db.commit()


@router.get("/me", response_model=UserSummary)
def me(user: CurrentUser):
    return user

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import verify_audit_chain
from ..auth import AdminUser
from ..database import get_db
from ..models import AuditLog
from ..schemas import AuditView


router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditView])
def list_audit(
    _admin: AdminUser,
    db: Session = Depends(get_db),
    limit: int = Query(default=200, ge=1, le=1000),
):
    return db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all()


@router.get("/verify")
def verify_chain(_admin: AdminUser, db: Session = Depends(get_db)):
    entries = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    return {"valid": verify_audit_chain(list(entries)), "entries": len(entries)}

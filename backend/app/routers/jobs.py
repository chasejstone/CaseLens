from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import CurrentUser
from ..database import get_db
from ..models import AnalysisJob, JobStatus
from ..schemas import JobView


router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("", response_model=list[JobView])
def list_jobs(
    _user: CurrentUser,
    db: Session = Depends(get_db),
    job_status: JobStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
):
    statement = select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(limit)
    if job_status:
        statement = statement.where(AnalysisJob.status == job_status)
    return db.scalars(statement).all()


@router.get("/{job_id}", response_model=JobView)
def get_job(job_id: uuid.UUID, _user: CurrentUser, db: Session = Depends(get_db)):
    job = db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job

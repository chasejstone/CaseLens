from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from ..audit import append_audit
from ..auth import CurrentUser, WritableUser
from ..database import get_db
from ..models import AnalysisJob, Evidence, Incident, JobStatus
from ..schemas import EvidenceView, JobView
from ..storage import store_upload
from ..tasks import analyze_evidence


router = APIRouter(prefix="/api", tags=["evidence"])


@router.post(
    "/incidents/{incident_id}/evidence",
    response_model=EvidenceView,
    status_code=status.HTTP_201_CREATED,
)
async def upload_evidence(
    incident_id: uuid.UUID,
    request: Request,
    user: WritableUser,
    upload: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    stored = await store_upload(upload)
    evidence = Evidence(
        incident_id=incident.id,
        uploaded_by_id=user.id,
        original_name=stored.original_name,
        stored_name=stored.stored_name,
        storage_path=stored.storage_path,
        content_type=stored.content_type,
        size_bytes=stored.size_bytes,
        sha256=stored.sha256,
        kind=stored.kind,
    )
    try:
        db.add(evidence)
        db.flush()
        append_audit(
            db,
            actor_id=user.id,
            action="evidence.uploaded",
            object_type="evidence",
            object_id=str(evidence.id),
            payload={
                "incident_id": str(incident.id),
                "filename": evidence.original_name,
                "sha256": evidence.sha256,
                "size_bytes": evidence.size_bytes,
            },
            ip_address=request.client.host if request.client else None,
        )
        db.commit()
    except Exception:
        db.rollback()
        Path(stored.storage_path).unlink(missing_ok=True)
        raise
    db.refresh(evidence)
    return evidence


@router.post("/evidence/{evidence_id}/analyze", response_model=JobView, status_code=status.HTTP_202_ACCEPTED)
def queue_analysis(
    evidence_id: uuid.UUID,
    request: Request,
    user: WritableUser,
    db: Session = Depends(get_db),
):
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    job = AnalysisJob(evidence_id=evidence.id, requested_by_id=user.id)
    db.add(job)
    db.flush()
    append_audit(
        db,
        actor_id=user.id,
        action="analysis.queued",
        object_type="analysis_job",
        object_id=str(job.id),
        payload={"evidence_id": str(evidence.id), "incident_id": str(evidence.incident_id)},
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    try:
        result = analyze_evidence.delay(str(job.id))
    except Exception:
        job.status = JobStatus.FAILED
        job.error = "Could not submit the job to the analysis queue"
        append_audit(
            db,
            actor_id=user.id,
            action="analysis.queue_failed",
            object_type="analysis_job",
            object_id=str(job.id),
            payload={"evidence_id": str(evidence.id)},
            ip_address=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analysis queue is unavailable",
        )
    job.celery_task_id = result.id
    db.commit()
    db.refresh(job)
    return job


@router.get("/evidence/{evidence_id}", response_model=EvidenceView)
def get_evidence(evidence_id: uuid.UUID, _user: CurrentUser, db: Session = Depends(get_db)):
    evidence = db.get(Evidence, evidence_id)
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    return evidence

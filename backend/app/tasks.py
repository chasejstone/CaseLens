from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .analyzers import extract_entities, run_analysis
from .audit import append_audit
from .celery_app import celery_app
from .database import SessionLocal
from .models import AnalysisJob, Entity, IncidentEntity, JobStatus


@celery_app.task(name="caselens.analyze_evidence", bind=True, autoretry_for=(), max_retries=0)
def analyze_evidence(self, job_id: str) -> dict[str, str]:
    job_uuid = uuid.UUID(job_id)
    with SessionLocal() as db:
        job = db.get(AnalysisJob, job_uuid)
        if not job:
            return {"status": "missing"}
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        job.celery_task_id = self.request.id
        append_audit(
            db,
            actor_id=job.requested_by_id,
            action="analysis.started",
            object_type="analysis_job",
            object_id=str(job.id),
            payload={"evidence_id": str(job.evidence_id)},
        )
        db.commit()

        try:
            findings = run_analysis(job.evidence.storage_path, job.evidence.kind)
            job.findings = findings
            job.status = JobStatus.SUCCEEDED
            job.completed_at = datetime.now(timezone.utc)
            _persist_entities(db, job, findings)
            append_audit(
                db,
                actor_id=job.requested_by_id,
                action="analysis.completed",
                object_type="analysis_job",
                object_id=str(job.id),
                payload={"engine": findings.get("engine"), "evidence_id": str(job.evidence_id)},
            )
            db.commit()
            return {"status": "succeeded", "job_id": str(job.id)}
        except Exception as exc:
            db.rollback()
            job = db.get(AnalysisJob, job_uuid)
            if job:
                job.status = JobStatus.FAILED
                job.error = str(exc)[:4000]
                job.completed_at = datetime.now(timezone.utc)
                append_audit(
                    db,
                    actor_id=job.requested_by_id,
                    action="analysis.failed",
                    object_type="analysis_job",
                    object_id=str(job.id),
                    payload={"error": job.error, "evidence_id": str(job.evidence_id)},
                )
                db.commit()
            raise


def _persist_entities(db, job: AnalysisJob, findings: dict) -> None:
    incident_id = job.evidence.incident_id
    for entity_type, value, source, context in extract_entities(findings):
        entity = db.scalar(select(Entity).where(Entity.type == entity_type, Entity.value == value))
        if not entity:
            try:
                with db.begin_nested():
                    entity = Entity(type=entity_type, value=value)
                    db.add(entity)
                    db.flush()
            except IntegrityError:
                entity = db.scalar(
                    select(Entity).where(Entity.type == entity_type, Entity.value == value)
                )
        if not entity:
            continue
        exists = db.scalar(
            select(IncidentEntity).where(
                IncidentEntity.incident_id == incident_id,
                IncidentEntity.entity_id == entity.id,
                IncidentEntity.evidence_id == job.evidence_id,
                IncidentEntity.source == source,
            )
        )
        if not exists:
            db.add(
                IncidentEntity(
                    incident_id=incident_id,
                    entity_id=entity.id,
                    evidence_id=job.evidence_id,
                    source=source,
                    context=context,
                )
            )

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from ..audit import append_audit
from ..auth import CurrentUser, WritableUser
from ..database import get_db
from ..models import Evidence, Incident, IncidentStatus, InvestigationNote, Role, Severity, User
from ..schemas import IncidentCreate, IncidentDetail, IncidentListItem, IncidentUpdate, NoteCreate, NoteView


router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _incident_query():
    return select(Incident).options(
        selectinload(Incident.assigned_to),
        selectinload(Incident.created_by),
        selectinload(Incident.notes).selectinload(InvestigationNote.author),
        selectinload(Incident.evidence).selectinload(Evidence.uploaded_by),
    )


def _get_incident(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.scalar(_incident_query().where(Incident.id == incident_id))
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _validate_assignment(db: Session, user: User, assigned_to_id: uuid.UUID | None) -> None:
    if user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can assign incidents",
        )
    if assigned_to_id:
        assignee = db.get(User, assigned_to_id)
        if not assignee or assignee.role not in {Role.ADMIN, Role.ANALYST}:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid assignee")


@router.get("", response_model=list[IncidentListItem])
def list_incidents(
    _user: CurrentUser,
    db: Session = Depends(get_db),
    query: str | None = Query(default=None, max_length=200),
    incident_status: IncidentStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = None,
):
    statement = _incident_query().order_by(Incident.updated_at.desc())
    if query:
        term = f"%{query.strip()}%"
        statement = statement.where(
            or_(Incident.case_number.ilike(term), Incident.title.ilike(term), Incident.summary.ilike(term))
        )
    if incident_status:
        statement = statement.where(Incident.status == incident_status)
    if severity:
        statement = statement.where(Incident.severity == severity)
    return db.scalars(statement).all()


@router.post("", response_model=IncidentListItem, status_code=status.HTTP_201_CREATED)
def create_incident(
    data: IncidentCreate,
    request: Request,
    user: WritableUser,
    db: Session = Depends(get_db),
):
    if data.assigned_to_id:
        _validate_assignment(db, user, data.assigned_to_id)
    case_number = f"CL-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
    incident = Incident(
        case_number=case_number,
        title=data.title.strip(),
        summary=data.summary.strip(),
        severity=data.severity,
        assigned_to_id=data.assigned_to_id,
        created_by_id=user.id,
    )
    db.add(incident)
    db.flush()
    append_audit(
        db,
        actor_id=user.id,
        action="incident.created",
        object_type="incident",
        object_id=str(incident.id),
        payload={"case_number": case_number, "severity": incident.severity.value},
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    return _get_incident(db, incident.id)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: uuid.UUID, _user: CurrentUser, db: Session = Depends(get_db)):
    return _get_incident(db, incident_id)


@router.patch("/{incident_id}", response_model=IncidentListItem)
def update_incident(
    incident_id: uuid.UUID,
    data: IncidentUpdate,
    request: Request,
    user: WritableUser,
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id)
    changes = data.model_dump(exclude_unset=True)
    if "assigned_to_id" in changes:
        _validate_assignment(db, user, changes["assigned_to_id"])
    for key, value in changes.items():
        if key in {"title", "summary"} and isinstance(value, str):
            value = value.strip()
        setattr(incident, key, value)
    incident.updated_at = datetime.now(timezone.utc)
    append_audit(
        db,
        actor_id=user.id,
        action="incident.updated",
        object_type="incident",
        object_id=str(incident.id),
        payload={key: str(value) for key, value in changes.items()},
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    return _get_incident(db, incident.id)


@router.post("/{incident_id}/notes", response_model=NoteView, status_code=status.HTTP_201_CREATED)
def add_note(
    incident_id: uuid.UUID,
    data: NoteCreate,
    request: Request,
    user: WritableUser,
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id)
    note = InvestigationNote(incident_id=incident.id, author_id=user.id, body=data.body.strip())
    db.add(note)
    db.flush()
    append_audit(
        db,
        actor_id=user.id,
        action="note.created",
        object_type="investigation_note",
        object_id=str(note.id),
        payload={"incident_id": str(incident.id)},
        ip_address=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(note)
    return note

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..auth import CurrentUser
from ..database import get_db
from ..models import Incident
from ..reports import render_executive_report, render_technical_report


router = APIRouter(prefix="/api/incidents", tags=["reports"])


def _incident(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.get("/{incident_id}/reports/executive", response_class=HTMLResponse)
def executive_report(incident_id: uuid.UUID, _user: CurrentUser, db: Session = Depends(get_db)):
    return HTMLResponse(render_executive_report(db, _incident(db, incident_id)))


@router.get("/{incident_id}/reports/technical", response_class=HTMLResponse)
def technical_report(incident_id: uuid.UUID, _user: CurrentUser, db: Session = Depends(get_db)):
    return HTMLResponse(render_technical_report(db, _incident(db, incident_id)))

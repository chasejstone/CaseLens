from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import CurrentUser
from ..database import get_db
from ..models import Entity, Incident, IncidentEntity
from ..schemas import CorrelationItem


router = APIRouter(prefix="/api/correlations", tags=["correlations"])


@router.get("", response_model=list[CorrelationItem])
def correlations(
    _user: CurrentUser,
    db: Session = Depends(get_db),
    minimum_incidents: int = Query(default=2, ge=1, le=100),
    limit: int = Query(default=100, ge=1, le=500),
):
    rows = db.execute(
        select(Entity, func.count(func.distinct(IncidentEntity.incident_id)).label("incident_count"))
        .join(IncidentEntity, IncidentEntity.entity_id == Entity.id)
        .group_by(Entity.id)
        .having(func.count(func.distinct(IncidentEntity.incident_id)) >= minimum_incidents)
        .order_by(func.count(func.distinct(IncidentEntity.incident_id)).desc(), Entity.value)
        .limit(limit)
    ).all()
    output = []
    for entity, incident_count in rows:
        incidents = db.execute(
            select(Incident.id, Incident.case_number, Incident.title)
            .join(IncidentEntity, IncidentEntity.incident_id == Incident.id)
            .where(IncidentEntity.entity_id == entity.id)
            .distinct()
            .order_by(Incident.case_number)
        ).all()
        output.append(
            CorrelationItem(
                entity_id=entity.id,
                type=entity.type,
                value=entity.value,
                incident_count=incident_count,
                incidents=[
                    {"id": str(incident_id), "case_number": case_number, "title": title}
                    for incident_id, case_number, title in incidents
                ],
            )
        )
    return output

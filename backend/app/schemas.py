from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from .models import EntityType, EvidenceKind, IncidentStatus, JobStatus, Role, Severity


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    display_name: str
    role: Role
    is_active: bool


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)


class UserCreate(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=12, max_length=256)
    role: Role = Role.READ_ONLY


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=220)
    summary: str = Field(default="", max_length=20_000)
    severity: Severity = Severity.MEDIUM
    assigned_to_id: uuid.UUID | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=220)
    summary: str | None = Field(default=None, max_length=20_000)
    severity: Severity | None = None
    status: IncidentStatus | None = None
    assigned_to_id: uuid.UUID | None = None


class NoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=50_000)


class NoteView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    body: str
    created_at: datetime
    author: UserSummary


class EvidenceView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    original_name: str
    content_type: str
    size_bytes: int
    sha256: str
    kind: EvidenceKind
    created_at: datetime
    uploaded_by: UserSummary


class JobView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    evidence_id: uuid.UUID
    status: JobStatus
    error: str | None
    findings: dict[str, Any] | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class IncidentListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_number: str
    title: str
    summary: str
    status: IncidentStatus
    severity: Severity
    assigned_to: UserSummary | None
    created_by: UserSummary
    created_at: datetime
    updated_at: datetime


class IncidentDetail(IncidentListItem):
    notes: list[NoteView]
    evidence: list[EvidenceView]


class CorrelationItem(BaseModel):
    entity_id: uuid.UUID
    type: EntityType
    value: str
    incident_count: int
    incidents: list[dict[str, str]]


class AuditView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    occurred_at: datetime
    actor_id: uuid.UUID | None
    action: str
    object_type: str
    object_id: str
    ip_address: str | None
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import AuditLog


ZERO_HASH = "0" * 64
AUDIT_LOCK_KEY = 112835769


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def append_audit(
    db: Session,
    *,
    actor_id: uuid.UUID | None,
    action: str,
    object_type: str,
    object_id: str,
    payload: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    if db.bind and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": AUDIT_LOCK_KEY})

    previous = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    previous_hash = previous.entry_hash if previous else ZERO_HASH
    occurred_at = datetime.now(timezone.utc)
    safe_payload = payload or {}
    canonical = json.dumps(
        {
            "occurred_at": _timestamp(occurred_at),
            "actor_id": str(actor_id) if actor_id else None,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "ip_address": ip_address,
            "payload": safe_payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    entry_hash = hashlib.sha256((previous_hash + canonical).encode("utf-8")).hexdigest()
    entry = AuditLog(
        occurred_at=occurred_at,
        actor_id=actor_id,
        action=action,
        object_type=object_type,
        object_id=object_id,
        ip_address=ip_address,
        payload=safe_payload,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    db.flush()
    return entry


def verify_audit_chain(entries: list[AuditLog]) -> bool:
    previous_hash = ZERO_HASH
    for entry in entries:
        canonical = json.dumps(
            {
                "occurred_at": _timestamp(entry.occurred_at),
                "actor_id": str(entry.actor_id) if entry.actor_id else None,
                "action": entry.action,
                "object_type": entry.object_type,
                "object_id": entry.object_id,
                "ip_address": entry.ip_address,
                "payload": entry.payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        expected = hashlib.sha256((previous_hash + canonical).encode("utf-8")).hexdigest()
        if entry.previous_hash != previous_hash or entry.entry_hash != expected:
            return False
        previous_hash = entry.entry_hash
    return True

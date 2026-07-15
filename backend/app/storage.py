from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

import aiofiles
from fastapi import HTTPException, UploadFile, status

from .config import get_settings
from .models import EvidenceKind


CHUNK_SIZE = 1024 * 1024
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
}


@dataclass(frozen=True)
class StoredUpload:
    original_name: str
    stored_name: str
    storage_path: str
    content_type: str
    size_bytes: int
    sha256: str
    kind: EvidenceKind


def clean_filename(filename: str | None) -> str:
    base = Path(filename or "evidence.bin").name
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", base).strip()
    return cleaned[:500] or "evidence.bin"


async def store_upload(upload: UploadFile) -> StoredUpload:
    settings = get_settings()
    settings.evidence_root.mkdir(parents=True, exist_ok=True)
    original_name = clean_filename(upload.filename)
    suffix = Path(original_name).suffix.lower()[:20]
    stored_name = f"{uuid.uuid4().hex}{suffix}"
    destination = settings.evidence_root / stored_name
    digest = hashlib.sha256()
    size = 0
    head = b""

    try:
        async with aiofiles.open(destination, "xb") as output:
            while chunk := await upload.read(CHUNK_SIZE):
                if not head:
                    head = chunk[:4]
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Upload exceeds {settings.max_upload_bytes} bytes",
                    )
                digest.update(chunk)
                await output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()

    kind = EvidenceKind.PCAP if head in PCAP_MAGICS else EvidenceKind.FILE
    return StoredUpload(
        original_name=original_name,
        stored_name=stored_name,
        storage_path=str(destination),
        content_type=upload.content_type or "application/octet-stream",
        size_bytes=size,
        sha256=digest.hexdigest(),
        kind=kind,
    )

from __future__ import annotations

from celery import Celery

from .config import get_settings


settings = get_settings()
celery_app = Celery("caselens", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    accept_content=["json"],
    task_serializer="json",
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    imports=("app.tasks",),
)

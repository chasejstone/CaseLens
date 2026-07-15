from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text

from .audit import append_audit
from .auth import hash_password
from .config import get_settings
from .database import SessionLocal
from .models import Role, User
from .routers import audit_routes, auth_routes, correlations, evidence, incidents, jobs, report_routes, users


settings = get_settings()


def bootstrap_admin() -> None:
    with SessionLocal() as db:
        if db.scalar(select(func.count(User.id))):
            return
        user = User(
            email=settings.bootstrap_admin_email.lower(),
            display_name=settings.bootstrap_admin_name,
            password_hash=hash_password(settings.bootstrap_admin_password),
            role=Role.ADMIN,
        )
        db.add(user)
        db.flush()
        append_audit(
            db,
            actor_id=user.id,
            action="user.bootstrap_created",
            object_type="user",
            object_id=str(user.id),
            payload={"email": user.email, "role": user.role.value},
        )
        db.commit()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap_admin()
    yield


app = FastAPI(
    title="CaseLens API",
    version="0.1.0",
    docs_url="/api/docs" if settings.environment != "production" else None,
    openapi_url="/api/openapi.json" if settings.environment != "production" else None,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

for router in (
    auth_routes.router,
    users.router,
    incidents.router,
    evidence.router,
    jobs.router,
    correlations.router,
    audit_routes.router,
    report_routes.router,
):
    app.include_router(router)


@app.get("/api/health")
def health():
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ok"}

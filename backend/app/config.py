from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


INSECURE_JWT_SECRETS = {
    "development-only-change-this-secret",
    "replace-with-at-least-24-random-characters",
}
INSECURE_BOOTSTRAP_PASSWORDS = {
    "change-this-password",
    "replace-with-a-long-admin-password",
}
INSECURE_DATABASE_MARKERS = (
    "caselens:caselens@",
    "caselens-development",
    "replace-with-a-database-password",
)


class Settings(BaseSettings):
    app_name: str = "CaseLens"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://caselens:caselens@db:5432/caselens"
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str = "development-only-change-this-secret"
    access_token_minutes: int = 480
    cookie_secure: bool = False
    evidence_root: Path = Path("/data/evidence")
    max_upload_bytes: int = 100 * 1024 * 1024
    allowed_origins: str = "http://localhost:3000,http://localhost:8080"
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_name: str = "CaseLens Administrator"
    bootstrap_admin_password: str = "change-this-password"

    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    @field_validator("jwt_secret")
    @classmethod
    def validate_secret(cls, value: str, info) -> str:
        if len(value) < 24:
            raise ValueError("JWT_SECRET must contain at least 24 characters")
        return value

    @model_validator(mode="after")
    def reject_production_defaults(self) -> "Settings":
        if self.environment.lower() == "production":
            if self.jwt_secret in INSECURE_JWT_SECRETS:
                raise ValueError("JWT_SECRET must be changed in production")
            if self.bootstrap_admin_password in INSECURE_BOOTSTRAP_PASSWORDS:
                raise ValueError("BOOTSTRAP_ADMIN_PASSWORD must be changed in production")
            if any(marker in self.database_url for marker in INSECURE_DATABASE_MARKERS):
                raise ValueError("DATABASE_URL must not use a placeholder password in production")
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE must be true in production")
        return self

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings


VALID_PRODUCTION_SETTINGS = {
    "environment": "production",
    "database_url": "postgresql+psycopg://caselens:a-unique-database-password@db:5432/caselens",
    "jwt_secret": "a-unique-jwt-secret-with-enough-length",
    "bootstrap_admin_password": "a-unique-bootstrap-password",
    "cookie_secure": True,
}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("jwt_secret", "replace-with-at-least-24-random-characters", "JWT_SECRET"),
        ("bootstrap_admin_password", "replace-with-a-long-admin-password", "BOOTSTRAP_ADMIN_PASSWORD"),
        (
            "database_url",
            "postgresql+psycopg://caselens:replace-with-a-database-password@db:5432/caselens",
            "DATABASE_URL",
        ),
    ],
)
def test_production_rejects_example_placeholders(field: str, value: str, message: str) -> None:
    values = {**VALID_PRODUCTION_SETTINGS, field: value}
    with pytest.raises(ValidationError, match=message):
        Settings(**values)


def test_production_accepts_replaced_secrets() -> None:
    settings = Settings(**VALID_PRODUCTION_SETTINGS)
    assert settings.environment == "production"

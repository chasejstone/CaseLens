from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest


from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app


@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, email: str, password: str):
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def create_user(client: TestClient, email: str, role: str, password: str = "a-strong-password"):
    response = client.post(
        "/api/users",
        json={"email": email, "display_name": email.split("@")[0].title(), "password": password, "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_role_enforcement_and_incident_workflow(client: TestClient) -> None:
    login(client, "admin@example.com", "change-this-password")
    create_user(client, "analyst@example.com", "analyst")
    create_user(client, "viewer@example.com", "read_only")

    login(client, "analyst@example.com", "a-strong-password")
    created = client.post(
        "/api/incidents",
        json={"title": "Suspicious DNS activity", "summary": "Repeated lookups need review.", "severity": "high"},
    )
    assert created.status_code == 201, created.text
    incident = created.json()
    assert incident["case_number"].startswith("CL-")

    note = client.post(f"/api/incidents/{incident['id']}/notes", json={"body": "Host isolated by desktop support."})
    assert note.status_code == 201

    login(client, "viewer@example.com", "a-strong-password")
    denied = client.post("/api/incidents", json={"title": "Viewer cannot create", "severity": "low"})
    assert denied.status_code == 403
    visible = client.get(f"/api/incidents/{incident['id']}")
    assert visible.status_code == 200
    assert visible.json()["notes"][0]["body"].startswith("Host isolated")


def test_evidence_upload_queue_and_audit_chain(client: TestClient) -> None:
    login(client, "admin@example.com", "change-this-password")
    incident = client.post(
        "/api/incidents",
        json={"title": "Packet capture review", "summary": "Review traffic from a server.", "severity": "medium"},
    ).json()
    upload = client.post(
        f"/api/incidents/{incident['id']}/evidence",
        files={"upload": ("capture.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 24, "application/vnd.tcpdump.pcap")},
    )
    assert upload.status_code == 201, upload.text
    evidence = upload.json()
    assert evidence["kind"] == "pcap"
    assert len(evidence["sha256"]) == 64

    with patch("app.routers.evidence.analyze_evidence.delay", return_value=SimpleNamespace(id="task-123")):
        queued = client.post(f"/api/evidence/{evidence['id']}/analyze")
    assert queued.status_code == 202, queued.text
    assert queued.json()["status"] == "queued"

    with patch("app.routers.evidence.analyze_evidence.delay", side_effect=RuntimeError("offline")):
        unavailable = client.post(f"/api/evidence/{evidence['id']}/analyze")
    assert unavailable.status_code == 503
    assert client.get("/api/jobs").json()[0]["status"] == "failed"

    chain = client.get("/api/audit/verify")
    assert chain.status_code == 200
    assert chain.json()["valid"] is True
    assert chain.json()["entries"] >= 4


def test_reports_escape_investigation_content(client: TestClient) -> None:
    login(client, "admin@example.com", "change-this-password")
    incident = client.post(
        "/api/incidents",
        json={"title": "<script>alert(1)</script>", "summary": "Executive review", "severity": "critical"},
    ).json()
    report = client.get(f"/api/incidents/{incident['id']}/reports/executive")
    assert report.status_code == 200
    assert "&lt;script&gt;" in report.text
    assert "<script>alert" not in report.text

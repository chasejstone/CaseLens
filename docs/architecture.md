# Architecture

CaseLens separates interactive requests from evidence processing. The web application and API stay responsive while workers handle analysis jobs.

```text
Browser
  |
  v
Nginx gateway :8080
  |                 |
  v                 v
Web service      FastAPI service
                      |
             PostgreSQL and evidence volume
                      |
                      v
                 Redis queue
                      |
                      v
                 Celery worker
                  |         |
                  v         v
              Crucible   PacketLens
```

## Data model

An incident owns notes, uploaded evidence, and correlated entities. Each analysis job points to one evidence record and stores its lifecycle, structured findings, error details, and timestamps. Entities are normalized by type and value, then linked to every incident where they occur.

Users are assigned one of three roles: admin, analyst, or read only. The API enforces permissions on every route. The frontend uses the same role information to hide actions that are not available, but it is not the security boundary.

## Analysis lifecycle

1. The API streams an upload to the evidence volume while computing SHA-256.
2. The API records evidence metadata and an audit entry in PostgreSQL.
3. An analyst queues a job. Celery publishes it through Redis.
4. A worker claims the job and selects the adapter from the evidence type.
5. The adapter runs the pinned Crucible or PacketLens library without executing uploaded programs.
6. Findings and extracted entities are committed in one database transaction.
7. Job completion and failure events are added to the audit chain.

Workers never execute uploaded programs. Crucible runs in static-analysis mode inside the worker container.

## Persistence

PostgreSQL is the system of record for investigations, findings, users, correlations, and audit entries. Original evidence is stored on a dedicated Docker volume. Redis carries transient queue state and is not a source of record.

The initial Alembic migration also creates a PostgreSQL trigger that rejects update, delete, and truncate operations on the audit table. Each audit entry includes the previous entry hash, which makes later tampering detectable through the verification endpoint.

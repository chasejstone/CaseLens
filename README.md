# CaseLens

CaseLens is a security operations case manager for file and network investigations. It brings Crucible and PacketLens into one workflow so a team can collect evidence, queue analysis, correlate indicators, document decisions, and produce reports without passing artifacts between separate tools.

## What it covers

- Incident ownership, severity, status, notes, and evidence
- File and PCAP uploads with SHA-256 verification
- Background analysis through Celery and Redis
- Static file inspection through Crucible
- PCAP inspection through PacketLens
- Correlation of IP addresses, domains, hashes, and MITRE ATT&CK techniques
- Admin, analyst, and read-only access levels
- Append-only, hash-chained audit history
- Executive and technical HTML reports
- PostgreSQL persistence, Docker deployment, and CI checks

## Run it with Docker

Requirements: Docker Desktop or Docker Engine with Compose.

```powershell
Copy-Item .env.example .env
```

Edit `.env` and replace the database password, JWT secret, and bootstrap administrator password. For a production deployment, set `ENVIRONMENT=production`, `COOKIE_SECURE=true`, and serve CaseLens over HTTPS.

```powershell
docker compose up --build
```

Open `http://localhost:8080` and sign in with the bootstrap administrator account from `.env`. The initial account is only created when the users table is empty.

## Investigation flow

1. Create an incident and assign an analyst.
2. Add investigation notes and upload evidence.
3. Queue an analysis from the evidence panel.
4. Review the job output and correlated indicators.
5. Export an executive summary or technical report.

Crucible is used for static file inspection only. Its dynamic execution path is intentionally disabled in the shared worker. PacketLens handles supported PCAP and PCAPNG captures. The worker stores structured findings in PostgreSQL and keeps original evidence in the configured evidence volume.

## Roles

| Role | Access |
| --- | --- |
| Admin | Full investigation access, account management, assignment, audit history, and chain verification |
| Analyst | Create and update incidents, add notes, upload evidence, queue jobs, and export reports |
| Read only | Review incidents, evidence metadata, findings, correlations, and reports |

## Local development

The frontend requires Node.js 22 or newer. The API targets Python 3.12.

```powershell
npm install
npm run dev
```

In another terminal:

```powershell
python -m venv .venv
.\.venv\Scripts\pip.exe install -r backend\requirements-dev.txt
$env:DATABASE_URL = "postgresql+psycopg://caselens:password@localhost:5432/caselens"
$env:REDIS_URL = "redis://localhost:6379/0"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
```

Start a worker after PostgreSQL and Redis are available:

```powershell
.\.venv\Scripts\python.exe -m celery --workdir backend -A app.celery_app:celery_app worker --loglevel=INFO
```

Run the checks:

```powershell
npm test
npm run lint
Push-Location backend
& ..\.venv\Scripts\python.exe -m pytest tests -q
Pop-Location
docker compose config
```

## Project layout

- `app/`: analyst web interface
- `backend/app/`: API, authorization, analysis adapters, audit chain, and reports
- `backend/migrations/`: PostgreSQL schema and audit immutability trigger
- `deploy/`: gateway configuration and security headers
- `docs/`: architecture and deployment security notes
- `.github/workflows/ci.yml`: frontend, backend, and Compose validation

See [architecture.md](docs/architecture.md) for the service boundaries and [security.md](docs/security.md) before exposing the platform outside a trusted network.

## Upstream analyzers

The worker installs fixed revisions of [Crucible](https://github.com/chasejstone/Crucible) and [PacketLens](https://github.com/chasejstone/PacketLens). Update those pins deliberately, then rerun the backend tests and analyze representative samples before deployment.

## License

MIT

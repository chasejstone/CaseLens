# Deployment security

CaseLens processes untrusted evidence. Treat the worker, storage volume, and report output as security-sensitive components.

## Before production

- Generate unique database, JWT, and bootstrap account secrets.
- Set `ENVIRONMENT=production` and `COOKIE_SECURE=true`.
- Terminate TLS at the gateway or an upstream load balancer.
- Restrict PostgreSQL and Redis to the private service network.
- Mount evidence storage on an encrypted volume with monitored capacity.
- Back up PostgreSQL and evidence together so records and files remain consistent.
- Put the worker on a host with no access to internal secrets or administrative networks.
- Forward container and gateway logs to the organization monitoring system.

Production startup rejects known example secrets, placeholder database passwords, and insecure cookie settings.

## Authentication and authorization

Passwords are stored with Argon2. Successful login returns a signed, expiring token in an HttpOnly cookie. The cookie uses SameSite Lax and should use the Secure flag in production. The API also accepts a bearer token for controlled integrations.

Authorization is enforced in the API. Read-only accounts cannot change incident data or queue analysis. Only administrators can create accounts, assign incidents, inspect the audit log, and verify its chain.

The Nginx gateway limits repeated login attempts and sets content, frame, referrer, and script policies. For internet-facing use, add organization SSO, centralized rate limiting, and session revocation before onboarding users.

## Evidence handling

Uploads are streamed with a configurable maximum size and named on disk by generated identifiers. The service does not trust browser MIME types when deciding whether a capture is a PCAP. It checks capture magic bytes and calculates SHA-256 during storage.

Analyzers are called through pinned Python libraries. Uploaded files are never passed through a shell. Crucible dynamic execution is disabled. Stronger deployments should add task time limits, container seccomp or AppArmor rules, a read-only worker root filesystem, CPU and memory limits, and an isolated analysis subnet.

## Audit guarantees

Application events form a SHA-256 hash chain. PostgreSQL blocks update, delete, and truncate operations against the audit table. Administrators can run chain verification from the API.

This design makes modifications detectable and prevents ordinary database roles from rewriting history. It does not protect against a database superuser who can disable triggers or replace the entire database. Ship audit events or signed chain checkpoints to separate storage when that threat is in scope.

## Reports

Report templates escape investigation content before rendering HTML. Reports may still contain sensitive evidence names, findings, indicators, and notes. Apply the same retention and distribution controls used for incident data.

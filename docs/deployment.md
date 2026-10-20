# Deployment checklist

Do not deploy this educational build as an identity provider without further engineering and review. A deployment should use:

1. HTTPS/TLS at a trusted reverse proxy; set `SECURE_COOKIES=true`, then enable HSTS only on correctly terminated HTTPS.
2. Unique `APP_SECRET` (32+ characters) and a generated Fernet `MFA_ENCRYPTION_KEY` in a managed secret store; back up/rotate keys securely.
3. PostgreSQL with a least-privilege DB account, private networking, backups and tested restore; run `alembic upgrade head` during controlled release.
4. Exact `CORS_ORIGINS`, production `ENVIRONMENT`, `DEBUG` disabled, no development-only email links, SMTP configured and verified.
5. Shared Redis/distributed rate limits and shared short-lived MFA challenge storage before multiple API workers/replicas.
6. Non-public database/admin ports, patched base images/dependencies, secret scanning, dependency audit, monitoring/log retention with sensitive-value redaction.
7. Independent security review and functional abuse testing; none is claimed here.

Compose is a local development stack bound to localhost (SQLite volume). A multi-stage image builds the Vite bundle and runs a single non-root FastAPI/Uvicorn application process serving the UI and API; no TLS is provided. Production HSTS and trusted proxy behavior must be configured at the real HTTPS edge. PostgreSQL runtime compatibility is configured through SQLAlchemy URL but was not verified against a running PostgreSQL service.

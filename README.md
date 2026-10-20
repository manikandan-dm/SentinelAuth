# SentinelAuth

**Intelligent Authentication & Account Protection Platform** — an educational portfolio application demonstrating secure login, server-side sessions, MFA, account recovery and explainable account monitoring. It is not certified, independently penetration-tested, or intended to protect real accounts as-is.

## Architecture and integration

- React 18 + TypeScript + Vite builds the client into `frontend/dist`.
- `python run.py` builds the frontend and starts one Uvicorn/FastAPI process. FastAPI serves the static bundle, client-side routes and `/api/v1/...` endpoints from the same origin. There is no separate frontend server in the integrated workflow.
- FastAPI uses SQLAlchemy 2, SQLite locally, PostgreSQL-compatible URLs with the pinned psycopg driver, and Alembic as schema source of truth.
- Vite dev server support remains available for frontend work, but is optional and not used by the integrated application command.

## Implemented features

- Name, email and password registration; normalized unique email; Argon2id password hashing; generic invalid-login message.
- Cryptographically opaque server-side session cookies; session-token hashes only in the database; HttpOnly/SameSite cookie; configurable Secure attribute; CSRF double-submit on authenticated mutations; 12-hour expiry and 30-minute idle timeout; logout, session listing/revocation, session rotation on login/MFA changes and revocation after password reset.
- TOTP enrollment with QR + manual fallback; Fernet-encrypted TOTP key; current-password proof for MFA changes; one-use login pre-auth challenges; TOTP replay watermark; eight single-use recovery codes stored as hashes.
- Hashed, expiring, single-use email-verification/password-reset tokens; SMTP adapter and explicit development-only local links if SMTP is absent in development. Configure an absolute `PUBLIC_BASE_URL` when delivering email.
- Persisted login/MFA/risk events, deterministic explainable risk scoring, repeated-failure and repeated-reset alerts, role-aware monitoring, user-scoped event data and administrator-only alert transitions with audit entries.
- Responsive React UI for landing, login, registration, dashboard, account security, MFA, recovery, sessions, alerts, event timeline and admin monitoring.

## Limitations

Process-local login/email/MFA throttles and pre-auth challenge state do not work across multiple workers/instances. No Redis integration, IP reputation, geo anomaly, external intelligence, trained AI, WebAuthn, verified SMTP account or operational alert delivery exists. Database migrations and automated tests are provided, but PostgreSQL runtime is not verified here. The app is not independently security reviewed; additional production engineering and a security assessment are required.

## Prerequisites and one-time setup

Requires Python 3.11+ and Node.js 20.19+ with npm. Python 3.12 or 3.13 is recommended and tested in this workspace (Python 3.13.16); Python 3.14 was not available here. SQLAlchemy is pinned to 2.0.50, which includes the upstream Python 3.14 typing compatibility fix (2.0.41+ is required).

1. Copy `.env.example` to `.env` (PowerShell: `Copy-Item .env.example .env`).
2. Generate secrets:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set the first output as `MFA_ENCRYPTION_KEY` and the second as `APP_SECRET` in `.env`. Development defaults are placeholders only. Keep `.env` out of Git.
3. Install backend requirements once:

```sh
python -m pip install -r backend/requirements.txt
```

4. Install frontend dependencies once:

```sh
cd frontend && npm ci && cd ..
```

Windows PowerShell uses the same commands after installing Python and Node. Linux/Kali can use `python3` and `python -m pip`.

## One-command integrated startup

From the project root:

```sh
python run.py
```

**Open:** http://127.0.0.1:8000  
**Health:** http://127.0.0.1:8000/api/v1/health  
**Development API docs:** http://127.0.0.1:8000/docs

`run.py` checks dependencies, builds the frontend, optionally applies forward-only migrations when `AUTO_MIGRATE=true`, and starts FastAPI serving both UI and API. It does not silently install packages, create secrets, overwrite `.env`, or reset a database. If frontend packages are missing, install them once with `cd frontend && npm ci`. If `AUTO_MIGRATE=false`, apply schema first using `cd backend && alembic upgrade head`.

The sample `.env.example` sets `AUTO_MIGRATE=true` for convenient local setup. Set it to `false` in production and run migrations through a controlled deployment step.

Optional development mode: `cd frontend && npm run dev` uses the Vite proxy; this is not needed for the integrated `python run.py` workflow.

## Database, SMTP and administrator setup

Default DB URL: `sqlite:///./sentinelauth.db`, relative to the backend working directory. Override `DATABASE_URL` with a SQLAlchemy URL, e.g. `postgresql+psycopg://...`. `psycopg[binary]` is included; PostgreSQL service connectivity is not verified here. Run `cd backend && alembic upgrade head`, inspect `alembic current`, check drift with `alembic check`, and back up databases before changes. SQLite DB files are gitignored and never mounted as static files.

Optional SMTP variables: `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_STARTTLS`, and absolute `PUBLIC_BASE_URL` (e.g. `https://auth.example.test`). Without SMTP in development, the UI shows local one-time verification/reset links. In production no development token links are returned. SMTP delivery was not verified because no credentials were supplied.

No HTTP admin-promotion endpoint exists. After creating and verifying an account, a trusted operator can promote it offline:

```sh
cd backend
python -m app.provision_admin verified-user@example.com --confirm
```

This CLI revokes existing sessions. Protect host/database access.

## Tests and checks

```sh
cd backend && pytest -q
cd backend && alembic check
cd backend && python -m pip check
cd backend && pip-audit -r requirements.txt  # install pip-audit first if needed
cd frontend && npm test
cd frontend && npm run build
cd frontend && npm audit --audit-level=high
```

Automated integration tests use isolated SQLite databases; clean migration behavior is covered. No secret-scanning CLI was available in the workspace; manual pattern checks found no private-key blocks, and `.env` is not present. Do not interpret that as comprehensive secret scanning.

## API and deployment

OpenAPI docs are at `/docs` in development. Endpoints include `/api/v1/auth/register`, `/login`, `/me`, `/logout`, `/sessions`, `/mfa/*`, `/email-verification/*`, `/password-reset/*`, `/profile` and `/api/v1/security/*`. Mutations with a cookie session require the CSRF cookie mirrored in `X-CSRF-Token`; the shared client handles this.

`docker compose up --build` builds and serves a local frontend/API stack on localhost, runs Alembic migrations, and persists SQLite data in a named volume. Docker was unavailable in the validation environment, so this workflow is documented but not verified by a container build.

Outside development, startup rejects the sample APP_SECRET, requires a valid MFA_ENCRYPTION_KEY, SECURE_COOKIES=true, and HTTPS-only CORS origins. Production still requires HTTPS/TLS termination, managed unique secrets and key backups, PostgreSQL, exact allowed origins, shared rate limits/challenge storage, controlled migrations/backups, verified SMTP, private DB network, operational monitoring and independent security review. No certification or production-security claim is made.

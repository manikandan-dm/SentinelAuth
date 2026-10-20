# Architecture

`python run.py` builds React/TypeScript through Vite, then runs a single Uvicorn/FastAPI process. FastAPI serves the `frontend/dist` asset directory and client-side routes plus versioned `/api/v1` endpoints from the same origin. Browser code uses same-origin relative URLs, cookies and CSRF header. API unknown routes remain JSON 404s; static assets are restricted to the build asset directory. A deployment can use the multi-stage `backend/Dockerfile` to build and serve both frontend and API in one process/container.

FastAPI owns authentication/authorization decisions and persists through SQLAlchemy. SQLite is the local default; PostgreSQL-compatible URLs use psycopg. Alembic revisions are the schema source of truth.

Key code locations: `run.py` (single local startup/build entry), `backend/app/main.py` (API, models, auth/session/MFA/token services and static routing), `backend/app/risk.py` (deterministic risk policy), `backend/app/emailer.py` (SMTP/development adapter), `backend/app/provision_admin.py` (offline admin provisioning), `backend/migrations/versions/` (schema), `frontend/src/api/client.ts` (same-origin client), `frontend/src/App.tsx` and `style.css` (UI).

The backend remains compact rather than fully decomposed. For substantial development, split routers, schemas, models, repositories and services. Rate limits and pre-auth MFA challenges are process-local and require shared storage before scaling horizontally. Startup does not create schema unless explicitly enabled via `AUTO_MIGRATE=true`.

# SentinelAuth
### Intelligent Authentication & Account Protection Platform

**A full-stack cybersecurity portfolio project focused on secure authentication, session protection, multi-factor authentication, and explainable security monitoring.**

<p align="center">

  **React · TypeScript · FastAPI · SQLAlchemy · SQLite · Alembic**

</p>

---

## Overview

SentinelAuth is a full-stack web application designed to demonstrate how modern authentication systems can protect user accounts, manage sessions securely, and monitor suspicious authentication activity.

The platform combines a responsive React interface with a FastAPI backend, database-backed session management, multi-factor authentication, account recovery workflows, and explainable security event monitoring.

The application is designed to run as a **single integrated web application**. A single startup command builds the frontend and starts the backend, which serves both the user interface and API from the same origin.

> **Project status:** Educational cybersecurity portfolio project. It is not certified, independently penetration-tested, or ready to protect real accounts without additional security engineering and review.

## Key Features

### Authentication & Account Security

- User registration with normalized email addresses and duplicate-account protection.
- Argon2id password hashing.
- Generic invalid-login responses to reduce account-enumeration disclosure.
- Server-side session management with opaque session tokens.
- HttpOnly cookies and configurable cookie security settings.
- Session expiration, idle timeout, logout, revocation, and session rotation.
- CSRF protection for authenticated state-changing requests.

### Multi-Factor Authentication

- Time-based one-time password (TOTP) authentication.
- QR-code enrollment and manual setup fallback.
- Encrypted storage of TOTP secrets.
- Password confirmation for sensitive MFA changes.
- Single-use recovery codes stored as hashes.
- Replay protection for previously accepted TOTP codes.

### Account Recovery

- Email verification with expiring, single-use tokens.
- Password reset with expiring, single-use tokens.
- Token hashes stored instead of raw recovery tokens.
- Optional SMTP integration.
- Explicit development-only verification and reset links when SMTP is not configured.

### Security Monitoring

- Persisted authentication and security events.
- Explainable, deterministic risk scoring.
- Detection rules for repeated authentication failures and password-reset activity.
- Security alerts and event history.
- User-scoped security information.
- Role-based administrative monitoring and audited alert transitions.

### Integrated Web Application

- Responsive React and TypeScript interface.
- Dashboard, login, registration, account security, MFA, session management, alerts, and activity pages.
- FastAPI serves the production-built frontend and backend API from the same origin.
- One-command local startup workflow.
- SQLAlchemy ORM and Alembic database migrations.
- Automated backend tests and frontend build checks.

## Architecture

```mermaid
flowchart TD
    U[User / Browser]
    UI[React + TypeScript Frontend]
    API[FastAPI Application]
    AUTH[Authentication & Session Services]
    MFA[MFA & Account Recovery]
    MON[Security Monitoring & Risk Rules]
    DB[(SQLAlchemy Database)]
    MAIL[Optional SMTP Service]

    U --> UI
    UI --> API
    API --> AUTH
    API --> MFA
    API --> MON
    AUTH --> DB
    MFA --> DB
    MON --> DB
    MFA -. Optional email delivery .-> MAIL
```

### Request Flow

1. The user interacts with the React frontend.
2. The frontend sends requests to the FastAPI backend using same-origin API endpoints.
3. The backend validates requests, authentication state, authorization, and CSRF requirements.
4. SQLAlchemy accesses the configured database.
5. Security-relevant events are recorded and evaluated by the monitoring rules.
6. The API returns the result to the frontend.

The frontend is built into `frontend/dist`. During integrated execution, FastAPI serves the compiled frontend and API routes through one server process.

## Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React 18, TypeScript, Vite |
| Backend | Python, FastAPI, Uvicorn |
| Database access | SQLAlchemy 2 |
| Local database | SQLite |
| PostgreSQL support | SQLAlchemy-compatible URL and psycopg driver |
| Database migrations | Alembic |
| Password security | Argon2id |
| MFA | TOTP, Fernet encryption |
| Authentication | Server-side sessions, secure cookie controls, CSRF protection |
| Testing | Pytest and available frontend checks |
| Deployment workflow | Integrated startup script; Docker Compose configuration |

## Project Structure

```text
SentinelAuth/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── emailer.py
│   │   ├── provision_admin.py
│   │   └── ...
│   ├── migrations/
│   ├── tests/
│   ├── requirements.txt
│   └── alembic.ini
├── frontend/
│   ├── src/
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
├── docs/
├── .env.example
├── .gitignore
├── run.py
├── docker-compose.yml
└── README.md
```

*The tree is representative; individual files may vary by project version.*

## Getting Started

### Prerequisites

- Python 3.12 or 3.13 recommended.
- Node.js 20.19 or later, with npm.
- Git.
- A terminal on Linux, macOS, or Windows.

Python 3.14 compatibility depends on the exact dependency set. Use the project's pinned requirements and verify installation and tests in your environment.

### 1. Clone the Repository

```bash
git clone https://github.com/manikandan-dm/SentinelAuth.git
cd SentinelAuth
```

### 2. Create a Python Virtual Environment

Linux / Kali Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install Backend Dependencies

From the project root:

```bash
python -m pip install -r backend/requirements.txt
```

### 4. Install Frontend Dependencies

```bash
cd frontend
npm ci
cd ..
```

### 5. Configure Environment Variables

Create a local environment file:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Generate an MFA encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Generate an application secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set the generated values in `.env`:

```dotenv
ENVIRONMENT=development
AUTO_MIGRATE=true
DATABASE_URL=sqlite:///./sentinelauth.db
APP_SECRET=replace-with-your-generated-secret
MFA_ENCRYPTION_KEY=replace-with-your-generated-fernet-key
SECURE_COOKIES=false
```

Replace both placeholder values with your generated secrets. Keep `.env` private and never commit it to Git.

For local development, `SECURE_COOKIES=false` permits HTTP-based local testing. Production must use HTTPS and appropriate secure-cookie settings.

### 6. Start the Integrated Application

From the repository root:

```bash
python run.py
```

The startup script builds the frontend, optionally applies forward-only database migrations according to the configuration, and starts the integrated FastAPI application.

**Local application:** http://127.0.0.1:8000

**Health endpoint:** http://127.0.0.1:8000/api/v1/health

**Development API documentation:** http://127.0.0.1:8000/docs

The health endpoint and documentation availability depend on the running application's configuration.

### Optional: Development Mode

For frontend-only development, the Vite development server can be used separately:

```bash
cd frontend
npm run dev
```

This is optional and is not required for the integrated `python run.py` workflow.

## Database & Migrations

The default local database uses SQLite:

```dotenv
DATABASE_URL=sqlite:///./sentinelauth.db
```

A PostgreSQL-compatible SQLAlchemy URL can be configured when a suitable database server is available:

```dotenv
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE
```

Before changing schemas or deploying:

- Back up existing data.
- Review the Alembic migration history.
- Apply migrations through a controlled process.
- Verify the resulting schema.
- Do not delete or recreate a database to resolve migration errors.

PostgreSQL runtime connectivity must be verified separately in the target environment.

## Security Design

SentinelAuth demonstrates several security engineering practices:

- Password hashing using Argon2id.
- Opaque session tokens with hashes stored server-side.
- HttpOnly cookie-based sessions.
- Session expiry and revocation.
- CSRF protection for authenticated mutations.
- Encrypted TOTP secret storage.
- Hashed, expiring, single-use recovery tokens.
- One-use account recovery codes.
- Authorization checks for administrative functionality.
- Persisted security events and explainable risk rules.
- Environment-based configuration for application secrets.

These controls are implementation features, not proof that the application is free of vulnerabilities.

## Testing & Quality Checks

Run the following checks from the project root where applicable.

### Backend Tests

```bash
cd backend
pytest -q
python -m pip check
alembic check
cd ..
```

### Frontend Build

```bash
cd frontend
npm run build
npm audit --audit-level=high
```

Run `npm test` if a test script is configured in `frontend/package.json`.

For a more complete review, test registration, login, logout, session expiration, CSRF validation, MFA enrollment, account recovery, authorization boundaries, and migration behavior.

**Testing status:** Publish actual test results only after running the checks. A successful frontend build alone does not establish that every authentication or security workflow is correct.

## Limitations & Future Improvements

The current design has known limitations:

- Rate limits and pre-authentication challenge state are process-local.
- Shared rate limiting and challenge storage are not implemented with Redis.
- No IP reputation or geolocation-based anomaly detection.
- Risk scoring is deterministic and rule-based, not a trained AI model.
- WebAuthn/passkeys are not implemented.
- SMTP delivery has not been verified without valid SMTP credentials.
- PostgreSQL runtime behavior requires separate verification.
- The Docker Compose workflow requires validation in a Docker-capable environment.
- The project has not undergone an independent penetration test or security audit.

### Potential Future Enhancements

- Redis-backed distributed rate limiting and challenge storage.
- WebAuthn/passkey authentication.
- Improved security event correlation and configurable alert rules.
- Verified SMTP integration and operational alert delivery.
- PostgreSQL integration testing.
- Automated dependency and secret scanning.
- Containerized deployment validation.
- Independent security review and penetration testing.

## Deployment Considerations

Before any production deployment:

- Use HTTPS with correctly configured TLS termination.
- Set `SECURE_COOKIES=true`.
- Use unique, strong, managed secrets and plan encryption-key backups.
- Configure exact trusted origins and email delivery settings.
- Use an appropriately secured database and tested migration procedures.
- Implement shared rate limiting and challenge storage for multiple workers.
- Protect database backups and operational logs.
- Monitor application health and security events.
- Perform an independent security assessment.

The included local configuration is intended for development, not production deployment.

## Documentation

Additional documentation is available in the `docs/` directory, including architecture, database schema, deployment, account security, risk scoring, security monitoring, and validation topics where provided.

## Disclaimer

SentinelAuth is an educational portfolio project intended to demonstrate full-stack development and security engineering concepts. It is provided without security certification or a guarantee of suitability for real-world account protection. Review the implementation, verify the configuration, test the deployed environment, and obtain independent security review before using it with real users.

## Author

**Manikandan D**

GitHub: [@manikandan-dm](https://github.com/manikandan-dm)

Project: [SentinelAuth](https://github.com/manikandan-dm/SentinelAuth)

---

*Built as a cybersecurity learning project exploring secure authentication, account protection, and application security monitoring.*

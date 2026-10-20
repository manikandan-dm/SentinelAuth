# Database schema

Models and relationships are declared in `backend/app/main.py`. Tables are created by the committed initial Alembic revision in `backend/migrations/versions/5935a40bb9ff_initial_schema.py`:

- `users`: unique indexed normalized email, display name, Argon2 password hash, role, active/verified/MFA flags, created time.
- `user_sessions`: user FK, unique indexed SHA-256 token hash, CSRF verifier hash, creation/last-activity/expiry times, revocation state, bounded user-agent metadata.
- `mfa_credentials`: one encrypted TOTP credential per user plus last accepted TOTP step for replay resistance.
- `recovery_codes`: per-user code hashes and single-use state.
- `one_time_tokens`: hashed unique verification/reset token, purpose, expiry and used flag.
- `login_events`: safe account hint, result, source and timestamp; may have no user for unknown accounts.
- `risk_events`: score, severity, decision and explanatory factors.
- `security_alerts`: severity/status/title/description, owner, unique correlation id and timestamps.
- `audit_logs`: safe actor/action/resource/timestamp metadata.

Run `cd backend && alembic upgrade head` to initialize a clean SQLite DB, `alembic current` to inspect, and `alembic check` for metadata drift. PostgreSQL compatibility comes from SQLAlchemy but has not been integration-tested here. Do not use runtime `create_all`; migrations are authoritative. Foreign-key deletes are configured on account-owned secret/token tables; SQLite deployments should ensure foreign-key enforcement is enabled if relying on cascades.

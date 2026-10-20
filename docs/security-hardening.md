# Security hardening implemented

- Argon2id through argon2-cffi with a maintained memory-hard configuration.
- Random opaque server sessions; SHA-256 hashes only at rest; HttpOnly SameSite=Lax cookies, configurable Secure attribute, expiry and 30-minute inactivity timeout; current logout and session revocation.
- CSRF double-submit token verification on cookie-authenticated mutations; exact configured credentialed CORS allowlist.
- Pydantic validation, normalized unique email, generic login failure, parameterized ORM, safe output through React text rendering, CSP and common browser security headers.
- Fernet-encrypted TOTP secrets from environment, fresh password proof for MFA changes, TOTP replay watermark, single-use preauth challenges/recovery codes, hashed single-use verification/reset tokens.
- Process-local in-memory rate limiting for registration, login, MFA and recovery email requests. It is reset on restart and not shared across workers.
- Backend authorization scopes own data by account; administrator access is read/transition guarded server-side. No public role mutation route. Offline admin CLI requires a verified existing user and explicit confirmation.
- SMTP adapter and development-only local links; dev links are not returned if `ENVIRONMENT` is non-development.
- API response fallback errors avoid exception detail disclosure. Secret values are not written to the audit event model.

Limitations: No external penetration test, Redis/shared rate limiter, reverse-proxy trust policy, persistent challenge store, key rotation, SIEM, or full browser CSP compatibility audit. Configure TLS before Secure cookies/HSTS. Use production secrets from a managed secret service. The integrated FastAPI middleware applies security headers to API and served frontend responses; production enforces frame denial, while development omits frame-denial headers so browser-based previews can embed the app. TLS/HSTS belongs at HTTPS termination.

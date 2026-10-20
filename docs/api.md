# API reference

Prefix `/api/v1`. Requests/responses use JSON unless noted. Invalid credentials use generic responses. Browser session cookies are HttpOnly and same-site; state-changing authenticated routes require the CSRF cookie mirrored as `X-CSRF-Token`.

## Public authentication

- `GET /health` — health status.
- `POST /auth/register` — `{name,email,password}`; Argon2id hash; may include a `development_only_link` only under development settings.
- `POST /auth/login` — `{email,password}`; returns user or restricted MFA challenge.
- `POST /auth/mfa/verify` — `{challenge_id,code}`; must succeed before full session issuance.
- `POST /auth/email-verification/confirm` — `{token}`.
- `POST /auth/password-reset/request` — `{email}`; generic message; dev-only link only in development.
- `POST /auth/password-reset/confirm` — `{token,password}`; revokes all existing sessions.

## Authenticated user

- `GET /auth/me`, `POST /auth/logout`.
- `GET /auth/sessions`, `POST /auth/sessions/{session_id}/revoke`, `POST /auth/sessions/revoke-others`.
- `PATCH /auth/profile` — `{name}`.
- `POST /auth/email-verification/request` — authenticated, CSRF protected.
- `POST /auth/mfa/enroll` — `{password}`; returns secret and provisioning URI once.
- `POST /auth/mfa/confirm` — `{password,code}`.
- `POST /auth/mfa/disable` — `{password,code}`.
- `POST /auth/mfa/recovery-codes` — `{password,code}`; eight one-time codes returned only for this response.

## Monitoring

- `GET /security/summary`, `/risk-summary`, `/alerts`, `/events` — user-scoped for regular accounts, global for admins.
- `GET /security/alerts/{alert_id}` — owner/admin access.
- `POST /security/alerts/{alert_id}/acknowledge`, `/resolve` — administrator only, CSRF protected and audited.

OpenAPI UI is `http://localhost:8000/docs` in development. Disable/restrict docs in deployment. Admin provisioning is a local CLI only (`python -m app.provision_admin ... --confirm`), not an HTTP endpoint.

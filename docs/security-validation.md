# Security validation record

Verified here: backend suite (registration/hash/duplicate, sessions/logout, CSRF, email token verification and password reset, MFA enrollment/challenge/recovery, auth scopes, security headers, clean migration); risk helper unit tests; frontend route test; production Vite build; npm audit; Python pip dependency consistency; Alembic clean DB migration and metadata check; live API smoke tests recorded in the final report.

Not verified: SMTP delivery (no credentials); PostgreSQL operation; multi-instance rate limiting; full browser-based end-to-end tests; vulnerability scan of Python packages (pip-audit unavailable); secret scanner (gitleaks unavailable); independent penetration test. Those limitations are not treated as passed.

Authorized local checklist: create disposable test account, verify password hash in DB is non-plaintext, inspect cookies (`HttpOnly`, `SameSite`, Secure per TLS), test login/MFA/invalid code/recovery one-use, test CSRF header removal, verify logout rejects session, open a second user and ensure user data isolation, verify non-admin cannot perform alert lifecycle actions, confirm reset tokens expire/use once, and test migrations against a fresh disposable SQLite database. Never test against systems or accounts without permission.

# Advanced account security

TOTP setup requires current-password verification at enrollment and confirmation. The secret is Fernet-encrypted at rest, and provisioning URI plus QR code are displayed for the setup step only. MFA activates only after valid confirmation. A successful code's time-step is recorded to reject replay. Login issues a five-minute restricted pre-auth challenge; a full session is created only after valid TOTP or a single-use recovery code. MFA disablement and recovery-code regeneration require password plus fresh TOTP.

Recovery codes are generated from cryptographically secure randomness, SHA-256 hashed, displayed once and conditionally consumed once. Regeneration invalidates prior codes. Store them offline. Email verification and password reset use random hashed tokens, one-hour/30-minute expiry, single-use conditional updates, and session revocation after password reset. Email is delivered through SMTP configuration; absent SMTP exposes a local dev-only link only when `ENVIRONMENT=development`.

Limitations: pre-auth MFA challenge state is process-local, no WebAuthn, no email provider credentials verified, no persistent token cleanup process, and no independent security assessment. Rotate/back up encryption keys securely; changing the Fernet key without a key-rotation procedure makes existing TOTP secrets unreadable.

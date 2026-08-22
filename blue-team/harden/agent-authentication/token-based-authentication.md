# Token-based Authentication

## Check List

* [ ] ​Validate the authentication flow, token issuance, identity assurance, MFA, and authorization-server trust boundary.
* [ ] Verify token signature, approved algorithm, issuer, audience, subject, claims, scope, `exp`, `nbf`, `iat`, and unique token identifier (`jti`).
* [ ] Test rejection of missing, malformed, tampered, expired, revoked, cross-audience, and replayed bearer tokens.
* [ ] Review access-token lifetime, least-privilege scopes, privilege changes, logout, timeout, session invalidation, and re-authentication controls.
* [ ] Assess refresh-token storage, rotation, reuse detection, device/context binding, revocation, and compromise-response procedures.
* [ ] Check TLS-only transport, secure client-side storage, Secure/HttpOnly/SameSite cookies, and exposure through URLs, logs, browser history, referrers, errors, XSS, and CSRF.

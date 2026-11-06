# Password Authentication

## Check List

* [ ] Enforce strong password policies, breached-password screening, secure enrollment, and TLS-protected authentication.
* [ ] Store passwords only with uniquely salted Argon2id, scrypt, bcrypt, or PBKDF2 hashes; protect peppers separately.
* [ ] Prevent brute-force, spraying, stuffing, enumeration, replay, and timing attacks through throttling, lockouts, generic errors, and constant-time verification.
* [ ] Require MFA and reauthentication for privileged accounts, sensitive operations, and anomalous access.
* [ ] Secure password changes and recovery with identity verification, short-lived single-use tokens, session revocation, and user notifications.
* [ ] Protect sessions using rotation, expiration, CSRF controls, and Secure, HttpOnly, SameSite cookies.
* [ ] Audit authentication events, detect anomalies, alert on attacks, and rotate default, exposed, shared, service, or compromised credentials.

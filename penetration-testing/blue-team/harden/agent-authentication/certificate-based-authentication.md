# Certificate-based Authentication

## Check List

* [ ] Validate the certificate chain up to a trusted root CA.
* [ ] Verify certificate validity, SAN/UPN, key usage, and expiration.
* [ ] Require proof of possession of the corresponding private key.
* [ ] Protect private keys using TPM, HSM, smart cards, or secure keystores.
* [ ] Check certificate revocation through CRL or OCSP.\
  Use mutual TLS to authenticate both client and server.
* [ ] Enforce certificate issuance, renewal, rotation, and decommissioning procedures.
* [ ] Monitor and log certificate-based authentication events.

# simrs-ecies

ECIES Profiles A and B for SUCI computation per 3GPP TS 33.501 Annex C.

Encrypts the MSIN portion of the SUPI to produce a SUCI (Subscription
Concealed Identifier) in 5G-SA networks.

- Profile A: X25519 ECDH + ANSI X9.63 KDF + AES-128-CTR + HMAC-SHA-256
- Profile B: P-256 ECDH + ANSI X9.63 KDF + AES-128-CTR + HMAC-SHA-256

Includes X25519 (RFC 7748), P-256 (FIPS 186-4), and AES-128-CTR
(NIST SP 800-38A) implementations.

`no_std`. No heap allocation.

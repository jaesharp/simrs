# simrs-rsa

RSA encryption/decryption and PKCS#1 v1.5 signing/verification.

Implements RSA raw operations and PKCS#1 v1.5 padding per RFC 8017.
Built on `simrs-bignum` for Montgomery modular exponentiation. Type
aliases for 512-bit through 2048-bit key sizes.

`no_std`, no alloc.

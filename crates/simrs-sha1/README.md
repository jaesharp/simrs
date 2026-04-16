# simrs-sha1

SHA-1 cryptographic hash function per NIST FIPS 180-1.

Required by GlobalPlatform SCP01/SCP02 key derivation and the Java Card
`MessageDigest.ALG_SHA` API. Provides a streaming `Sha1` hasher and a
one-shot `sha1` function.

SHA-1 is cryptographically broken for collision resistance; included
because legacy smart card protocols mandate it.

`no_std`. No heap allocation.

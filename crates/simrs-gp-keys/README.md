# simrs-gp-keys

GlobalPlatform Security Domain key store per GP Card Specification v2.1.1
Appendix C.

Each Security Domain maintains cryptographic keys (ENC, MAC, DEK)
identified by `(key_version_number, key_identifier)` pairs. Supports
multiple key versions for key rotation.

`no_std`. No heap allocation.

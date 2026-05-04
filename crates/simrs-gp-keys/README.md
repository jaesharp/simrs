# simrs-gp-keys

GlobalPlatform Security Domain key store. Implementation derived from
GP Card Specification v2.1.1 Appendix C (the spec the table/clause
numbers were verified against); primary spec target is GP 2.3.1
which reorganises the key store layout into a different appendix.
See `docs/standards/06-globalplatform.md` for the dual-spec map.

Each Security Domain maintains cryptographic keys (ENC, MAC, DEK)
identified by `(key_version_number, key_identifier)` pairs. Supports
multiple key versions for key rotation.

`no_std`. No heap allocation.

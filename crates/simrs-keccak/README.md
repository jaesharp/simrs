# simrs-keccak

Keccak-f[1600] permutation -- the core primitive of SHA-3 and TUAK.

**Layer:** Foundation | **`no_std`:** yes | **Status:** Implemented

## Standards

| Spec | Clause | Coverage |
|------|--------|----------|
| NIST FIPS 202 | Section 3.2 | Keccak-f[1600] 24-round permutation |
| NIST SP 800-185 | -- | SHA-3 derived functions (permutation only) |
| 3GPP TS 35.231 | -- | TUAK uses Keccak-f[1600] directly |

## Dependencies

None (leaf crate).

## API

- `keccak_f1600(&mut [u64; 25])` -- apply the 24-round permutation to 25 lanes
- `keccak_f1600_bytes(&mut [u8; 200])` -- byte-level convenience wrapper (little-endian)

## Tests

4 unit tests + 1 doctest: all-zero known-answer test (KeccakCodePackage reference),
byte/lane round-trip equivalence, non-identity, determinism.

## Specs

- [Architecture](../../docs/architecture.md#simrs-keccak)
- [Standards: Authentication](../../docs/standards/02-authentication.md)

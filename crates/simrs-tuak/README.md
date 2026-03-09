# simrs-tuak

TUAK authentication algorithm -- the 3GPP alternative to Milenage for USIM authentication,
built on Keccak-f[1600].

**Layer:** Foundation | **`no_std`:** yes | **Status:** Implemented

## Standards

| Spec | Clause | Coverage |
|------|--------|----------|
| 3GPP TS 35.231 V19.0.0 | Clauses 4-6 | TUAK algorithm specification |
| 3GPP TS 35.232 V19.0.0 | -- | Implementers' test data |
| 3GPP TS 35.233 V19.0.0 | -- | Design conformance test data |

## Dependencies

- `simrs-keccak` -- Keccak-f[1600] permutation
- `simrs-milenage` -- `AuthenticationAlgorithm` trait, `AuthenticationOutput`, `AuthenticationError`

## API

- `TuakParams` -- TUAK algorithm parameters (K, TOPc)
- `OperatorVariant` -- raw TOP or pre-computed TOPc
- `AuthenticationAlgorithm` trait implementation for integration with `simrs-usim`
- `.authenticate(...)` -- via `AuthenticationAlgorithm` trait default method (shared with Milenage)
- `.compute_response_and_keys(...)` -- batched single-Keccak override (f2/f3/f4 in one call)

### Renamed API

| Old | New | Reason |
|-----|-----|--------|
| `TopVariant` | `OperatorVariant` | TOP is the 3GPP TUAK Operator Parameter |
| `f1` / `f1_star` | `compute_auth_mac` / `compute_resync_mac` | MAC-A / MAC-S computation |
| `f2` / `f3` / `f4` | `compute_response` / `compute_cipher_key` / `compute_integrity_key` | RES / CK / IK computation |
| `f5` / `f5_star` | `compute_anonymity_key` / `compute_resync_anonymity_key` | AK / AK\* computation |

Old names remain as `#[deprecated]` aliases with compiler guidance.

## Tests

Unit tests: TOPc derivation, f1-f5 structural tests, authenticate flow,
snapshot round-trip, conformance against 3GPP TS 35.233 test data.

## Specs

- [Architecture](../../docs/architecture.md#simrs-tuak)
- [Standards: Authentication](../../docs/standards/02-authentication.md)

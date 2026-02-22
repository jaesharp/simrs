# simrs-tuak

TUAK authentication algorithm -- the 3GPP alternative to Milenage for USIM authentication,
built on Keccak-f[1600].

**Layer:** Foundation | **`no_std`:** yes | **Status:** Implemented

## Standards

| Spec | Clause | Coverage |
|------|--------|----------|
| 3GPP TS 35.231 V17.0.0 | Clauses 4-6 | TUAK algorithm specification |
| 3GPP TS 35.232 V17.0.0 | -- | Implementers' test data |
| 3GPP TS 35.233 V17.0.0 | -- | Design conformance test data |

## Dependencies

- `simrs-keccak` -- Keccak-f[1600] permutation
- `simrs-milenage` -- `AuthAlgorithm` trait, `AuthOutput`, `MilenageError`

## API

- `TuakParams` -- TUAK algorithm parameters (K, TOPc)
- `TopVariant` -- raw TOP or pre-computed TOPc
- `AuthAlgorithm` trait implementation for integration with `simrs-usim`

## Tests

Unit tests: TOPc derivation, f1-f5 structural tests, authenticate flow,
snapshot round-trip, conformance against 3GPP TS 35.233 test data.

## Specs

- [Architecture](../../docs/architecture.md#simrs-tuak)
- [Standards: Authentication](../../docs/standards/02-authentication.md)

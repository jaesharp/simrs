# simrs-comp128

`COMP128v1` (A3/A8) GSM authentication algorithm.

**Layer:** Foundation | **`no_std`:** yes | **Status:** Implemented

## Standards

| Spec | Clause | Coverage |
|------|--------|----------|
| GSM 11.11 v4.21.1 | 11 | A3/A8 interface |
| 3GPP TS 51.011 V4.15.0 | 11 | RUN GSM ALGORITHM |

## Dependencies

None (leaf crate).

## Dependents

| Crate | Uses |
|-------|------|
| [simrs-gsm](../simrs-gsm/) | RUN GSM ALGORITHM handler |

## API

- `comp128(&Secret<[u8; 16]>, &[u8; 16]) -> GsmAuthResult` -- COMP128v1: Ki + RAND -> SRES + Kc
- `comp128v2(&Secret<[u8; 16]>, &[u8; 16]) -> GsmAuthResult` -- COMP128v2
- `comp128v3(&Secret<[u8; 16]>, &[u8; 16]) -> GsmAuthResult` -- COMP128v3
- `comp128_versioned(Comp128Version, &Secret<[u8; 16]>, &[u8; 16]) -> GsmAuthResult` -- version-dispatched
- `Comp128Version` -- `V1`, `V2`, `V3` enum
- `SignedResponse` -- 4-byte SRES wrapper
- `GsmAuthResult { sres: SignedResponse, kc: [u8; 8] }`

## Specs

- [BDD: specs/comp128.feature](../../specs/comp128.feature) -- 12 scenarios
- [Architecture](../../docs/architecture/#simrs-comp128)
- [Standards: Authentication](../../docs/standards/02-authentication.md)

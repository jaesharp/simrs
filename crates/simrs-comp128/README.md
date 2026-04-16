# simrs-comp128

`COMP128v1` (A3/A8) GSM authentication algorithm.

**Layer:** Foundation | **`no_std`:** yes | **Status:** Docs + BDD (impl pending)

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

- `comp128(&Secret<[u8; 16]>, &[u8; 16]) -> Comp128Result` -- Ki + RAND -> SRES + Kc
- `Comp128Result { sres: [u8; 4], kc: [u8; 8] }`

## Specs

- [BDD: specs/comp128.feature](../../specs/comp128.feature) -- 12 scenarios
- [Architecture](../../docs/architecture/#simrs-comp128)
- [Standards: Authentication](../../docs/standards/02-authentication.md)

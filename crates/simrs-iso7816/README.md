# simrs-iso7816

ISO/IEC 7816 APDU types, CLA parsing, status words, instruction constants.

**Layer:** Foundation | **`no_std`:** yes | **Status:** Implemented

## Standards

| Spec | Clause | Coverage |
|------|--------|----------|
| ISO/IEC 7816-4:2020 | 5 | APDU structure, status words |
| ETSI TS 102 221 V18.0.0 | 10.1.1 | CLA byte, command set |
| GSM 11.11 v4.21.1 | 9 | GSM CLA=A0 |

## Dependencies

None (leaf crate).

## Dependents

| Crate | Uses |
|-------|------|
| [simrs-fs](../simrs-fs/) | File selection, FCP construction |
| [simrs-pin](../simrs-pin/) | VERIFY/UNBLOCK status words |
| [simrs-proactive](../simrs-proactive/) | FETCH/ENVELOPE INS codes |
| [simrs-gsm](../simrs-gsm/) | GSM APDU dispatch |
| [simrs-usim](../simrs-usim/) | 3GPP APDU dispatch |
| [simrs-sim](../simrs-sim/) | Top-level event routing |
| [simrs-transport](../simrs-transport/) | Transport trait types |
| [simrs-peripheral](../simrs-peripheral/) | Peripheral trait types |
| [simrs-hle](../simrs-hle/) | C-ABI APDU exchange |
| [simrs-fuzz](../simrs-fuzz/) | APDU-aware mutation |

## API

- `Command::parse(&[u8]) -> Result<Command, ApduError>` -- zero-copy APDU parser
- `StatusWord` enum -- 16 variants with `const fn` encode/decode
- `ClassByte` enum -- interindustry vs proprietary routing
- `ins::*` -- 19 instruction code constants

## Specs

- [BDD: specs/iso7816.feature](../../specs/iso7816.feature)
- [Architecture](../../docs/architecture.md#simrs-iso7816)
- [Standards map](../../docs/standards/01-catalog.md)

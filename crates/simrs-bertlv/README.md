# simrs-bertlv

BER-TLV encoding and decoding with dry-run mode.

**Layer:** Foundation | **`no_std`:** yes | **Status:** Implemented

## Standards

| Spec | Clause | Coverage |
|------|--------|----------|
| ETSI TS 101 220 V19.0.0 | all | Tag assignments |
| ISO/IEC 8825-1 | BER | Basic Encoding Rules |
| ETSI TS 102 221 V18.3.0 | 11.1 | FCP TLV structures |

## Dependencies

None (leaf crate).

## Dependents

| Crate | Uses |
|-------|------|
| [simrs-fs](../simrs-fs/) | FCP construction |
| [simrs-proactive](../simrs-proactive/) | Proactive command encoding |
| [simrs-usim](../simrs-usim/) | FCP BER-TLV, AUTHENTICATE response |

## API

- `Tag { class, constructed, number }` -- tag representation
- `Encoder` -- write TLV into caller buffer; dry-run mode counts bytes
- `Decoder` -- iterate TLV objects from byte slice
- `BerError` -- buffer full, invalid tag/length, truncated

## Specs

- [Architecture](../../docs/architecture/#simrs-bertlv)
- [Standards map](../../docs/standards/01-catalog.md)

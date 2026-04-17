# simrs-swicc

Boot a simrs SIM card and expose it as a swICC PC/SC virtual reader over TCP.

## Usage

```sh
# Start the virtual card (default port 37324)
cargo run -p simrs-swicc

# With APDU logging
cargo run -p simrs-swicc -- -v

# Custom port
cargo run -p simrs-swicc -- --port 9000
```

Then point a swICC PC/SC server at `127.0.0.1:37324` (or your chosen port).
Any PC/SC application (e.g. `opensc-tool`, `pcsc_scan`) connected through
the swICC server will see the simrs virtual SIM card.

## Default credentials

The card boots with test credentials:

| Parameter | Value |
|-----------|-------|
| GSM Ki    | `11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11` |
| USIM K    | `22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22` |
| USIM OPc  | `33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33` |
| ATR       | `3B 9F 96 80` |

The filesystem is the `REFERENCE_MF` profile from `simrs-usim`, which
includes EF.ICCID, EF.DIR, ADF.USIM, and standard GSM/USIM EFs.

## Protocol

Uses the swICC wire protocol as implemented in `simrs-transport-tcp`.
The card side listens for a TCP connection and speaks the packed binary
message format (see `simrs-transport-tcp` crate docs for wire details).

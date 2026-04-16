# simrs-vpcd

Boot a simrs SIM card and expose it as a vpcd (Virtual PCD) virtual smart card over TCP.

## Usage

```sh
# Start the virtual card (default vpcd port 35963)
cargo run -p simrs-vpcd

# With APDU logging
cargo run -p simrs-vpcd -- -v

# Custom port
cargo run -p simrs-vpcd -- --port 9000
```

Then configure your vpcd reader (e.g. in `/etc/reader.conf.d/vpcd`) to
connect to `127.0.0.1:35963` (or your chosen port). Any PC/SC application
(e.g. `opensc-tool`, `pcsc_scan`) connected through the virtual reader will
see the simrs virtual SIM card.

## vpcd wire protocol

Every message is a 2-byte big-endian length prefix followed by a payload.

**Control commands (length == 1):**

| Bytes         | Meaning   |
|---------------|-----------|
| `00 01 00`    | Power Off |
| `00 01 01`    | Power On  |
| `00 01 02`    | Reset     |
| `00 01 04`    | Get ATR   |

When length > 1, the payload is a C-APDU. The card responds with
`data || SW1 || SW2` using the same framing.

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

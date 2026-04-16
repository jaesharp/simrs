# simrs-transport-tcp

TCP transport for swICC PC/SC server. Requires `std`.

**Layer:** Boundary | **`no_std`:** no | **Status:** Implemented

## Wire Protocol

Packed binary message format with little-endian multi-byte integers (matching the C swICC server's native x86 byte order):

```text
Offset  Size  Field
------  ----  -----
  0      4    hdr.size     -- payload byte count (LE u32)
  4      4    cont_state   -- contact state bitmask (LE u32)
  8      4    buf_len_exp  -- expected buffer length (LE u32)
 12      1    ctrl         -- control / status byte
 13    0-258  buf          -- APDU data (max 258 bytes)
```

Total maximum message size: 271 bytes.

## Features

- `SwIccClient` -- card-side transport, implements `CardTransport` (recv/send/send_atr)
- `SwIccTerminal` -- terminal-side transport, implements `Transport` (exchange, reset_cold, reset_warm)
- `SwIccMessage` -- encode/decode for the swICC wire protocol
- Automatic keepalive handling in `SwIccClient::recv()`
- Control byte parsing for reset, keepalive, success/failure signals

## Dependencies

| Crate | Purpose |
|-------|---------|
| [simrs-transport](../simrs-transport/) | `CardTransport` and `Transport` traits |

## Specs

- [Architecture](../../docs/architecture/#simrs-transport-tcp)

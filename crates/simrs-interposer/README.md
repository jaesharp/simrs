# simrs-interposer

APDU interposer proxy for shadow SIM comparison with PCAP capture.

**Layer:** Application | **`no_std`:** no | **Status:** Implemented

```mermaid
graph TD
    TCP["simrs-transport-tcp"] --> INT["simrs-interposer"]
    TR["simrs-transport"] --> INT
    PCAP["simrs-pcap"] --> INT
    SIM["simrs-sim"] --> INT
    MIL["simrs-milenage"] --> INT
    FS["simrs-fs"] --> INT
    GSM["simrs-gsm"] --> INT
    USIM["simrs-usim"] --> INT

    style TCP fill:#C35400,stroke:#333,color:#fff
    style TR fill:#C35400,stroke:#333,color:#fff
    style PCAP fill:#0072B2,stroke:#333,color:#fff
    style SIM fill:#E69F00,stroke:#333,color:#000
    style MIL fill:#008060,stroke:#333,color:#fff
    style FS fill:#008060,stroke:#333,color:#fff
    style GSM fill:#E69F00,stroke:#333,color:#000
    style USIM fill:#E69F00,stroke:#333,color:#000
    style INT fill:#D55E00,stroke:#333,color:#fff
```

## Operating Modes

| Mode | Description |
|------|-------------|
| **Log** | Passthrough APDUs to real SIM, write PCAP |
| **Shadow** | Forward to both real and simulated SIM, compare responses |
| **Replace** | Use simrs SIM responses instead of real SIM |

## Features

- Connects to swICC PC/SC servers via TCP (modem side + optional card side)
- Shadow SIM with configurable GSM Ki and UMTS K/OPc credentials
- PCAP capture with GsmTap or User0 link-layer types
- Response divergence tracking (SW mismatch, data mismatch, shadow ignored)
- Mismatch flagging in PCAP output for post-hoc analysis

## CLI Usage

```
simrs-interposer [OPTIONS]

Options:
  --mode <log|shadow|replace>   Operating mode (default: log)
  --modem <addr:port>           Modem-side swICC address (default: 127.0.0.1:37324)
  --card <addr:port>            Card-side swICC address
  --pcap <path>                 PCAP output file path
  --link-type <gsmtap|user0>    PCAP link-layer type (default: user0)
  --ki <hex>                    GSM Ki (32 hex chars)
  --k <hex>                     UMTS K (32 hex chars)
  --opc <hex>                   UMTS OPc (32 hex chars)
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| [simrs-transport-tcp](../simrs-transport-tcp/) | SwIccClient / SwIccTerminal TCP connections |
| [simrs-transport](../simrs-transport/) | CardTransport / Transport traits |
| [simrs-pcap](../simrs-pcap/) | PCAP file encoding |
| [simrs-sim](../simrs-sim/) | Top-level SIM state machine (shadow SIM) |
| [simrs-milenage](../simrs-milenage/) | UMTS authentication for shadow SIM |
| [simrs-fs](../simrs-fs/) | Filesystem definitions for shadow SIM |
| [simrs-gsm](../simrs-gsm/) | GSM application layer for shadow SIM |
| [simrs-usim](../simrs-usim/) | USIM application layer for shadow SIM |

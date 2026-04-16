# simrs

SIM/USIM Emulation and Specification in Pure Embeddable Rust.

## Design

- **`no_std` throughout** -- no allocator; all buffers are stack or `'static`
- **Zero external runtime deps** -- crypto, BER-TLV, filesystem all self-contained
- **State machine driven** -- `Sim::process(SimEvent) -> SimResponse`; pure function, no callbacks
- **`const` everything** -- S-boxes, filesystem trees, protocol constants
- **Spec-linked** -- every public item cites its standard clause

## Quick Start

```bash
# check entire workspace
cargo check --workspace

# run all tests
cargo test --workspace

# clippy (pedantic, no warnings)
cargo clippy --workspace
```

### swICC PC/SC bridge (pcscd / pcsc-lite)

simrs speaks the [swICC](https://github.com/nickg/swicc) wire protocol over TCP, making it accessible to any PC/SC client via the swICC virtual reader driver.

```bash
# 1. Start simrs listening on the default swICC port (127.0.0.1:37324)
cargo run -p simrs-transport-tcp

# 2. With swICC's pcscd driver installed, standard PC/SC tools work:
#    - opensc-tool -a           (list ATR)
#    - pkcs15-tool -D           (dump PKCS#15 structure)
#    - pcsc_scan                (monitor card events)
#    - any PKCS#11 / PC/SC application
```

### APDU interposer (shadow SIM proxy)

The interposer sits between a modem and a real or simulated SIM, with PCAP capture for Wireshark analysis.

```bash
# Shadow mode: forward APDUs to both a real SIM and simrs, compare responses
cargo run -p simrs-interposer -- \
    --mode shadow \
    --modem 127.0.0.1:37324 \
    --card 127.0.0.1:37325 \
    --pcap trace.pcap

# Open the capture in Wireshark (GSMTAP SIM dissector, LINKTYPE 2342)
wireshark trace.pcap
```

### Authentication vector generation

Generate Milenage auth vectors for LTE/UMTS test environments (e.g., Open5GS, srsRAN, Python mini-MME).

```bash
cargo run -p simrs-auth-cli -- gen-vector \
    --ki 00112233445566778899AABBCCDDEEFF \
    --opc 00000000000000000000000000000000 \
    --rand AAAABBBBCCCCDDDDEEEEFFFFAAAABBBB
```

### QEMU HLE integration

The HLE library (`cdylib`) plugs into QEMU for high-speed baseband fuzzing with snapshot save/restore.

```bash
# Build the C-ABI shared library
cargo build -p simrs-hle --release
# => target/release/libsimrs_hle.so
```

## Documentation

| Doc | Contents |
|-----|----------|
| **[crates/README.md](crates/README.md)** | Crate map, dependency graph, standards coverage |
| **[docs/architecture.md](docs/architecture.md)** | API surface, data flow diagrams |
| **[docs/DIAGRAM_STYLE_GUIDE.md](docs/DIAGRAM_STYLE_GUIDE.md)** | Okabe-Ito colour palette, WCAG AA compliance |
| **[docs/standards/](docs/standards/README.md)** | 4G-LTE / 5G-NR standards map, auth flows, key hierarchies, EF catalog |

## License

MIT OR Apache-2.0

# simrs

SIM/USIM Emulation and Specification in Pure Embeddable Rust.

## Features

- **Constant-time crypto with compile-time enforcement** -- `Secret<T>` blocks `PartialEq`, `Hash`, `Deref` at the type level; all key material flows through `CtEq`/`CtSelect`/`CtSwap`. DudeCT timing validation (Bayesian, not Welch's t-test) verifies the runtime guarantees.
- **Self-contained cryptography** -- AES-128, SHA-256, Keccak-f[1600], DES/3DES, COMP128v1-v3, Milenage, TUAK, RSA (Montgomery), X25519, ECIES Profiles A/B -- all implemented from scratch with zero external dependencies.
- **Four generations of mobile auth** -- GSM (COMP128), UMTS (Milenage), LTE (Milenage + 3GPP KDF), 5G (TUAK + SUCI ECIES) in a single tool.
- **Full JavaCard stack** -- JCVM bytecode interpreter (~185 opcodes), compiler with IR + optimizer + source maps, proc-macro assembler, and decompiler. Bytecode applets run on the GlobalPlatform card alongside native Rust applets.
- **GlobalPlatform card OS** -- OPEN runtime, ISD, applet registry, SCP01/SCP02 secure channels, card lifecycle management, GET STATUS / SET STATUS / INSTALL / DELETE.
- **Real eUICC profile ingestion** -- TCA eUICC Profile Package v3.3.1 DER parser converts carrier-distributed profiles into a live USIM filesystem.
- **Shadow SIM interposer** -- transparent proxy between a modem and SIM with PCAP/GSMTAP capture, diff mode for A/B comparison, and response injection.
- **Differential testing against Oracle** -- automated conformance testing against the Oracle Java Card Simulator (jcsl) across 100+ APDU scenarios.
- **`no_std` / zero-alloc** -- 74% of crates are `no_std` with no heap allocation, including all cryptographic implementations. Embeddable on bare-metal targets without libc or a memory manager.

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

### C-ABI shared library

The HLE crate builds as a `cdylib` for embedding into any host application or runtime.

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

# simrs

Electronic Embedded Card Simulation, Emulation, and Specification in Pure Embeddable Rust (`no_std`).

- **SIM / USIM / ISIM / HPSIM** (GSM 11.11, TS 102 221, TS 31.102, TS 31.103, TS 31.104)
  - SIM, USIM, ISIM, HPSIM applications with filesystem, PIN/PUK, proactive UICC
  - Runs standalone or as a GlobalPlatform applet alongside JavaCard bytecode applets
- **Authentication** (TS 35.206, TS 35.231, TS 33.501)
  - COMP128v1-v3, Milenage, TUAK, EAP-AKA', 5G SUCI (ECIES A/B)
- **Cryptography** (FIPS 197, FIPS 180-4, RFC 7748)
  - AES-128, SHA-256, DES/3DES, Keccak, RSA, X25519, HMAC, KDF
- **GlobalPlatform** (GP 2.1.1, GP 2.3.1 Amd D)
  - OPEN, ISD, applet registry, SCP01/SCP02/SCP03, card lifecycle
- **JavaCard** (JC VM 2.1.1, JC RE 2.1.1)
  - JCVM bytecode interpreter, compiler, assembler, decompiler
- **eUICC profiles** (TCA v3.3.1, SGP.22)
  - TCA Profile Package DER parser -- ingest carrier-distributed profiles into a live filesystem
- **OTA** (TS 102 225, TS 102 226)
  - Secured packet structure, remote APDU
- **Tooling**
  - Interposer/shadow SIM, differential testing, auth vector CLI, PCAP/GSMTAP

## Design

- **`no_std` core** -- all crypto, protocol, filesystem, and card logic compiles without `std` or an allocator. Only boundary crates (TCP, OS ioctl, CLI binaries) require `std`.
- **Zero external runtime deps** -- every cryptographic algorithm is implemented from scratch, validated against NIST/ETSI/3GPP published test vectors, property-tested with proptest, and checked for undefined behavior under Miri
- **State machine driven** -- `Sim::process(SimEvent) -> SimResponse`; pure function, no callbacks
- **Information flow security** -- `Secret<T>` enforces classification boundaries at compile time (blocks `PartialEq`, `Hash`, `Display`, `Deref`); `Redact` prevents secrets in log output; uniform error responses close side-channel oracles; DudeCT (Bayesian) validates constant-time properties at runtime
- **Spec-linked** -- every public item cites its standard clause

## Toolchains

### jacc -- JavaCard-Approximately-Compatible Compiler

Full compilation pipeline from Java Card source to on-card bytecode:

```
.java / .jva source  -->  jacc  -->  .cap (JCVM bytecode package)
.class / .jvc file   -->  jacc  -->  .cap
.cap                 -->  jacc  -->  assembly text (--disasm)
.cap                 -->  jacc  -->  JVA source (--decompile)
```

Includes IR with constant folding, dead code elimination, strength reduction, and a branch-aware peephole optimizer with side-effect safety guards. Source maps (`.jvamap`) link bytecode offsets back to source lines.

### jcasm -- proc-macro assembler

Inline JCVM bytecode assembly in Rust tests and build scripts:

```rust
let (aid, methods) = jcasm! {
    applet A0_00_00_00_62 {
        fn process() {
            sconst_3; sconst_2; sadd; sreturn;
        }
    }
};
```

### jcasm-jva -- proc-macro applet DSL

Higher-level Java Card applet definition with fields, methods, control flow, and arithmetic -- compiles through `simrs-jccompile` to JCVM bytecode at macro expansion time.

## Quick start

```bash
cargo check --workspace          # build
cargo test --workspace           # test
cargo clippy --workspace         # lint (pedantic, zero warnings)
```

### PC/SC (pcscd / pcsc-lite)

```bash
# Start simrs on the swICC port (127.0.0.1:37324)
cargo run -p simrs-transport-tcp

# Standard PC/SC tools work: opensc-tool, pkcs15-tool, pcsc_scan, etc.
```

### Shadow SIM interposer

```bash
cargo run -p simrs-interposer -- \
    --mode shadow \
    --modem 127.0.0.1:37324 \
    --card 127.0.0.1:37325 \
    --pcap trace.pcap
```

### Auth vector generation

```bash
cargo run -p simrs-auth-cli -- gen-vector \
    --ki 00112233445566778899AABBCCDDEEFF \
    --opc 00000000000000000000000000000000 \
    --rand AAAABBBBCCCCDDDDEEEEFFFFAAAABBBB
```

### C-ABI shared library

```bash
cargo build -p simrs-hle --release
# => target/release/libsimrs_hle.so
```

## License

GPL-2.0-or-later

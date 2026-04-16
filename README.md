# simrs

Electronic Embedded Card Simulation, Emulation, and Specification in Pure Embeddable Rust (`no_std`).
If it's not supported - it's a bug.

- **SIM / USIM / ISIM / HPSIM** (GSM 11.11, TS 102 221, TS 31.102, TS 31.103, TS 31.104)
  - SIM, USIM, ISIM, HPSIM applications with filesystem, PIN/PUK, proactive UICC
    - eUICC profiles (TCA v3.3.1, SGP.22)
      - TCA Profile Package DER parser -- ingest carrier-distributed profiles into a live filesystem
    - OTA (TS 102 225, TS 102 226)
      - Secured packet structure, remote APDU
  - Runs standalone or as a GlobalPlatform applet alongside JavaCard Bytecode or Rust Native Applets
- **GlobalPlatform card OS** (GP 2.1.1, GP 2.3.1 Amd D)
  - OPEN, ISD, applet registry, SCP01/SCP02/SCP03, card lifecycle
- **Complete JavaCard toolchain** (JC VM 2.1.1, JC RE 2.1.1)
  - JCVM-compatible bytecode interpreter
  - `jacc` compiler (IR, optimizer, source maps)
  - Rust-inline Assembler/Compiler Support with macros
  - Decompiler
- Tooling
  - Interposer/shadow SIM
    - PCAP/GSMTAP Capture
  - Differential Testing Framework
  - and More

## Research Flexibility Built to be Deployed in The Real World

- **`no_std` core** -- all crypto, protocol, filesystem, and card logic compiles without `std` or an allocator. Only boundary crates (TCP, OS ioctl, CLI binaries) require `std`. See [crate index](crates/README.md).
- **Zero external runtime deps** -- every cryptographic algorithm is implemented from scratch, validated against NIST/ETSI/3GPP published test vectors, property-tested with [proptest](https://crates.io/crates/proptest), checked for undefined behavior under [Miri](https://github.com/rust-lang/miri), verified for constant-time execution with [tacet](crates/simrs-consttime-validation/) (adaptive Bayesian timing analysis), and [adversarially tested](tools/simrs-security-tests/) for protocol-level vulnerabilities. See [simrs-ref](crates/simrs-ref/) for reference test vectors.
- **State machine driven** -- [`Sim::process(SimEvent) -> SimResponse`](crates/simrs-sim/); pure function, no callbacks
- **Information flow security** -- [`Secret<T>`](crates/simrs-secret/) enforces classification boundaries at compile time (blocks `PartialEq`, `Hash`, `Display`, `Deref`); [`Redact`](crates/simrs-redact/) prevents secrets in log output; uniform error responses close side-channel oracles
- **Differential testing against Oracle** -- GP and SCP protocol behavior [validated against Oracle's reference JCVM](tools/simrs-differential-tests/) across 100+ APDU scenarios
- **Spec-linked** -- every public item cites its standard clause. See [standards map](docs/standards/)

## Quick start

```bash
cargo check --workspace          # build
cargo test --workspace           # test
cargo clippy --workspace         # lint (pedantic, zero warnings)
```

### Compile and run a JavaCard applet

```bash
# Compile a Java Card source file to a CAP package
cargo run -p simrs-jacc -- applet.java -o applet.cap

# Decompile it back to verify
cargo run -p simrs-jacc -- --decompile applet.cap

# Run the full test suite (includes JCVM execution of compiled applets)
cargo test -p simrs-jcvm
cargo test -p simrs-jacc
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

### CLI tools

```bash
# Generate a Milenage auth vector (for Open5GS, srsRAN, etc.)
cargo run -p simrs-auth-cli -- gen-vector \
    --ki 465B5CE8B199B49FAA5F0A2EE238A6BC \
    --opc CD63CB71954A9F4E48A5994E37A02BAF \
    --sqn FF9BB4D0B607 --amf B9B9

# Manage the Oracle jcsl reference simulator
cargo run -p simrs-jcsl -- status        # show installation
cargo run -p simrs-jcsl -- guide         # acquisition instructions

# Run differential tests against Oracle jcsl
cargo test -p simrs-differential-tests

# Build the C-ABI shared library for embedding
cargo build -p simrs-hle --release
# => target/release/libsimrs_hle.so
```

## License

GPL-2.0-or-later
# simrs

Electronic Embedded Card Simulation, Emulation, and Specification in Pure Embeddable Rust (`no_std`).

_If it's not supported - it's a bug._

- **SIM / USIM / ISIM / HPSIM** (GSM 11.11, TS 102 221, TS 31.102, TS 31.103, TS 31.104)
  - SIM, USIM, ISIM, HPSIM applications with filesystem, PIN/PUK, proactive UICC
    - eUICC profiles (TCA v3.3.1, SGP.22)
      - TCA Profile Package DER parser -- ingest carrier-distributed profiles into a live filesystem
    - OTA (TS 102 225, TS 102 226)
      - Secured packet structure, remote APDU support
  - Runs standalone or as a GlobalPlatform-Compatible applet alongside JavaCard Bytecode or Rust Native Applets
- **GlobalPlatform-Compatible card OS** (GP 2.1.1, GP 2.3.1 Amd D)
  - OPEN, ISD, applet registry, SCP01/SCP02/SCP03, card lifecycle
- **Complete JavaCard-Compatible toolchain** (JC VM 2.1.1, JC RE 2.1.1)
  - Interpreter (Full Instrumentation and Introspection)
  - Assembler (HLA support)
  - Compiler (Fully Optimising HLL IR with Source Maps)
  - Rust-inline Assembler/Compiler Support via proc-macros
- Tooling
  - Interposer/shadow machine-in-the-middle virtual card
    - PCAP/GSMTAP Capture/Replay
  - Differential Testing Framework
  - ...

## Research Flexibility Built to be Deployed in Hard Reality

- **`no_std` core** -- all crypto, protocol, filesystem, and card logic compiles without `std` or an allocator. Only boundary crates (TCP, OS ioctl, CLI binaries) require `std`. See [crate index](crates/README.md).
- **Zero external runtime deps** -- every cryptographic algorithm is self-contained and validated against 
  NIST/ETSI/3GPP published test vectors, property-tested with [proptest](https://crates.io/crates/proptest), checked for undefined behavior under [Miri](https://github.com/rust-lang/miri), verified for constant-time execution with [tacet](crates/simrs-consttime-validation/) (adaptive Bayesian timing analysis), and [adversarially tested](tools/simrs-security-tests/) for protocol-level vulnerabilities. See [simrs-ref](crates/simrs-ref/) for reference test vectors.
- **State machine driven** -- [`Sim::process(SimEvent) -> SimResponse`](crates/simrs-sim/); pure function, no callbacks
- **Information flow security** -- [`Secret<T>`](crates/simrs-secret/) enforces classification boundaries at compile time (blocks `PartialEq`, `Hash`, `Display`, `Deref`); [`Redact`](crates/simrs-redact/) prevents secrets in log output; uniform error responses close side-channel oracles
- **Differential behavioural validation against Oracle's Reference JCVM** -- GP and SCP protocol behavior [validated against Oracle's reference JCVM](tools/simrs-differential-tests/) across 100+ APDU scenarios
- **Spec-linked** -- every public item cites its standard clause. See [standards map](docs/standards/)

## Quick start

```bash
cargo check --workspace          # build
cargo test --workspace           # test
cargo clippy --workspace         # lint (pedantic, zero warnings)
```

### Virtual smart card reader

Boot a SIM card and expose it over TCP for PC/SC tools:

```bash
# vpcd protocol (port 35963) -- works with vsmartcard-vpcd pcscd driver
cargo run -p simrs-vpcd

# swICC protocol (port 37324) -- works with swICC pcscd driver
cargo run -p simrs-swicc

# Both support -v for APDU logging and --port to override
cargo run -p simrs-vpcd -- -v --port 35964
```

Install a pcscd reader driver to bridge PC/SC tools to the virtual card:
- **vpcd**: `apt install vsmartcard-vpcd` (some distros) or [build from source](https://frankmorgner.github.io/vsmartcard/)
- **swICC**: [build from source](https://github.com/nickg/swicc)

Then standard tools connect directly:

```bash
opensc-tool -l                                         # list readers
opensc-tool -a                                         # list ATR
opensc-tool -s "00A40400 07 A0000000871002"            # SELECT USIM AID
pcsc_scan                                              # monitor card events
pkcs15-tool -D                                         # dump PKCS#15 structure
gp -l                                                  # list applets (GlobalPlatformPro)
```

### Compile and run a JavaCard-Compatible applet

```bash
# Compile a Java Card source file to a CAP package
cargo run -p simrs-jacc -- applet.java -o applet.cap

# Decompile it back to verify
cargo run -p simrs-jacc -- --decompile applet.cap

# Run the full test suite (includes JCVM execution of compiled applets)
cargo test -p simrs-jcvm
cargo test -p simrs-jacc
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
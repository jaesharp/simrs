# SimRS

Electronic Embedded Card Simulation, Emulation, and Specification in Pure Embeddable Rust (No Standard Library or Alloc
Required).

_You know - that metallic chip on the punched out card that you shoved into your mobile when you bought it, and on your
ID at the office, and on the banking cards in your wallet. The point is - they're everywhere. This project maps and
specifies those chips well enough that anyone can make one in any way they want. That's the goal, anyway._

## Features

- **SIM / USIM / ISIM / HPSIM** (GSM 11.11, TS 102 221, TS 31.102, TS 31.103, TS 31.104)
  - SIM, USIM, ISIM, HPSIM applications with filesystem, PIN/PUK, proactive UICC
    - eUICC profiles (TCA v3.3.1, SGP.22)
      - TCA Profile Package DER parser -- ingest carrier-distributed profiles into a live filesystem
    - OTA (TS 102 225, TS 102 226)
      - Secured packet structure, remote APDU support
  - Runs standalone or as a GlobalPlatform-Compatible applet alongside JavaCard Bytecode or Rust Native Applets
- **GlobalPlatform-Compatible card OS** (primary target GP 2.3.1; legacy GP 2.1.1)
  - OPEN, ISD, applet registry, SCP01/SCP02/SCP03, card lifecycle
  - Conformance status and phased upgrade plan: [docs/standards/06-globalplatform.md](docs/standards/06-globalplatform.md)
- **JavaCard-Compatible toolchain** (primary target JavaCard 3.2; legacy 2.1.1)
  - Interpreter (Full Instrumentation and Introspection)
  - Assembler (HLA support)
  - Compiler (Fully Optimising HLL IR with Source Maps)
  - Rust-inline Assembler/Compiler Support via proc-macros
- Tooling
  - Interposer/shadow machine-in-the-middle virtual card
    - PCAP/GSMTAP Capture/Replay
  - Differential Testing Framework
    - APDU-matrixed across Oracle `jcsl` and martinpaljak `JCardEngine`
      reference simulators (runtime-switchable via `SIMRS_DIFF_BACKEND`)
    - 60+ per-cell scenarios: power-on / SELECT / GET DATA / lifecycle /
      MANAGE CHANNEL / SCP02+SCP03 handshakes / authenticated operations
    - Per-backend markdown + JUnit reports + cross-backend combined
      report; known-divergence catalog with typed SW / backend-version
      citations
  - Conformance Engine (design phase — see [design suite](docs/architecture/conformance/))
    - Typed normative-standards pipeline: Source → Transcribe → Slice →
      Transform → Clause → Rule → Outcome → Book
    - eADR-style attribute macros (`#[adr]`, `#[cite]`, `#[governs]`)
      with typed `DocumentRef` citations; build-time confluence +
      compatibility validators; product-variant enumeration

## Language Bindings (LGPL-2.0-or-later)

SimRS exposes its high-level engine (HLE) through a single C ABI
(`libsimrs_hle_capi.so` / `.a` / `simrs.h`). Idiomatic wrappers sit on top
of that ABI for each supported host language. **All bindings in
[`exports/`](exports/) are released under LGPL-2.0-or-later**, so proprietary
applications can link against them (subject to the LGPL's relinking
requirement). Other SimRS modules otherwise not specified remain GPL-2.0-or-later.

| Language    | Directory                                              | Tested Versions                               | Tested Platforms                                                 | Mechanism                                      |
|-------------|--------------------------------------------------------|-----------------------------------------------|------------------------------------------------------------------|------------------------------------------------|
| C / C++     | [exports/simrs-hle-capi/](exports/simrs-hle-capi/)     | any C99-capable compiler                      | Linux x86_64, Linux aarch64, macOS arm64, Windows x86_64         | cdylib + generated `simrs.h`                   |
| Rust        | [exports/simrs-hle-rust/](exports/simrs-hle-rust/)     | stable, beta, nightly                         | Linux x86_64, Linux aarch64, macOS arm64, Windows x86_64         | Safe, Limited LGPL re-export of `simrs-hle`    |
| Python      | [exports/simrs-hle-python/](exports/simrs-hle-python/) | 3.10, 3.11, 3.12, 3.13                        | Linux x86_64, Linux aarch64, macOS arm64, Windows x86_64         | ctypes over cdylib, thread-safe by default     |
| Java/Kotlin | [exports/simrs-hle-java/](exports/simrs-hle-java/)     | JDK 11, 17, 21 (Temurin); Kotlin 2.3          | Linux x86_64, Linux aarch64, macOS arm64                         | JNI shim + Kotlin extensions, tested via jbang |
| Go          | [exports/simrs-hle-go/](exports/simrs-hle-go/)         | 1.23, 1.24                                    | Linux x86_64, Linux aarch64, macOS arm64                         | cgo over cdylib                                |
| Swift       | [exports/simrs-hle-swift/](exports/simrs-hle-swift/)   | 5.10.1 (Xcode 15), 6.1.3 (Xcode 16)           | Linux x86_64, Linux aarch64, macOS arm64 (see note)              | Swift Package over cdylib via C module map     |
| C# / .NET   | [exports/simrs-hle-dotnet/](exports/simrs-hle-dotnet/) | 8.0, 9.0                                      | Linux x86_64, Linux aarch64, macOS arm64, Windows x86_64         | P/Invoke over cdylib, thread-safe by default   |

Swift note: 5.10.1 is tested on `macos-14` (bundled Xcode 15), 6.1.3 on
`macos-15` (bundled Xcode 16). Swift 5.10 is incompatible with Xcode 16's
SDK module system; 5.10 coverage on macOS requires a macOS 14 toolchain.

Java/Go/Swift Windows coverage is a planned follow-up. Each needs a
Windows-specific C toolchain path (MSVC or MinGW for the JNI shim and
cgo; Swift-on-Windows is still stabilising upstream).

All bindings link dynamically against the capi cdylib at runtime
(`libsimrs_hle_capi.so` on Linux, `libsimrs_hle_capi.dylib` on macOS,
`simrs_hle_capi.dll` on Windows): `python`/`dotnet` via ctypes /
P/Invoke, `java`/`go`/`swift` via JNI / cgo / Swift's C module auto-
linking.

See [exports/README.md](exports/README.md) for build instructions, the
shared 8-function API surface, and thread-safety notes.

```python
# Example: Python
from simrs import Sim, generate_credentials

creds = generate_credentials(seed=42)
with Sim.with_credentials(creds) as sim:
    atr = sim.reset()
    data, sw1, sw2 = sim.apdu_hex("00 A4 04 00 07 A0000000871002")
```

## Research Flexibility Built to be Deployed in Hard Reality

- **no standard/alloc core** -- all crypto, protocol, filesystem, and card logic can go absolutely anywhere -
  including microcontrollers. Only boundary crates (TCP, OS ioctl, CLI binaries) require `std` or an allocator. See
  [crate index](crates/README.md) for more details.
- **Zero external runtime deps** -- every cryptographic algorithm is self-contained and validated against
  NIST/ETSI/3GPP published test vectors, property-tested with [proptest](https://crates.io/crates/proptest), checked for
  undefined behavior under [Miri](https://github.com/rust-lang/miri), verified for constant-time execution
  with [tacet](crates/simrs-consttime-validation/) (adaptive Bayesian timing analysis -- block ciphers, hashes,
  bigint arithmetic, RSA, ECIES, KDF, AKA, COMP128, secure-channel SCP01/02/03, PUT KEY unwrap, PIN/OTA flows;
  see the [Known limitations](#known-limitations) section for one CT path that is **not** yet validated),
  and [adversarially tested](tests/simrs-adversarial-countervalidation/) for protocol-level vulnerabilities.
  See [simrs-ref](crates/simrs-ref/) for reference test vectors.
- **State machine driven** -- [`Sim::process(SimEvent) -> SimResponse`](crates/simrs-sim/); single entry point, no
  callbacks
- **Information flow security** -- [`Secret<T>`](crates/simrs-secret/) enforces classification boundaries at compile
  time (blocks `PartialEq`, `Hash`, `Display`, `Deref`); [`Redact`](crates/simrs-redact/) prevents secrets in log
  output; uniform error responses close side-channel oracles
- **Differential behavioural validation across multiple reference JCVMs** -- GP and SCP protocol
  behaviour [validated against Oracle's `jcsl` and martinpaljak's
  `JCardEngine`](tests/simrs-differential-crossvalidation/), runtime-
  switchable, with a shared known-divergence catalog
- **Spec-linked** -- every public item cites its standard clause. See [standards map](docs/standards/)

## Maturity

SimRS is pre-1.0 and under active development. It has not undergone independent
security audit. While significant effort goes into correctness -- constant-time
enforcement, information flow controls, Miri validation, adversarial testing,
and differential compliance against reference implementations -- this project
should not be used in production security-critical applications without
independent review.

### Known limitations

**JCVM bytecode-level constant-time properties are not yet validated.** The
host-side cryptographic primitives an applet calls into (`javacard.security`,
`javacardx.crypto`, the underlying ciphers/hashes/RSA/bignum) are all under
tacet Bayesian timing analysis. But if an applet processes secret data via
JavaCard *bytecode* -- for example, a custom PIN comparison, a key-search
loop, or a constant-time branch implemented in Java Card source -- whether
the [`simrs-jcvm`](crates/simrs-jcvm/) bytecode interpreter preserves the
applet's CT discipline depends on:

- Constant-time bytecode dispatch (no jump-table or branch-prediction
  optimisations that vary with secret stack values)
- Constant-time array bounds checks
- Data-independent allocation patterns and frame management
- Spec-faithful operand-stack discipline (no operand-value-dependent
  shortcuts)

These are deeper invariants than primitive-level CT and require both
implementation work and a separate validation regime. See the
[GP/JC upgrade plan](docs/standards/06-globalplatform.md#phased-upgrade-plan)
Phase 4 (JCRE 3.x runtime semantics); the JCVM-level CT validation work
plugs into that phase rather than the host-crypto coverage already in
place.

Until that work lands, **applets that need timing-attack resistance must
not rely on bytecode-level CT in this VM** -- they should perform
sensitive comparisons via host-validated primitives
(e.g. [`javacard.framework.Util.arrayCompare`](https://docs.oracle.com/en/java/javacard/3.2/javacard-platform-3.2-api/api/javacard/framework/Util.html#arrayCompare-byte:A-short-byte:A-short-short-)
once it is wrapped to dispatch into [`simrs-consttime::ct_eq`](crates/simrs-consttime/),
or via direct calls to the validated `javacardx.crypto` primitives).

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

- **vpcd**: `apt install vsmartcard-vpcd` (some distros)
  or [build from source](https://frankmorgner.github.io/vsmartcard/)
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
    --k 465B5CE8B199B49FAA5F0A2EE238A6BC \
    --opc CD63CB71954A9F4E48A5994E37A02BAF \
    --sqn FF9BB4D0B607 --amf B9B9

# Manage the Oracle jcsl reference simulator
cargo run -p simrs-jcsl -- status        # show installation
cargo run -p simrs-jcsl -- guide         # acquisition instructions

# Manage the martinpaljak JCardEngine bridge (second reference)
cargo run -p simrs-jcardengine -- status
cargo run -p simrs-jcardengine -- guide

# Run differential tests (Oracle jcsl default)
cargo test -p simrs-differential-crossvalidation

# Or against JCardEngine
SIMRS_DIFF_BACKEND=jcardengine \
    cargo test -p simrs-differential-crossvalidation

# Build the C-ABI shared library for embedding
cargo build --manifest-path exports/simrs-hle-capi/Cargo.toml --release
# => exports/simrs-hle-capi/target/release/libsimrs_hle_capi.so
```

## License

GPL-2.0-or-later
# simrs

Pure Rust software SIM/USIM card simulator. `no_std`, zero external dependencies, bare-metal ready.

Port of [swsim](https://github.com/nicktool/SIMurai) (SIMurai) to Rust, designed for Shannon baseband fuzzing via QEMU HLE.

## Quick Start

```bash
# check entire workspace
cargo check --workspace

# run all tests
cargo test --workspace

# clippy (pedantic, no warnings)
cargo clippy --workspace
```

## Workspace

22 crates across 7 layers -- from AES-128 primitives up to a snapshot fuzzer harness.

See **[INDEX.md](INDEX.md)** for the full crate map, dependency graph, and standards coverage.

See **[docs/architecture.md](docs/architecture.md)** for detailed API surface and data flow diagrams.

## Design

- **`no_std` throughout** -- no allocator; all buffers are stack or `'static`
- **Zero external runtime deps** -- crypto, BER-TLV, filesystem all self-contained
- **State machine driven** -- `Sim::process(SimEvent) -> SimResponse`; pure function, no callbacks
- **`const` everything** -- S-boxes, filesystem trees, protocol constants
- **Spec-linked** -- every public item cites its standard clause

## License

MIT OR Apache-2.0

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

28 crates across 5 semantic layers -- from AES-128 primitives up to a snapshot fuzzer harness.

| Doc | Contents |
|-----|----------|
| **[INDEX.md](INDEX.md)** | Crate map, dependency graph, standards coverage |
| **[docs/architecture.md](docs/architecture.md)** | API surface, data flow diagrams |
| **[docs/DIAGRAM_STYLE_GUIDE.md](docs/DIAGRAM_STYLE_GUIDE.md)** | Okabe-Ito colour palette, WCAG AA compliance |
| **[docs/standards/](docs/standards/README.md)** | 4G-LTE / 5G-NR standards map, auth flows, key hierarchies, EF catalog |

## Design

- **`no_std` throughout** -- no allocator; all buffers are stack or `'static`
- **Zero external runtime deps** -- crypto, BER-TLV, filesystem all self-contained
- **State machine driven** -- `Sim::process(SimEvent) -> SimResponse`; pure function, no callbacks
- **`const` everything** -- S-boxes, filesystem trees, protocol constants
- **Spec-linked** -- every public item cites its standard clause

## License

MIT OR Apache-2.0

# simrs-differential-tests

Differential testing harness that compares the simrs `GpCard` implementation against the Oracle jcsl reference simulator.

## Usage

```
cargo test -p simrs-differential-tests
```

If the Oracle jcsl binary is not available, all Oracle-dependent tests skip automatically.

To point at the binary explicitly:

```
SIMRS_JCSL_BINARY=/path/to/jcsl cargo test -p simrs-differential-tests
```

Or install it into the XDG cache (see `simrs-jcsl` tool) and it will be discovered automatically.

## Architecture

Three layers, from high-level to low-level:

- **`DiffSession`** -- builder-pattern front-end for replay-based differential tests. Wraps the interposer's `DiffEngine` with backend selection and automatic resource management (jcsl process lifecycle, key configuration).

- **`DualCard`** -- low-level harness for tests that need asymmetric access to both implementations (e.g., different AIDs per side, reconnecting Oracle after reset). Sends the same APDU to both and collects structured `DualResponse` results.

- **`GpCardTerminal`** -- wraps an in-process `GpCard` as a `Transport`, allowing it to be used interchangeably with `JcslClient` in the comparison engine.

## Modules

- `session` -- `DiffSession` builder and replay engine
- `known_divergences` -- catalog of known Oracle/simrs behavioral differences
- `report` -- divergence report formatting

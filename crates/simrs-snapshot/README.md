# simrs-snapshot

Deterministic SIM state serialization for snapshot-based fuzzing.

**Layer:** Meta | **`no_std`:** yes | **Status:** Stub

```mermaid
graph LR
    SIM["simrs-sim"] --> SNAP["simrs-snapshot<br/><i>Snapshot trait</i>"]
    SNAP --> HLE["simrs-hle"]
    SNAP --> FUZZ["simrs-fuzz"]

    style SIM fill:#E69F00,stroke:#333,color:#000
    style SNAP fill:#AA4499,stroke:#333,color:#fff
    style HLE fill:#AA4499,stroke:#333,color:#fff,stroke-dasharray:5 5
    style FUZZ fill:#AA4499,stroke:#333,color:#fff,stroke-dasharray:5 5
```

## API (planned)

```rust
pub trait Snapshot: Sized {
    const BLOB_SIZE: usize;
    fn save(&self, buf: &mut [u8; Self::BLOB_SIZE]);
    fn restore(buf: &[u8; Self::BLOB_SIZE]) -> Self;
    fn state_hash(&self) -> u64;
}
```

Guarantees: no timestamps, no RNG, no floating point, no hash maps. Identical blob across platforms for the same logical state.

## Specs

- [Architecture](../../docs/architecture.md#simrs-snapshot)
- [Standards: Crate Impact](../../docs/standards/05-crate-impact.md)

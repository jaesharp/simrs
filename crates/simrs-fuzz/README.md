# simrs-fuzz

APDU-aware snapshot fuzzer harness for Shannon baseband.

**Layer:** Meta | **`no_std`:** no (binary) | **Status:** Stub

```mermaid
graph TD
    subgraph fuzz_loop ["Fuzz Loop"]
        direction TB
        RESTORE["1. Restore QEMU + SIM snapshot"]
        MUTATE["2. Mutate APDU sequence"]
        INJECT["3. Inject into guest RAM"]
        EXEC["4. Resume QEMU execution"]
        COLLECT["5. Collect coverage"]
        SAVE["6. Save interesting to corpus"]
        RESTORE --> MUTATE --> INJECT --> EXEC --> COLLECT --> SAVE --> RESTORE
    end

    FUZZ["simrs-fuzz"] --> HLE["simrs-hle"]
    FUZZ --> SNAP["simrs-snapshot"]

    style FUZZ fill:#AA4499,stroke:#333,color:#fff,stroke-dasharray:5 5
    style HLE fill:#AA4499,stroke:#333,color:#fff,stroke-dasharray:5 5
    style SNAP fill:#AA4499,stroke:#333,color:#fff
```

## Features

- Structure-aware APDU mutation (understands CLA/INS/P1/P2/Lc/Le)
- Snapshot-restore-mutate-execute-feedback loop
- Coverage: edge bitmap + SIM state hash dedup
- Feedback signals: INS coverage, auth attempts, file selection patterns

## Dependencies

[simrs-hle](../simrs-hle/), [simrs-snapshot](../simrs-snapshot/), [simrs-iso7816](../simrs-iso7816/)

## Specs

- [Architecture](../../docs/architecture.md#simrs-fuzz)
- [Standards: Crate Impact](../../docs/standards/05-crate-impact.md)

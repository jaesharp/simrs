# simrs-peripheral-shannon

Samsung Shannon baseband SIM controller (MMIO + `VirtIO` control device).

**Layer:** Boundary | **`no_std`:** yes | **Status:** Stub

```mermaid
graph LR
    FW["Shannon firmware<br/>(ARM guest)"] -->|"MMIO write"| QEMU["QEMU trap"]
    QEMU --> SHAN["simrs-peripheral-shannon"]
    SHAN -->|"virtqueue"| VIO["simrs-transport-virtio"]
    VIO --> SIM["simrs-sim"]

    style FW fill:#F0F0F0,stroke:#666,color:#333
    style QEMU fill:#F0F0F0,stroke:#666,color:#333
    style SHAN fill:#C35400,stroke:#333,color:#fff
    style VIO fill:#C35400,stroke:#333,color:#fff
    style SIM fill:#E69F00,stroke:#333,color:#000
```

## Dependencies

[simrs-peripheral](../simrs-peripheral/), [simrs-transport-virtio](../simrs-transport-virtio/), [simrs-iso7816](../simrs-iso7816/)

## Specs

- [Architecture](../../docs/architecture.md#simrs-peripheral-shannon)

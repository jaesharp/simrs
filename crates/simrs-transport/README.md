# simrs-transport

`Transport` trait -- APDU exchange abstraction.

**Layer:** Boundary | **`no_std`:** yes | **Status:** Implemented

```mermaid
graph TD
    TR["simrs-transport<br/><i>trait</i>"]
    TCP["simrs-transport-tcp<br/><i>std::net</i>"]
    SHM["simrs-transport-shmem<br/><i>ring buffer</i>"]
    VIO["simrs-transport-virtio<br/><i>virtqueue</i>"]
    TR --> TCP & SHM & VIO

    style TR fill:#C35400,stroke:#333,color:#fff
    style TCP fill:#C35400,stroke:#333,color:#fff,stroke-dasharray:5 5
    style SHM fill:#C35400,stroke:#333,color:#fff
    style VIO fill:#C35400,stroke:#333,color:#fff
```

## API (planned)

```rust
pub trait Transport {
    type Error;
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error>;
}
```

## Specs

- [Architecture](../../docs/architecture.md#simrs-transport)

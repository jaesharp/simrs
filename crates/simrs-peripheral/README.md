# simrs-peripheral

`SimPeripheral` trait -- hardware SIM slot abstraction.

**Layer:** Boundary | **`no_std`:** yes | **Status:** Stub

```mermaid
graph TD
    PERI["simrs-peripheral<br/><i>trait</i>"]
    SHAN["simrs-peripheral-shannon"]
    OSEM["simrs-peripheral-osembed"]
    PERI --> SHAN & OSEM

    style PERI fill:#C35400,stroke:#333,color:#fff
    style SHAN fill:#C35400,stroke:#333,color:#fff
    style OSEM fill:#C35400,stroke:#333,color:#fff,stroke-dasharray:5 5
```

## API (planned)

```rust
pub trait SimPeripheral {
    type Error;
    fn power_on(&mut self) -> Result<&'static [u8], Self::Error>;  // -> ATR
    fn power_off(&mut self) -> Result<(), Self::Error>;
    fn reset(&mut self) -> Result<(), Self::Error>;
    fn exchange(&mut self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize, Self::Error>;
}
```

## Specs

- [Architecture](../../docs/architecture.md#simrs-peripheral)

# simrs-gp-card

GlobalPlatform card -- top-level event-driven card type.

Provides `GpCard`, the GP equivalent of `simrs-sim::Sim`. Implements the
same `process(event) -> response` interface using `SimEvent`/`SimResponse`
from `simrs-card-api`, so it integrates with the existing infrastructure
(HLE, interposer, fuzzer, QEMU bridge).

`no_std`. No heap allocation.

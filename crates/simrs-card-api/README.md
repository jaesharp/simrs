# simrs-card-api

Shared card event/response types for SIM and GlobalPlatform cards.

Defines `SimEvent`, `SimResponse`, `ResetKind`, `ResetEffects`, and
`CardState` so that both `simrs-sim` (SIM/USIM) and `simrs-gp-card`
(GlobalPlatform) integrate with the same infrastructure: HLE, QEMU
bridge, interposer, fuzzer, and snapshot.

`no_std`. No heap allocation. Only depends on `simrs-iso7816`.

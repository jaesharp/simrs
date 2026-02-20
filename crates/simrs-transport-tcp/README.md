# simrs-transport-tcp

TCP transport for swICC PC/SC server. Requires `std`.

**Layer:** Boundary | **`no_std`:** no | **Status:** Stub

Wire protocol: 4-byte big-endian length prefix + APDU payload.

## Dependencies

[simrs-transport](../simrs-transport/), [simrs-iso7816](../simrs-iso7816/)

## Specs

- [Architecture](../../docs/architecture.md#simrs-transport-tcp)

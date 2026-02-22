# simrs-auth-cli

CLI tool for Milenage authentication vector generation and verification.

**Layer:** Application | **`no_std`:** no | **Status:** Implemented

## Features

- `gen-vector`: compute (RAND, AUTN, XRES, CK, IK) from subscriber credentials (K, OPc, SQN, AMF)
- `verify`: constant-time comparison of RES vs XRES, exit code 0 on match
- JSON output for consumption by Python `subprocess.run()` callers (BridgeWire mini-MME)
- Random RAND generation via `getrandom`, or fixed via `--rand` flag
- Hex input with optional `0x`/`0X` prefix

## Usage

```
simrs-auth gen-vector --k <hex> --opc <hex> --sqn <hex> --amf <hex> [--rand <hex>]
simrs-auth verify --xres <hex> --res <hex>
```

## Standards

| Spec | Coverage |
|------|----------|
| ETSI TS 135 206 | Milenage f1-f5 (via simrs-milenage) |
| ETSI TS 135 208 | Test Set 1 validated in unit tests |
| ETSI TS 133 102 | AKA procedure, AUTN construction |

## Dependencies

| Crate | Purpose |
|-------|---------|
| [simrs-milenage](../simrs-milenage/) | Milenage f1-f5 authentication functions |

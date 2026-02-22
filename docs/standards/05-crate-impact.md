# Crate Impact Analysis

What 4G-LTE and 5G-NR support means for each simrs crate.

[Back to Standards Map](README.md)

---

## Impact Matrix

| Crate | 4G Impact | 5G SA Impact | 5G NSA Impact | Priority |
|-------|-----------|--------------|---------------|----------|
| [simrs-iso7816](../../crates/simrs-iso7816/) | None | None | None | -- |
| [simrs-bertlv](../../crates/simrs-bertlv/) | None | None | None | -- |
| [simrs-rijndael](../../crates/simrs-rijndael/) | None | None | None | -- |
| [simrs-comp128](../../crates/simrs-comp128/) | None (2G only) | None | None | -- |
| [simrs-milenage](../../crates/simrs-milenage/) | Used identically | Used identically | Used identically | P0 |
| [simrs-fs](../../crates/simrs-fs/) | EPS EFs (6FE3, 6FE4) | +DF_5GS (5FC0, 4F01-4F11) | No change | P1 |
| [simrs-pin](../../crates/simrs-pin/) | No change | No change | No change | -- |
| [simrs-proactive](../../crates/simrs-proactive/) | No change | +5G events (Rel-16) | No change | P2 |
| [simrs-gsm](../../crates/simrs-gsm/) | No change (2G compat) | No change | No change | -- |
| [simrs-usim](../../crates/simrs-usim/) | AUTHENTICATE, EPS EFs | +DF_5GS EFs, SUCI info | No change | P1 |
| [simrs-sim](../../crates/simrs-sim/) | No change | No change | No change | -- |
| [simrs-hle](../../crates/simrs-hle/) | No change | No change | No change | -- |
| [simrs-snapshot](../../crates/simrs-snapshot/) | +EPS EF state | +DF_5GS EF state | No change | P1 |

---

## Per-Crate Details

### `simrs-milenage`

**Status:** No changes needed for any generation. The USIM runs f1-f5 identically for 3G/4G/5G. The AMF separation bit (0 for 3G/4G, 1 for 5G) is passed through AUTN but doesn't change the USIM-side computation.

**Future:** Extract `AuthAlgorithm` trait from `MilenageParams` to enable TUAK (f1-f5 signatures already conform to TS 35.205 clause 3) as a drop-in. The trait interface matches the 3GPP f1-f5 function signatures exactly. TUAK implementation (P2) would add a `simrs-tuak` crate depending on a new `simrs-keccak` crate.

```rust
// Future crate dependency for TUAK support:
//   simrs-tuak -> simrs-keccak (Keccak-f[1600] permutation)
// Both would implement the AuthAlgorithm trait from simrs-milenage.
```

### `simrs-fs`

**Changes needed:**
1. Add DF_5GS (FID 5FC0) as a child of ADF_USIM
2. Add all Rel-15 EFs (4F01-4F0A) with appropriate types and default data
3. Add Rel-16 EFs (4F0B-4F0E) as stubs
4. `DfDef` needs to support nested DFs (DF_5GS under ADF_USIM)

**Already supported:** `SelectionCtx` handles DF navigation. `EfData::AllFf` handles stub EFs at zero cost.

### `simrs-usim`

**Changes needed (P1):**
1. Define DF_5GS filesystem as `const` statics in a `data::df_5gs` module
2. Handle SELECT into DF_5GS
3. Handle READ BINARY / READ RECORD for 5G EFs
4. Handle UPDATE RECORD for EF5GS3GPPNSC (ME writes security context)
5. Handle UPDATE BINARY for EF5GS3GPPLOCI (ME writes 5G-GUTI)

**No changes needed for AUTHENTICATE** -- the handler is already generation-agnostic.

### `simrs-proactive`

**Changes needed (P2):**
- Add 5G-specific event download types:
  - Network Rejection (0x13)
  - Data Connection Status Change (0x14)
- Add 5G-specific PROVIDE LOCAL INFORMATION values (serving NSSAI, etc.)
- These are additive; existing command encoding is unaffected.

### `simrs-snapshot`

**Changes needed (P1):**
- Include DF_5GS EF contents in the snapshot blob
- The `Snapshot::BLOB_SIZE` const will increase to accommodate 5G state

---

## Implementation Phases (updated with 4G/5G scope)

| Phase | Crates | 4G/5G Content |
|-------|--------|---------------|
| 1 | rijndael, comp128, iso7816, bertlv | None (generation-agnostic) |
| 2 | milenage, fs, pin | Add AuthAlgorithm trait; DF_5GS directory structure |
| 3 | proactive, gsm, usim | EPS EFs, DF_5GS EFs, AUTHENTICATE (all gens) |
| 4 | sim, transport, peripheral | No generation-specific changes |
| 5 | snapshot, hle, fuzz | Include EPS + 5G state in snapshots |
| Future | simrs-tuak, simrs-keccak | TUAK algorithm (256-bit K for 5G SUCI) |
| Future | simrs-kdf | HMAC-SHA-256 KDF for ME-side derivation (KASME, KAUSF) |
| Future | simrs-ecies | ECIES for SUCI computation (Curve25519 / secp256r1) |

---

## Key Reasoning

**Why the USIM crate doesn't need generation-specific code paths:** The 3GPP authentication architecture was explicitly designed so that the USIM is generation-agnostic. The same K, the same Milenage/TUAK, the same AUTHENTICATE APDU. Generation differences live in:
1. The ME (key derivation: KASME for 4G, KAUSF/KSEAF/KAMF for 5G)
2. The core network (HSS for 4G, AUSF/UDM for 5G)
3. The filesystem (which EFs are present on the card)

This is a deliberate design choice by 3GPP -- it means SIM cards don't need hardware changes for new generations, only filesystem provisioning (OTA updates to add DF_5GS files and enable services in EF_UST).

For simrs, this means our core authentication path (`simrs-milenage` + `simrs-usim` AUTHENTICATE handler) is stable across all generations. The 5G work is filesystem-only: defining new EFs and handling reads/writes to them. This is exactly the kind of change that our `const`-static filesystem design handles well.

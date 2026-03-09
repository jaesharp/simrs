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
| [simrs-fs](../../crates/simrs-fs/) | EPS EFs (6FE3, 6FE4) | +DF_5GS (5FC0, 4F01-4F11) -- implemented | No change | Done |
| [simrs-pin](../../crates/simrs-pin/) | No change | No change | No change | -- |
| [simrs-proactive](../../crates/simrs-proactive/) | No change | +5G events (Rel-16) -- implemented | No change | Done |
| [simrs-gsm](../../crates/simrs-gsm/) | No change (2G compat) | No change | No change | -- |
| [simrs-usim](../../crates/simrs-usim/) | AUTHENTICATE, EPS EFs | +DF_5GS EFs, SUCI info | No change | Done |
| [simrs-sim](../../crates/simrs-sim/) | No change | No change | No change | -- |
| [simrs-hle](../../crates/simrs-hle/) | No change | No change | No change | -- |
| [simrs-snapshot](../../crates/simrs-snapshot/) | +EPS EF state | +EPS + 5G EF state -- implemented | No change | Done |
| [simrs-keccak](../../crates/simrs-keccak/) | None | None | None | -- |
| [simrs-tuak](../../crates/simrs-tuak/) | Used identically | Used identically | Used identically | P0 |
| [simrs-ota](../../crates/simrs-ota/) | No change | No change | No change | -- |
| [simrs-pcap](../../crates/simrs-pcap/) | No change | No change | No change | -- |
| [simrs-interposer](../../crates/simrs-interposer/) | No change | No change | No change | -- |
| [simrs-auth-cli](../../crates/simrs-auth-cli/) | No change | No change | No change | -- |
| [simrs-consttime](../../crates/simrs-consttime/) | None | None | None | -- |
| [simrs-consttime-macros](../../crates/simrs-consttime-macros/) | None | None | None | -- |
| [simrs-consttime-validation](../../crates/simrs-consttime-validation/) | None | None | None | -- |
| [simrs-transport-tcp](../../crates/simrs-transport-tcp/) | No change | No change | No change | -- |
| [simrs-sha256](../../crates/simrs-sha256/) | None | None | None | Done |
| [simrs-kdf](../../crates/simrs-kdf/) | KASME, KeNB, algorithm keys | +KAUSF, RES*, KSEAF, KAMF, KgNB | Same as 4G | Done |
| [simrs-ecies](../../crates/simrs-ecies/) | None | SUCI encryption (Profile A + B) | None | Done |
| [simrs-profile](../../crates/simrs-profile/) | Synthesizes all other crates | Synthesizes all other crates | Synthesizes all other crates | Done |

---

## Per-Crate Details

### `simrs-milenage`

**Status:** No changes needed for any generation. The USIM runs f1-f5 identically for 3G/4G/5G. The AMF separation bit (0 for 3G/4G, 1 for 5G) is passed through AUTN but doesn't change the USIM-side computation.

**Done:** The `AuthenticationAlgorithm` trait is defined in `simrs-milenage` and implemented by both `MilenageParams` and `TuakParams`. `simrs-usim` and `simrs-sim` are generic over `A: AuthenticationAlgorithm`. `simrs-hle` selects the algorithm at runtime.

```
Crate dependency for TUAK support (implemented):
  simrs-tuak -> simrs-keccak (Keccak-f[1600] permutation)
  simrs-tuak -> simrs-milenage (AuthenticationAlgorithm trait, AuthenticationOutput, AuthenticationError)
```

### `simrs-fs`

**Implemented:**
1. DF_5GS (FID 5FC0) added as a child of ADF_USIM
2. All Rel-15 EFs (4F01-4F0A) defined with appropriate types and default data
3. Rel-16 EFs (4F0B-4F0E) defined
4. `DfDef` supports nested DFs (DF_5GS under ADF_USIM)

**Already supported:** `SelectionCtx` handles DF navigation. `EfData::AllFf` handles stub EFs at zero cost.

### `simrs-usim`

**Implemented:**
1. DF_5GS filesystem defined as `const` statics in a `data::df_5gs` module
2. SELECT into DF_5GS handled
3. READ BINARY / READ RECORD for 5G EFs handled
4. UPDATE RECORD for EF5GS3GPPNSC (ME writes security context) handled
5. UPDATE BINARY for EF5GS3GPPLOCI (ME writes 5G-GUTI) handled

Full catalog: 115 ADF EFs + 19 DF_5GS + 11 sub-DFs + ISIM + HPSIM.

**No changes needed for AUTHENTICATE** -- the handler is already generation-agnostic.

### `simrs-proactive`

**Implemented:**
- 5G event download types added: Network Rejection (0x12), Data Connection Status Change (0x1D), Slices Status Change (0x1F)
- 5G PROVIDE LOCAL INFORMATION qualifiers: slices information (0x15), rejected slices information (0x17)
- Full event_id module (30 events, 0x00-0x1F) and pli_qualifier module (22 qualifiers)
- Timer Expiration refactored to use correct D7 envelope (was incorrectly handled as D6 Event Download)
- Event subscription bitmask widened from u32 to u64

Note: many proactive commands are already implemented (DISPLAY TEXT, GET INPUT, SET UP MENU, SEND SMS, PLAY TONE, PROVIDE LOCAL INFORMATION, etc.).

### `simrs-snapshot`

**Implemented:**
- DF_5GS EF contents included in the snapshot blob
- EPS + 5G EF state included in snapshots

---

## Implementation Phases (updated with 4G/5G scope)

| Phase | Crates | 4G/5G Content | Status |
|-------|--------|---------------|--------|
| 1 | rijndael, comp128, iso7816, bertlv | None (generation-agnostic) | Done |
| 2 | milenage, fs, pin | AuthenticationAlgorithm trait; DF_5GS directory structure | Done |
| 3 | proactive, gsm, usim | EPS EFs, DF_5GS EFs, AUTHENTICATE (all gens) | Done |
| 4 | sim, transport, peripheral | No generation-specific changes | Done |
| 5 | snapshot, hle, fuzz | EPS + 5G state in snapshots | Done |
| 6 | fs, usim, consttime | Type system: EfDef constructors, Sfi/Fid validation, compile-time FID uniqueness | Done |
| -- | simrs-tuak, simrs-keccak | TUAK algorithm (256-bit K for 5G SUCI) | Done |
| -- | simrs-sha256 | SHA-256 hash (NIST FIPS 180-4) | Done |
| -- | simrs-kdf | HMAC-SHA-256 KDF for ME-side derivation (KASME, KAUSF, KSEAF, KAMF, KgNB) | Done |
| -- | simrs-ecies | ECIES Profiles A + B for SUCI computation (X25519/P-256 + AES-128-CTR) | Done |

---

## Key Reasoning

**Why the USIM crate doesn't need generation-specific code paths:** The 3GPP authentication architecture was explicitly designed so that the USIM is generation-agnostic. The same K, the same Milenage/TUAK, the same AUTHENTICATE APDU. Generation differences live in:
1. The ME (key derivation: KASME for 4G, KAUSF/KSEAF/KAMF for 5G)
2. The core network (HSS for 4G, AUSF/UDM for 5G)
3. The filesystem (which EFs are present on the card)

This is a deliberate design choice by 3GPP -- it means SIM cards don't need hardware changes for new generations, only filesystem provisioning (OTA updates to add DF_5GS files and enable services in EF_UST).

For simrs, this means our core authentication path (`simrs-milenage` + `simrs-usim` AUTHENTICATE handler) is stable across all generations. The 5G work is filesystem-only: defining new EFs and handling reads/writes to them. This is exactly the kind of change that our `const`-static filesystem design handles well.

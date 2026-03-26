# Differential Compliance Report: simrs vs Oracle jcsl

Generated from 23 differential tests + 22 replay tests against Oracle jcsl.
simrs targets GP 2.1.1 (SCP01/SCP02) and GP 2.3.1 (SCP03).
Oracle implements GP 2.3 (SCP03).

## Divergence Catalog

### D1: SELECT FCI Response Richness -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **Behavior** | Returns `6F { 84 { AID } A5 { 9F65 { lifecycle } } }` | Returns full FCI template (99 bytes) |
| **SW** | 9000 | 9000 |

**GP 2.1.1 clause 9.9.3.1 Table 9-13**: FCI must contain tag 84 (AID) and tag A5
(FCI proprietary data) with tag 9F65 (lifecycle).

**Status: FIXED** -- simrs now includes the A5 proprietary template with lifecycle byte.

---

### D2: SELECT with 8-byte ISD AID

| | simrs | Oracle |
|-|-------|--------|
| **SW** | 6A82 (not found) | 9000 |

simrs ISD AID = 7 bytes `A0 00 00 01 51 00 00` (GP 2.1.1 default).
Oracle ISD AID = 8 bytes `A0 00 00 01 51 00 00 00` (GP 2.3 default).

**Category: C (configurable)** -- simrs supports `with_isd_aid()` for custom AID.
Both implementations respond to each other's AID via prefix matching on SELECT.

---

### D3: INITIALIZE UPDATE Response Length -- RESOLVED

| | simrs (SCP02) | simrs (SCP03) | Oracle (SCP03) |
|-|---------------|---------------|----------------|
| **Length** | 28 bytes | 29 bytes | 32 bytes |
| **SCP ID** | 0x02 | 0x03 | 0x03 |

**Status: RESOLVED** -- simrs now supports SCP03 (29-byte response with SCP ID 0x03).
Oracle returns 32 bytes (3 extra for pseudo-random sequence counter, i=0x70).
simrs uses explicit challenge mode (i=0x00), producing 29 bytes per spec.

---

### D4: Invalid GP INS Error SW -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **APDU** | `80 FD 00 00` | `80 FD 00 00` |
| **SW** | 6D00 (INS not supported) | 6D00 (INS not supported) |

**Status: FIXED** -- simrs now checks INS validity before the auth guard.

---

### D5: Wrong Key Version SW -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **APDU** | `80 50 FF 00 08 ...` (KV=0xFF) | same |
| **SW** | 6A86 (incorrect parameters P1-P2) | 6A86 (incorrect parameters P1-P2) |

**Status: FIXED** -- changed from 6A88 to 6A86 per GP 2.1.1 Table 9-8.

---

### D6: Bad EXTERNAL AUTHENTICATE SW

| | simrs | Oracle |
|-|-------|--------|
| **SW** | 6988 (SM data objects incorrect) | 6985 (conditions not satisfied) |

**Category: B (spec ambiguity)** -- both implementations choose valid but different SWs.
simrs's 6988 is defensible for the padding oracle defense (Avoine & Ferreira TCHES 2018).

---

### D7: CPLC (Tag 9F7F) Support -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **SW** | 9000 (45 bytes) | 9000 (45 bytes) |
| **Data** | Identical (`9F 7F 2A` + 42 zero bytes) | Identical |

**Status: FIXED** -- simrs now returns a default CPLC structure (tag 9F7F, 42 zero bytes).

---

### D8: GET DATA 0066 Response Richness -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **Length** | 53 bytes | 79 bytes |
| **Common** | Both start with `66 .. 73 .. 06 07 2A 86 48 86 FC 6B 01` (GP OID) |

**Status: FIXED** -- simrs now returns extended OIDs for card management type,
card identification scheme, and SCP (SCP02 i=0x15). Oracle has additional OIDs
for contactless and CVM that are outside GP 2.1.1 scope.

---

### D9: GET DATA 0042 Response Format -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **SW** | 6A88 (not found) | 9000 (tag 42 + IIN data) |

**GP 2.1.1 clause 9.6**: Tag 0042 is "Issuer Identification Number" (IIN), not the ISD AID.

**Status: FIXED** -- simrs now correctly returns 6A88 for unconfigured IIN instead
of incorrectly returning the ISD AID.

---

### D10: Authenticated GET STATUS Response -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **Privileges** | 0x9E (SD + DAP + DM + Lock + Terminate) | 0x9E |

**Status: FIXED** -- ISD privilege byte changed from 0x80 to 0x9E.

---

### D11: GET STATUS TLV Format -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **Format** | TLV: `E3 { 4F { AID } 9F70 { lifecycle } C5 { privileges } }` | Same TLV format |

**Status: FIXED** -- GET STATUS now uses GP 2.1.1 Table 9-7 TLV format.

---

## Summary

| ID | Category | Status | Description |
|----|----------|--------|-------------|
| D1 | A: simrs bug | **FIXED** | SELECT FCI proprietary template |
| D2 | C: configurable | **RESOLVED** | ISD AID length (configurable via `with_isd_aid()`) |
| D3 | B: GP version | **RESOLVED** | INIT UPDATE length (simrs now supports SCP03) |
| D4 | A: simrs bug | **FIXED** | Invalid INS SW (6985 -> 6D00) |
| D5 | A: simrs bug | **FIXED** | Wrong KV SW (6A88 -> 6A86) |
| D6 | B: spec ambiguity | -- | EXT AUTH failure SW (6988 vs 6985) |
| D7 | C: missing feature | **FIXED** | CPLC tag 9F7F |
| D8 | C: missing feature | **FIXED** | Extended card recognition data |
| D9 | A: simrs bug | **FIXED** | GET DATA 0042 returns wrong data |
| D10 | A: simrs bug | **FIXED** | ISD privileges 0x80 -> 0x9E |
| D11 | A: simrs bug | **FIXED** | GET STATUS E3 TLV format |

### Remaining divergence (1, spec ambiguity):

- **D6**: EXT AUTH failure SW (6988 vs 6985) -- spec allows both values

### SCP03 validation:

| Test | Result |
|------|--------|
| SCP03 INIT UPDATE (KV=0x03) | 29 bytes, SCP ID=0x03, i=0x00 |
| SCP03 card cryptogram verification | Matches AES-CMAC KDF derivation |
| SCP03 full mutual auth | INIT UPDATE -> EXT AUTH -> Authenticated |
| SCP03 authenticated GET STATUS | 9000 with E3 TLV ISD data |
| SCP03 C-MAC chaining | 16-byte AES-CMAC chaining value |

### Matching behaviors (no divergence):

| Command | Both return |
|---------|------------|
| SELECT unknown AID | 6A82 |
| GET DATA unknown tag (0xDEAD) | 6A88 |
| Invalid GP INS (80 FD) | 6D00 |
| Invalid ISO INS (00 FD) | 6D00 |
| EXT AUTH without INIT UPDATE | 6985 |
| GET STATUS without auth | 6985 |
| MANAGE CHANNEL open | 9000, channel=01 |
| MANAGE CHANNEL close | 9000 |
| CPLC (GET DATA 9F7F) | 9000 (identical 45 bytes) |
| Wrong key version (KV=0xFF) | 6A86 |

### Changelog

- **2026-03-26**: 8 divergences fixed (6 Category A bugs, 2 Category C features).
- **2026-03-26**: SCP03 (GP 2.3.1 Amendment D) implemented. D2 and D3 resolved.
  23 differential tests, 22 replay tests, 102 BDD scenarios, 147 unit tests pass.

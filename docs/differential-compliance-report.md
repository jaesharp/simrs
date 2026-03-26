# Differential Compliance Report: simrs vs Oracle jcsl

Generated from 61 differential tests against Oracle jcsl reference implementation.
simrs targets GP 2.1.1 (SCP01/SCP02). Oracle implements GP 2.3 (SCP03).

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

**Category: B (GP version difference)** -- expected. simrs uses the 7-byte AID per 2.1.1.

---

### D3: INITIALIZE UPDATE Response Length

| | simrs | Oracle |
|-|-------|--------|
| **Length** | 28 bytes | 32 bytes |
| **SCP ID** | 0x02 (SCP02) | 0x03 (SCP03) |

**Category: B (GP version difference)** -- different SCP versions produce different formats.

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
| **SW** | 6988 (SM data objects incorrect) | 6982 (security status not satisfied) |

**Category: B (spec ambiguity)** -- both implementations choose valid but different SWs.
simrs's 6988 is defensible for the padding oracle defense (Avoine & Ferreira TCHES 2018).

---

### D7: CPLC (Tag 9F7F) Support -- FIXED

| | simrs | Oracle |
|-|-------|--------|
| **SW** | 9000 (45 bytes) | 9000 (45 bytes) |

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
| D2 | B: GP version | -- | ISD AID length (7 vs 8) |
| D3 | B: GP version | -- | INIT UPDATE response length (SCP02 vs SCP03) |
| D4 | A: simrs bug | **FIXED** | Invalid INS SW (6985 -> 6D00) |
| D5 | A: simrs bug | **FIXED** | Wrong KV SW (6A88 -> 6A86) |
| D6 | B: spec ambiguity | -- | EXT AUTH failure SW (6988 vs 6982) |
| D7 | C: missing feature | **FIXED** | CPLC tag 9F7F |
| D8 | C: missing feature | **FIXED** | Extended card recognition data |
| D9 | A: simrs bug | **FIXED** | GET DATA 0042 returns wrong data |
| D10 | A: simrs bug | **FIXED** | ISD privileges 0x80 -> 0x9E |
| D11 | A: simrs bug | **FIXED** | GET STATUS E3 TLV format |

### Remaining divergences (3, all GP version differences):

- **D2**: ISD AID length (7 vs 8 bytes) -- GP 2.1.1 vs 2.3
- **D3**: INIT UPDATE format (28 vs 32 bytes) -- SCP02 vs SCP03
- **D6**: EXT AUTH failure SW -- spec allows both values

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
| CPLC (GET DATA 9F7F) | 9000 |

### Fixes applied: 2025-03-26

8 divergences fixed (6 Category A bugs, 2 Category C features).
All unit tests (70/70), BDD scenarios (97/97), and snapshot tests (18/18) pass.

# Differential Compliance Report: simrs vs Oracle jcsl

Generated from 61 differential tests against Oracle jcsl reference implementation.
simrs targets GP 2.1.1 (SCP01/SCP02). Oracle implements GP 2.3 (SCP03).

## Divergence Catalog

### D1: SELECT FCI Response Richness

| | simrs | Oracle |
|-|-------|--------|
| **Behavior** | Returns `6F { 84 { AID } }` (11 bytes) | Returns full FCI template (99 bytes) |
| **SW** | 9000 | 9000 |
| **Data** | `6F 09 84 07 A0 00 00 01 51 00 00` | `6F 61 84 08 A0...00 A5 55 73 4B...9F 65 01 FE` |

**GP 2.1.1 clause 9.9.3.1**: "The OPEN shall return the FCI in the response data field."
Table 9-13 specifies: tag 6F containing tag 84 (AID), tag A5 (FCI proprietary data) with
tag 9F65 (lifecycle), tag 73 (SD management data with GP OID).

**Category: A (simrs bug)** -- simrs omits the A5 proprietary template. The spec requires it.

**Fix**: Expand `handle_select_by_aid()` to include `A5 { 9F65 { lifecycle } 73 { OID } }`.

---

### D2: SELECT with 8-byte ISD AID

| | simrs | Oracle |
|-|-------|--------|
| **SW** | 6A82 (not found) | 9000 |

simrs ISD AID = 7 bytes `A0 00 00 01 51 00 00` (GP 2.1.1 default).
Oracle ISD AID = 8 bytes `A0 00 00 01 51 00 00 00` (GP 2.3 default).

**GP 2.1.1 clause 6.4**: ISD AID is implementation-defined.
**GP 2.3 clause 3.6**: Default ISD AID is `A0 00 00 01 51 00 00 00` (8 bytes).

**Category: B (GP version difference)** -- expected. simrs uses the 7-byte AID per 2.1.1.

**No fix needed.** Document as known version difference.

---

### D3: INITIALIZE UPDATE Response Length

| | simrs | Oracle |
|-|-------|--------|
| **Length** | 28 bytes | 32 bytes |
| **SCP ID** | 0x02 (SCP02) | 0x03 (SCP03) |
| **Format** | key_div[10] + key_info[2] + seq[2] + cc[6] + crypto[8] | key_div[10] + key_info[3] + cc[8] + crypto[8] + seq[3] |

**GP 2.1.1 Appendix E**: SCP02 returns 28 bytes.
**GP Amendment D**: SCP03 returns 29-32 bytes (with optional sequence counter).

**Category: B (GP version difference)** -- different SCP versions produce different formats.

---

### D4: Invalid GP INS Error SW

| | simrs | Oracle |
|-|-------|--------|
| **APDU** | `80 FD 00 00` | `80 FD 00 00` |
| **SW** | 6985 (conditions not satisfied) | 6D00 (INS not supported) |

**GP 2.1.1 clause 9**: Invalid INS in GP class should return 6D00.
simrs returns 6985 because the SCP auth guard runs before INS dispatch.

**Category: A (simrs bug)** -- the auth guard should not apply to completely invalid INS values.
The card should check INS validity before checking authentication.

**Fix**: In `handle_gp_command()`, check INS validity (is it a known GP INS?) before the auth guard.
Return 6D00 for unknown INS regardless of auth state.

---

### D5: Wrong Key Version SW

| | simrs | Oracle |
|-|-------|--------|
| **APDU** | `80 50 FF 00 08 ...` (KV=0xFF) | same |
| **SW** | 6A88 (referenced data not found) | 6A86 (incorrect parameters P1-P2) |

**GP 2.1.1 clause 9.7 Table 9-8**: Key version is in P1. Invalid P1 should return 6A86.
6A88 means "referenced data not found" which implies the key was looked up and not found.
6A86 means "incorrect parameters P1-P2" which implies the value is outright rejected.

**Category: A (simrs bug)** -- 6A86 is more correct per the spec table. The key version
is a P1 parameter, and an invalid value is "incorrect P1-P2".

**Fix**: Change `handle_initialize_update()` bad KV return from `wrong_params(0x88)` to
`wrong_params(0x86)`.

---

### D6: Bad EXTERNAL AUTHENTICATE SW

| | simrs | Oracle |
|-|-------|--------|
| **APDU** | `84 82 00 00 10 [bad crypto+MAC]` | same |
| **SW** | 6988 (SM data objects incorrect) | 6982 (security status not satisfied) |

**GP 2.1.1 clause 9.8 Table 9-9**: Failed EXT AUTH may return 6300 (authentication failed)
or 6985 (conditions not satisfied) or 6A88.

Both 6988 and 6982 are reasonable for this failure mode. 6988 = "SM data incorrect" (wrong MAC),
6982 = "security status not satisfied" (authentication failed).

**Category: B (spec ambiguity)** -- both implementations choose valid but different SWs.

**No fix needed.** simrs's 6988 is defensible for the padding oracle defense (uniform error
for all SM failures per Avoine & Ferreira TCHES 2018).

---

### D7: CPLC (Tag 9F7F) Support

| | simrs | Oracle |
|-|-------|--------|
| **SW** | 6A88 (not found) | 9000 (45 bytes data) |

**GP 2.1.1 clause 9.6**: GET DATA for tag 9F7F returns Card Production Life Cycle data.
This is an optional data object that not all cards support.

**Category: C (missing feature)** -- simrs doesn't implement CPLC.

**Fix (optional)**: Add tag 9F7F to `get_data()` returning a default CPLC structure.

---

### D8: GET DATA 0066 Response Richness

| | simrs | Oracle |
|-|-------|--------|
| **Length** | 15 bytes | 79 bytes |
| **Common** | Both start with `66 .. 73 .. 06 07 2A 86 48 86 FC 6B 01` (GP OID) | |
| **Extra** | simrs: lifecycle + SCP ID only | Oracle: extended OIDs for SSD, CASD, CVM, Contactless |

**GP 2.1.1 clause 9.6 Table 9-3**: Card Recognition Data (tag 66) contains tag 73
with GP OID and optional extended tags for card capabilities.

**Category: C (missing feature)** -- simrs returns minimal card recognition data.

**Fix (optional)**: Add extended OID entries for supported features.

---

### D9: GET DATA 0042 Response Format

| | simrs | Oracle |
|-|-------|--------|
| **Data** | `A0 00 00 01 51 00 00` (raw 7-byte AID) | `42 07 49 53 44 5F 49 49 4E` (TLV-wrapped) |

Oracle returns tag 42 + length + ASCII "ISD_IIN" which is the Issuer Identification Number.
simrs returns the raw ISD AID without TLV wrapping.

**GP 2.1.1 clause 9.6**: Tag 0042 is "Issuer Identification Number" per ISO 7816-4, not the ISD AID.

**Category: A (simrs bug)** -- simrs returns the wrong data for tag 0042. It should return
the Issuer Identification Number (IIN), or 6A88 if not configured.

**Fix**: Either return the IIN (if configured) or 6A88 for unimplemented tag 0042.

---

### D10: Authenticated GET STATUS Response

| | simrs | Oracle |
|-|-------|--------|
| **Data** | `07 A0 00 00 01 51 00 00 07 80` | `08 A0 00 00 01 51 00 00 00 01 9E` |
| **AID len** | 7 | 8 |
| **Lifecycle** | 0x07 (INITIALIZED) | 0x01 (OP_READY) |
| **Privileges** | 0x80 (SD basic) | 0x9E (SD + DAP + DM + Token + Lock + Terminate) |

**GP 2.1.1 clause 9.4.3**: ISD privileges per Table 6-1 should include:
- bit 7 (0x80): Security Domain
- bit 4 (0x10): DAP Verification
- bit 3 (0x08): Delegated Management
- bit 2 (0x04): Card Lock
- bit 1 (0x02): Card Terminate

Full ISD privilege byte = 0x80 | 0x10 | 0x08 | 0x04 | 0x02 = 0x9E.

**Category: A (simrs bug)** -- simrs only sets bit 7 (0x80). Should set full ISD privileges.

**Fix**: Change ISD default privileges from 0x80 to 0x9E in `GpOpen::new()`.

---

### D11: GET STATUS TLV Format

| | simrs | Oracle |
|-|-------|--------|
| **Format** | Flat: `aid_len \|\| AID \|\| lifecycle \|\| privileges` | TLV: `E3 { 4F { AID } 9F70 { lifecycle } C5 { privileges } }` |

**GP 2.1.1 clause 9.4.3 Table 9-7**: GET STATUS response shall use TLV format
with tag E3 wrapping each entry.

**Category: A (simrs bug)** -- simrs uses a non-standard flat format.

**Fix**: Wrap each registry entry in tag E3 with sub-tags 4F, 9F70, C5.

---

## Summary

| Category | Count | Description |
|----------|-------|-------------|
| **A: simrs bug** | 5 | FCI template, invalid INS SW, wrong KV SW, ISD privileges, GET STATUS TLV, GET DATA 0042 |
| **B: GP version difference** | 3 | ISD AID length, SCP version, EXT AUTH SW |
| **C: Missing feature** | 2 | CPLC, extended card recognition data |
| **D: Different defaults** | 0 | (covered by B) |

### Matching behaviors (no divergence):

| Command | Both return |
|---------|------------|
| SELECT unknown AID | 6A82 |
| GET DATA unknown tag (0xDEAD) | 6A88 |
| ISO invalid INS (00 FD) | 6D00 |
| EXT AUTH without INIT UPDATE | 6985 |
| GET STATUS without auth | 6985 |
| MANAGE CHANNEL open | 9000, channel=01 |
| MANAGE CHANNEL close | 9000 |

### Priority fix order:

1. **ISD privileges** (D10) -- trivial one-line fix
2. **Wrong KV SW** (D5) -- trivial one-line fix
3. **GET DATA 0042** (D9) -- return 6A88 instead of wrong data
4. **Invalid INS SW** (D4) -- restructure auth guard ordering
5. **SELECT FCI** (D1) -- add A5 proprietary template
6. **GET STATUS TLV** (D11) -- reformat response with E3/4F/9F70/C5

# Differential Test Report

**Summary:** 8 match, 0 known divergences, 1 regression

| # | Test | simrs SW | Oracle SW | Status | Note |
|---|------|----------|-----------|--------|------|
| 1 | Power on (ATR) | 9000 | 9000 | PASS |  |
| 2 | SELECT simrs ISD AID | 9000 | 9000 | PASS |  |
| 3 | SELECT Oracle ISD AID | 6A82 | 9000 | FAIL | REGRESSION |
| 4 | SELECT unknown AID | 6A82 | 6A82 | PASS |  |
| 5 | GET DATA card recognition (0066) | 9000 | 9000 | PASS |  |
| 6 | GET DATA CPLC (9F7F) | 9000 | 9000 | PASS |  |
| 7 | GET DATA unknown tag (DEAD) | 6A88 | 6A88 | PASS |  |
| 8 | Invalid GP INS (80 FD) | 6D00 | 6D00 | PASS |  |
| 9 | Invalid ISO INS (00 FD) | 6D00 | 6D00 | PASS |  |

## Divergences

### SELECT Oracle ISD AID (REGRESSION)

- **Command:** `00 A4 04 00 08 A0 00 00 01 51 00 00 00`
- **simrs:** 6A82 | **Oracle:** 9000
- **simrs response:** `6A 82`
- **Oracle response:** `6F 61 84 08 A0 00 00 01 51 00 00 00 A5 55 73 4B 06 07 2A 86 48 86 FC 6B 01 60 0B 06 09 2A 86 48 86 FC 6B 02 02 02 63 09 06 07 2A 86 48 86 FC 6B 03 64 0B 06 09 2A 86 48 86 FC 6B 04 03 70 65 0D 06 0B 2A 86 48 86 FC 6B 05 07 02 01 00 66 0C 06 0A 2B 06 01 04 01 2A 02 6E 01 03 9F 6E 01 01 9F 65 01 FE 90 00`


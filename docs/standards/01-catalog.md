# Standards Catalog

All 3GPP, ETSI, ISO, and NIST specifications referenced by simrs, with latest known versions.

[Back to Standards Map](README.md) | [Authentication](02-authentication.md) | [Filesystem](03-filesystem.md)

---

## UICC Platform (Physical / Logical Interface)

| Spec | Title | Rel-17 | Rel-18 | simrs Crate | Notes |
|------|-------|--------|--------|-------------|-------|
| ISO/IEC 7816-3 | Electrical interface, transmission protocols | N/A | N/A | [iso7816](../../crates/simrs-iso7816/) | T=0, T=1 framing |
| ISO/IEC 7816-4:2020 | Organization, security, commands | N/A | N/A | [iso7816](../../crates/simrs-iso7816/) | APDU structure, SW codes |
| ETSI TS 102 221 | UICC-Terminal interface | V17.4.0 | V18.2.0 | [iso7816](../../crates/simrs-iso7816/), [fs](../../crates/simrs-fs/) | SELECT, READ, UPDATE, FCP, logical channels |
| ETSI TS 101 220 | ETSI numbering system for telecoms | V17.1.0 | V18.0.0 | [bertlv](../../crates/simrs-bertlv/) | BER-TLV tag assignments, AIDs |
| ETSI TS 102 230-1 | UICC test spec (terminal) | V17.2.0 | -- | -- | Conformance testing |
| ETSI TS 102 230-2 | UICC test spec (UICC) | V17.1.0 | -- | -- | Conformance testing |
| 3GPP TS 31.101 | UICC-terminal interface (3GPP ref) | V17.x | V18.x | -- | Normative reference to TS 102 221 |

## USIM Application

| Spec | Title | Rel-17 | Rel-18 | Rel-19 | simrs Crate |
|------|-------|--------|--------|--------|-------------|
| 3GPP TS 31.102 | USIM application | V17.16.0 | V18.9.0 | V19.4.0 | [usim](../../crates/simrs-usim/), [fs](../../crates/simrs-fs/) |
| 3GPP TS 31.103 | ISIM application | V17.x | -- | -- | Future |
| 3GPP TS 31.111 | USAT (USIM Application Toolkit) | V17.14.0 | V18.11.0 | V19.3.0 | [proactive](../../crates/simrs-proactive/) |
| 3GPP TS 31.121 | USIM test spec | V17.x | -- | V19.x | -- |
| 3GPP TS 31.122 | USIM conformance | V17.3.0 | V18.3.0 | -- | -- |

## Authentication Algorithms

| Spec | Title | Version | simrs Crate | Notes |
|------|-------|---------|-------------|-------|
| NIST FIPS 197 | AES (Rijndael) | 2001 | [rijndael](../../crates/simrs-rijndael/) | 128-bit block cipher, encrypt only |
| 3GPP TS 35.205 | Milenage: General | V16.0.0 | [milenage](../../crates/simrs-milenage/) | Algorithm set overview |
| 3GPP TS 35.206 | Milenage: Algorithm spec | V16.0.0 | [milenage](../../crates/simrs-milenage/) | f1-f5, f1*, f5*, OPc |
| 3GPP TS 35.207 | Milenage: Test data | V16.0.0 | [milenage](../../crates/simrs-milenage/) | 6 test sets |
| 3GPP TS 35.208 | Milenage: Design conformance | V16.0.0 | [milenage](../../crates/simrs-milenage/) | Verification data |
| 3GPP TS 35.231 | TUAK: Algorithm spec | V15.0.0 | [tuak](../../crates/simrs-tuak/) | Keccak-based alternative to Milenage |
| 3GPP TS 35.232 | TUAK: Test data | V12.1.0 | [tuak](../../crates/simrs-tuak/) | Test vectors |
| 3GPP TS 35.233 | TUAK: Design conformance | V12.1.0 | [tuak](../../crates/simrs-tuak/) | Verification data |

## Security Architecture

| Spec | Title | Rel-17 | Rel-18 | simrs Crate | Scope |
|------|-------|--------|--------|-------------|-------|
| 3GPP TS 33.102 | 3G Security architecture | V17.0.0 | -- | [milenage](../../crates/simrs-milenage/) | AKA procedure, SQN management, C3 conversion |
| 3GPP TS 33.401 | EPS (4G) Security | V17.7.0 | V18.3.0 | [usim](../../crates/simrs-usim/) | EPS-AKA, KASME hierarchy |
| 3GPP TS 33.501 | 5G Security | V17.5.0 | V18.9.0 | Future | 5G-AKA, EAP-AKA', SUCI, KAUSF hierarchy |
| 3GPP TS 33.220 | GBA (Generic Bootstrapping) | V17.x | -- | Future | HMAC-SHA-256 KDF framework |

## SIM Toolkit / OTA

| Spec | Title | Rel-17 | Rel-18 | simrs Crate |
|------|-------|--------|--------|-------------|
| ETSI TS 102 223 | Card Application Toolkit (CAT) | V17.2.0 | V18.2.0 | [proactive](../../crates/simrs-proactive/) |
| ETSI TS 102 225 | Secured packet structure | V17.x | V18.1.0 | [ota](../../crates/simrs-ota/) |
| ETSI TS 102 226 | Remote APDU structure | V17.0.0 | V18.5.0 | [ota](../../crates/simrs-ota/) |
| 3GPP TS 31.115 | Secured packet (3GPP) | V17.x | -- | Future |
| 3GPP TS 31.116 | Remote APDU (3GPP) | V17.x | -- | Future |
| ETSI TS 102 241 | UICC API for Java Card | V17.5.0 | -- | N/A |
| GlobalPlatform v2.3.1 | Card spec (applet lifecycle) | -- | -- | N/A |

## GSM Legacy

| Spec | Title | Version | simrs Crate |
|------|-------|---------|-------------|
| GSM 11.11 (ETS 300 608) | ME-SIM interface | v4.21.1 | [gsm](../../crates/simrs-gsm/) |
| 3GPP TS 51.011 | SIM-ME interface (successor) | V4.15.0 | [gsm](../../crates/simrs-gsm/) |

---

## Revision Decision: Which Releases to Target

**Tradeoff:** Supporting the latest release (Rel-19) maximizes feature coverage but adds complexity from EFs and services that most real-world terminals never use. Supporting only Rel-15 misses critical 5G features like SUCI and network slicing.

**simrs strategy:**

| Priority | Release | Rationale |
|----------|---------|-----------|
| P0 (must) | Rel-4/5 | GSM 11.11 baseline for `simrs-gsm` |
| P0 (must) | Rel-8 | UMTS/EPS baseline: EF_EPSLOCI, EF_EPSNSC, EPS-AKA |
| P1 (should) | Rel-15 | 5G SA baseline: DF_5GS, SUCI, 5G-AKA |
| P2 (nice) | Rel-16 | URSP, CAG, trusted non-3GPP |
| P3 (later) | Rel-17+ | Disaster roaming, eDRX, satellite access |

This means the filesystem (EF catalog) should be Rel-15 complete with Rel-16 stubs, and the auth path should support both Milenage and (eventually) TUAK for 256-bit key support.

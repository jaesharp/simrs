# Standards Catalog

All 3GPP, ETSI, ISO, and NIST specifications referenced by simrs, with latest known versions.

[Back to Standards Map](README.md) | [Authentication](02-authentication.md) | [Filesystem](03-filesystem.md)

---

## UICC Platform (Physical / Logical Interface)

| Spec | Title | Rel-17 | Rel-18 | Rel-19 | simrs Crate | Notes |
|------|-------|--------|--------|--------|-------------|-------|
| ISO/IEC 7816-3 | Electrical interface, transmission protocols | N/A | N/A | N/A | [iso7816](../../crates/simrs-iso7816/) | T=0, T=1 framing |
| ISO/IEC 7816-4:2020 | Organization, security, commands | N/A | N/A | N/A | [iso7816](../../crates/simrs-iso7816/) | APDU structure, SW codes |
| ETSI TS 102 221 | UICC-Terminal interface | V17.4.0 | V18.3.0 | -- | [iso7816](../../crates/simrs-iso7816/), [fs](../../crates/simrs-fs/), [usim](../../crates/simrs-usim/) | SELECT, READ, UPDATE, FCP, logical channels; DF.TELECOM (12 EFs, feature: `telecom`) |
| ETSI TS 101 220 | ETSI numbering system for telecoms | V17.1.0 | -- | V19.0.0 | [bertlv](../../crates/simrs-bertlv/) | BER-TLV tag assignments, AIDs |
| ETSI TS 102 230-1 | UICC test spec (terminal) | V17.2.0 | -- | -- | -- | Conformance testing |
| ETSI TS 102 230-2 | UICC test spec (UICC) | V17.1.0 | -- | -- | -- | Conformance testing |
| 3GPP TS 31.101 | UICC-terminal interface (3GPP ref) | V17.0.0 | -- | -- | -- | Normative reference to TS 102 221 |
| 3GPP TS 23.038 | Alphabets and language-specific information | V17.0.0 | -- | V19.0.0 | [proactive](../../crates/simrs-proactive/) | GSM 7-bit default alphabet, CBS data coding, text packing |

## USIM Application

| Spec | Title | Rel-17 | Rel-18 | Rel-19 | simrs Crate |
|------|-------|--------|--------|--------|-------------|
| 3GPP TS 31.102 | USIM application | V17.16.0 | V18.9.0 | V19.4.0 | [usim](../../crates/simrs-usim/), [fs](../../crates/simrs-fs/). Full catalog: 115 ADF EFs + 19 DF_5GS + 11 sub-DFs. |
| 3GPP TS 31.103 | ISIM application | V17.0.0 | -- | V19.0.0 | [usim](../../crates/simrs-usim/) (feature: `isim`). 10 EFs: IMPI, DOMAIN, IMPU, ARR, IST, P-CSCF, GBABP, GBANL, NAFKCA, AD. |
| 3GPP TS 31.104 | HPSIM application | V17.0.0 | -- | V19.0.0 | [usim](../../crates/simrs-usim/) (feature: `hpsim`). 3 EFs: ARR, HPST, AD. |
| 3GPP TS 31.111 | USAT (USIM Application Toolkit) | V17.14.0 | V18.11.0 | V19.3.0 | [proactive](../../crates/simrs-proactive/) |
| 3GPP TS 31.121 | USIM test spec | V17.x | -- | V19.x | -- |
| 3GPP TS 31.122 | USIM conformance | V17.3.0 | V18.3.0 | -- | -- |

## Authentication Algorithms

| Spec | Title | Version | simrs Crate | Notes |
|------|-------|---------|-------------|-------|
| NIST FIPS 180-4 | SHA-256 | 2015 | [sha256](../../crates/simrs-sha256/) | Cryptographic hash function |
| NIST FIPS 186-4 | Digital Signature Standard (P-256) | 2013 | [ecies](../../crates/simrs-ecies/) | secp256r1/P-256 ECDH for ECIES Profile B |
| NIST FIPS 197 | AES (Rijndael) | 2001 | [rijndael](../../crates/simrs-rijndael/) | 128-bit block cipher, encrypt only |
| NIST FIPS 198-1 | HMAC | 2008 | [kdf](../../crates/simrs-kdf/) | Keyed-hash message authentication code |
| RFC 2104 | HMAC | 1997 | [kdf](../../crates/simrs-kdf/) | HMAC construction (basis for FIPS 198-1) |
| RFC 7748 | Elliptic Curves for Security (X25519) | 2016 | [ecies](../../crates/simrs-ecies/) | Curve25519 Diffie-Hellman for ECIES Profile A |
| 3GPP TS 35.205 | Milenage: General | V19.0.0 | [milenage](../../crates/simrs-milenage/) | Algorithm set overview |
| 3GPP TS 35.206 | Milenage: Algorithm spec | V19.0.0 | [milenage](../../crates/simrs-milenage/) | f1-f5, f1*, f5*, OPc |
| 3GPP TS 35.207 | Milenage: Test data | V19.0.0 | [milenage](../../crates/simrs-milenage/) | 6 test sets |
| 3GPP TS 35.208 | Milenage: Design conformance | V19.0.0 | [milenage](../../crates/simrs-milenage/) | Verification data |
| 3GPP TS 35.231 | TUAK: Algorithm spec | V19.0.0 | [tuak](../../crates/simrs-tuak/) | Keccak-based alternative to Milenage |
| 3GPP TS 35.232 | TUAK: Test data | V19.0.0 | [tuak](../../crates/simrs-tuak/) | Test vectors |
| 3GPP TS 35.233 | TUAK: Design conformance | V19.0.0 | [tuak](../../crates/simrs-tuak/) | Verification data |
| NIST FIPS 202 | SHA-3 Standard (Keccak permutation) | 2015 | [keccak](../../crates/simrs-keccak/) | Keccak-f[1600] used by TUAK |
| GSM 03.20 / 3GPP TS 43.020 | Security related network functions (COMP128) | V19.0.0 | [comp128](../../crates/simrs-comp128/) | COMP128 v1/v2/v3 algorithms |

## Security Architecture

| Spec | Title | Rel-17 | Rel-18 | Rel-19 | simrs Crate | Scope |
|------|-------|--------|--------|--------|-------------|-------|
| 3GPP TS 33.102 | 3G Security architecture | V17.0.0 | -- | V19.1.0 | [milenage](../../crates/simrs-milenage/) | AKA procedure, SQN management, C3 conversion |
| 3GPP TS 33.401 | EPS (4G) Security | V17.7.0 | V18.3.0 | -- | [usim](../../crates/simrs-usim/), [kdf](../../crates/simrs-kdf/) | EPS-AKA, KASME hierarchy; KDF Annex A |
| 3GPP TS 33.501 | 5G Security | V17.5.0 | V18.9.0 | -- | [usim](../../crates/simrs-usim/), [kdf](../../crates/simrs-kdf/), [ecies](../../crates/simrs-ecies/) | USIM-side: SUCI_Calc_Info, 5GAUTHKEYS, 5G NAS security context EFs; KDF Annex A; ECIES Annex C (Profiles A/B) |
| 3GPP TS 33.220 | GBA (Generic Bootstrapping) | V17.x | -- | -- | [kdf](../../crates/simrs-kdf/) | Generic 3GPP KDF (Annex B) |

## SIM Toolkit / OTA

| Spec | Title | Rel-17 | Rel-18 | Rel-19 | simrs Crate |
|------|-------|--------|--------|--------|-------------|
| ETSI TS 102 223 | Card Application Toolkit (CAT) | V17.2.0 | V18.2.0 | -- | [proactive](../../crates/simrs-proactive/) |
| ETSI TS 102 225 | Secured packet structure | -- | V18.1.0 | V19.0.0 | [ota](../../crates/simrs-ota/) |
| ETSI TS 102 226 | Remote APDU structure | V17.0.0 | -- | V19.0.0 | [ota](../../crates/simrs-ota/) |
| 3GPP TS 31.115 | Secured packet (3GPP) | V17.x | -- | -- | Future |
| 3GPP TS 31.116 | Remote APDU (3GPP) | V17.x | -- | -- | Future |
| ETSI TS 102 241 | UICC API for Java Card | V17.5.0 | -- | -- | N/A |
| GlobalPlatform v2.3.1 | Card spec (applet lifecycle) | -- | -- | -- | N/A |

## eSIM / Profile Provisioning

| Spec | Title | Version | simrs Crate | Notes |
|------|-------|---------|-------------|-------|
| TCA eUICC Profile Package | Interoperability Technical Specification | v3.3.1 | [profile](../../crates/simrs-profile/) | DER ASN.1 profile format, PE parsing |
| GSMA SGP.22 | RSP Technical Specification (consumer eSIM) | v2.6 | [profile](../../crates/simrs-profile/) | UPP format reference |
| GSMA SGP.32 | IoT RSP Technical Specification | v1.2 | -- | IoT eSIM architecture (reference only) |
| GSMA TS.48 | Generic Test Profile | v1.0 | [profile](../../crates/simrs-profile/) | Test profile fixtures |

## GSM Legacy

| Spec | Title | Version | simrs Crate |
|------|-------|---------|-------------|
| GSM 11.11 (ETS 300 608) | ME-SIM interface | v4.21.1 | [gsm](../../crates/simrs-gsm/) |
| 3GPP TS 51.011 | SIM-ME interface (successor) | V4.15.0 | [gsm](../../crates/simrs-gsm/) |

## GlobalPlatform Card Specifications

Primary target: **GP 2.3.1** (CC-certified) + Amendment D (SCP03). Legacy
target: GP 2.1.1 (JCOP10..JCOP31bio compatibility). Detailed conformance
status is tracked in [06-globalplatform.md](06-globalplatform.md#conformance-status-2026-04-snapshot).

| Spec | Title | Version | Ref | Status | simrs Crate |
|------|-------|---------|-----|--------|-------------|
| GP Card Specification | Card Management, OPEN, Security Domains | v2.3.1 | GPC_SPE_034 | Primary | gp-open, gp-scp, gp-keys |
| GP Card Specification | (legacy compat for JCOP10..JCOP31bio) | v2.1.1 | GPC_SPE_006 | Legacy | gp-open, gp-scp, gp-keys |
| GP Card Specification | (intermediate) | v2.2, v2.2.1 | -- | Reference | gp-open (reference) |
| GP Amendment A | Confidential Card Content Management | v1.2 | GPC_SPE_007 | Not implemented | gp-open (DAP) -- planned |
| GP Amendment B | Remote Application Management over HTTP (SCP81) | v1.1.3 | GPC_SPE_011 | Not implemented | (future) |
| GP Amendment C | Contactless Services | v1.2 | GPC_SPE_025 | N/A by design (transport layer) | -- |
| GP Amendment D | Secure Channel Protocol 03 | v1.1.2 | GPC_SPE_014 | Implemented (i-parameter parsed but not enforced) | gp-scp |
| GP Amendment E | Security Upgrade (ECC/RSA) | v1.1 | GPC_SPE_042 | Not implemented | gp-scp -- enables JCOP3x |
| GP SE Access Control | Secure Element Access Control | v1.1 | GPD_SPE_013 | Not implemented | hle (Android HCE) |

## JavaCard Platform Specifications

Primary target: **JavaCard Classic Edition 3.2** (January 2023). Legacy target:
JC 2.1.1 (JCOP target spec, ~82% of bytecodes implemented today). Detailed
conformance status and the phased upgrade plan live in
[06-globalplatform.md](06-globalplatform.md#phased-upgrade-plan).

| Spec | Title | Version | Status | simrs Crate | Notes |
|------|-------|---------|--------|-------------|-------|
| JC Virtual Machine Spec | Bytecode set, CAP format, type system | 3.2 | Primary, in flight; **known opcode compliance gap** | jcvm, jacc | Component-tagged CAP parser surfaces 10 of 13 components on `Package`; jacc CAP writer emits all 13. Opcode numbering deviates from spec (~20 opcodes off; ~20 spec opcodes missing); audit at [07-jcvm-opcode-compliance.md](07-jcvm-opcode-compliance.md) |
| JC Runtime Environment Spec | Applet lifecycle, firewall, transactions | 3.2 | Primary, in flight | jcre | 2.1.1 baseline; multiselect/SIO/extended-APDU pending |
| JC API | Framework, security, crypto, NIO, events, KDF, certs | 3.2 | Primary, in flight | jcre, jcvm/native | Small subset of packages today; Phase 5 is the bulk |
| JC VM Spec + RE Spec | (latest classic) | 3.1 | Reference | -- | Normative clarity for 3.2 ambiguity |
| JC VM Spec + RE Spec | (mid-classic) | 3.0.5 | Reference | -- | StaticResources component introduced |
| JC VM Spec | (many older applets target this) | 2.2.2 | Reference | -- | Extended int support |
| JC VM Spec + RE Spec + API | (legacy) | 2.1.1 | Legacy | jcvm, jcre | JCOP target spec |

## IBM JCOP Product Documentation

| Document | Variants | simrs Crate | Notes |
|----------|----------|-------------|-------|
| JCOP Family Overview | All | jcop-profile | JCOP10/20/21/21id/31bio specs |
| JCOP10 Technical Brief | JCOP10 | jcop-profile | 8KB EEPROM, SCP01, RSA-1024 |
| JCOP20 Technical Brief | JCOP20 | jcop-profile | 16KB, SCP02, RSA-2048 |

## EMV Specifications

| Spec | Title | Version | simrs Crate | Notes |
|------|-------|---------|-------------|-------|
| EMV Book 1 | ICC to Terminal Interface | v4.3 | -- | Physical interface (existing simrs-t0) |
| EMV Book 2 | Security and Key Management | v4.3 | rsa, sha1 | RSA, SHA-1 for EMV applet |
| EMV Book 3 | Application Specification | v4.3 | gp-applet-emv | Core EMV application logic |
| EMV Book 4 | Other Interfaces | v4.3 | gp-applet-emv | Cardholder/attendant interface |
| EMV Contactless Book A | Architecture | -- | (future) | Contactless EMV overview |
| EMV Contactless Book B | Entry Point | -- | (future) | ISO 14443 entry point |
| EMV Contactless Book C-2 | Kernel 2 (MasterCard) | -- | (future) | Scheme-specific kernel |
| EMV Contactless Book D | Communication Protocol | -- | (future) | ISO 14443-4 APDU mapping |

---

## Revision Decision: Which Releases to Target

**Tradeoff:** Supporting the latest release (Rel-19) maximizes feature coverage but adds complexity from EFs and services that most real-world terminals never use. Supporting only Rel-15 misses critical 5G features like SUCI and network slicing.

**simrs strategy:**

| Priority | Release | Rationale |
|----------|---------|-----------|
| P0 (done) | Rel-4/5 | GSM 11.11 baseline for `simrs-gsm` (19 EFs) |
| P0 (done) | Rel-8 | UMTS/EPS baseline: EF_EPSLOCI, EF_EPSNSC, EPS-AKA |
| P0 (done) | Rel-15 | 5G SA baseline: DF_5GS (19 EFs through Rel-18), SUCI_Calc_Info, 5G-GUTI |
| P0 (done) | Rel-16 | URSP, CAG, trusted non-3GPP (EFs in DF_5GS) |
| P0 (done) | Rel-17 | Disaster roaming, eDRX, NSWO (EFs in DF_5GS) |
| P1 (ref) | Rel-19 | Reference PDFs downloaded for 18 specs; spec references updated to Rel-19 versions |

The filesystem EF catalog is Rel-18 complete for DF_5GS (19 EFs through Rel-18) and Rel-19 complete for ADF.USIM root EFs (115 EFs). The auth path supports both Milenage and TUAK for 256-bit key support. Rel-19 PDFs are available as local reference for all core specs (TS 31.102, TS 102 221, TS 102 223, TS 35.206, etc.).

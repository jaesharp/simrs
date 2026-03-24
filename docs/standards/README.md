# simrs Standards Map

Standards reference for 4G-LTE and 5G-NR (SA and NSA) USIM support, mapped to the simrs crate architecture.

Colours follow the [Diagram Style Guide](../DIAGRAM_STYLE_GUIDE.md).

## Documents

| Document | Scope |
|----------|-------|
| [Standards Catalog](01-catalog.md) | All referenced 3GPP/ETSI/GSMA specs with versions |
| [Authentication & Key Management](02-authentication.md) | EPS-AKA, 5G-AKA, EAP-AKA', key hierarchies, Milenage/TUAK, SUCI, Rust API |
| [Filesystem & Data Lifecycle](03-filesystem.md) | EF catalog (LTE + 5G), data structures, APDU sequences |
| [Proactive UICC & SIM Toolkit](04-proactive.md) | CAT/USAT commands, FETCH, OTA, event downloads |
| [Crate Impact Analysis](05-crate-impact.md) | What each standard means for simrs crate public API |
| [GlobalPlatform & JavaCard](06-globalplatform.md) | GP card management, SCP01/SCP02/SCP03, JCVM bytecodes, JCRE runtime, JCOP profiles |

## Standards-to-Crate Map

```mermaid
graph LR
    subgraph standards ["Standards"]
        S1["ISO/IEC 7816-4"]
        S2["ETSI TS 102 221"]
        S3["ETSI TS 101 220"]
        S4["NIST FIPS 197"]
        S5["TS 35.205/206"]
        S6["TS 35.231"]
        S7["TS 33.102"]
        S8["TS 33.401"]
        S9["TS 33.501"]
        S10["TS 31.102"]
        S11["TS 31.103"]
        S12["TS 102 223"]
        S13["TS 31.111"]
        S14["GSM 11.11"]
        S15["TS 35.232"]
        S16["TS 35.233"]
        S17["TS 102 225"]
        S18["TS 102 226"]
        S19["TS 31.104"]
    end

    subgraph crates ["simrs Crates"]
        ISO["simrs-iso7816"]
        BER["simrs-bertlv"]
        RIJ["simrs-rijndael"]
        C128["simrs-comp128"]
        KEC["simrs-keccak"]
        MIL["simrs-milenage"]
        TUAK["simrs-tuak"]
        FS["simrs-fs"]
        PIN["simrs-pin"]
        PRO["simrs-proactive"]
        OTA["simrs-ota"]
        GSM["simrs-gsm"]
        USIM["simrs-usim"]
        SIM["simrs-sim"]
    end

    S1 --> ISO
    S2 --> ISO
    S2 --> FS
    S3 --> BER
    S4 --> RIJ
    S5 --> MIL
    S6 --> TUAK
    S15 --> TUAK
    S16 --> TUAK
    TUAK --> KEC
    TUAK --> MIL
    S7 --> MIL
    S8 --> USIM
    S9 -->|"DF_5GS EFs"| USIM
    S10 --> USIM
    S10 --> FS
    S11 -.->|"feature: isim"| USIM
    S19 -.->|"feature: hpsim"| USIM
    S2 -.->|"feature: telecom"| USIM
    S12 --> PRO
    S13 --> PRO
    S14 --> GSM
    S17 --> OTA
    S18 --> OTA
    OTA --> RIJ
    OTA --> ISO

    classDef foundation fill:#0072B2,stroke:#333,color:#fff
    classDef composition fill:#008060,stroke:#333,color:#fff
    classDef application fill:#E69F00,stroke:#333,color:#000
    classDef std fill:#F0F0F0,stroke:#666,color:#333

    class ISO,BER,RIJ,C128,KEC foundation
    class MIL,TUAK,FS,PIN,PRO,OTA composition
    class GSM,USIM,SIM application
    class S1,S2,S3,S4,S5,S6,S7,S8,S9,S10,S11,S12,S13,S14,S15,S16,S17,S18,S19 std
```

## Generation Scope

| Generation | Auth Method | simrs Coverage | Notes |
|------------|------------|----------------|-------|
| 2G GSM | COMP128 (A3/A8) | `simrs-comp128`, `simrs-gsm` | Implemented |
| 3G UMTS | Milenage (f1-f5) | `simrs-milenage`, `simrs-usim` | Implemented |
| 3G/4G/5G | TUAK (f1-f5, Keccak) | `simrs-keccak`, `simrs-tuak`, `simrs-hle` | Implemented; HLE dispatches Milenage or TUAK |
| 4G LTE (EPS) | EPS-AKA (Milenage + KASME KDF) | `simrs-usim` | USIM-side identical to 3G; ME-side KDF out of scope |
| 5G NR NSA | EPS-AKA (via LTE anchor) | `simrs-usim` | No 5G-specific USIM changes needed |
| 5G NR SA | 5G-AKA / EAP-AKA' | `simrs-usim` (DF_5GS: 19 EFs) | USIM-side: DF_5GS EFs implemented (SUCI, 5G-GUTI, KAMF, URSP, CAG, MCHPPLMN, KAUSF); ME-side key derivation out of scope |

## Protocol Coverage (Tiers 5--6)

APDU-level protocol features implemented in `simrs-sim`, `simrs-usim`, and `simrs-gsm`:

| Feature | Standard | Clause | Crate(s) |
|---------|----------|--------|----------|
| SELECT by path | ETSI TS 102 221 | 11.1.1 | `simrs-usim` |
| SFI-based file access | ETSI TS 102 221 | 8.4.2 | `simrs-usim` |
| CLA byte routing (logical channel, secure messaging) | ETSI TS 102 221 | 10.1.1 | `simrs-sim` |
| AUTHENTICATE GSM context | 3GPP TS 31.102 | 7.1.2 | `simrs-usim` |
| READ/UPDATE RECORD modes (current, absolute, next, prev) | ETSI TS 102 221 | 11.3 | `simrs-usim` |
| INCREASE with overflow detection | ETSI TS 102 221 | 11.3.5 | `simrs-usim` |
| STATUS response variants (FCP, no data) | ETSI TS 102 221 | 11.1.2 | `simrs-usim` |
| SEARCH RECORD | ETSI TS 102 221 | 11.3.4 | `simrs-usim` |
| TERMINAL CAPABILITY | ETSI TS 102 221 | 11.2.19 | `simrs-usim` |
| ACTIVATE/DEACTIVATE FILE | ETSI TS 102 221 | 11.1.14/15 | `simrs-usim`, `simrs-fs` |
| MANAGE CHANNEL (open/close) | ETSI TS 102 221 | 11.1.17 | `simrs-usim` |
| SELECT by AID occurrence (first/last/next) | ETSI TS 102 221 | 11.1.1 | `simrs-usim` |
| FCP security attributes (tag 0x8C) | ETSI TS 102 221 | 11.1.1.3 | `simrs-usim` |
| OTA secured packets (SPI, KIc/KID, CBC-MAC) | ETSI TS 102 225 | 5 | `simrs-ota` |
| Remote APDU structure | ETSI TS 102 226 | 5 | `simrs-ota` |
| PIN1 access control enforcement | ETSI TS 102 221 | 9.5.1 | `simrs-usim`, `simrs-gsm` |
| GSM 7-bit alphabet pack/unpack | 3GPP TS 23.038 | 6.2.1 | `simrs-proactive` |
| Proactive session lifecycle | ETSI TS 102 223 | 6.4 | `simrs-usim` |
| PCAP APDU capture (GSMTAP + DLT_USER0) | libpcap / GSMTAP | -- | `simrs-pcap` |
| Shadow SIM / APDU interposer | -- | -- | `simrs-interposer` |
| Milenage auth vector CLI | ETSI TS 135 206 | 4 | `simrs-auth-cli` |

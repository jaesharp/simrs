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
    end

    subgraph crates ["simrs Crates"]
        ISO["simrs-iso7816"]
        BER["simrs-bertlv"]
        RIJ["simrs-rijndael"]
        C128["simrs-comp128"]
        MIL["simrs-milenage"]
        FS["simrs-fs"]
        PIN["simrs-pin"]
        PRO["simrs-proactive"]
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
    S6 -.->|"future: TUAK"| MIL
    S7 --> MIL
    S8 --> USIM
    S9 -.->|"future: 5G-AKA"| USIM
    S10 --> USIM
    S10 --> FS
    S11 -.->|"future: ISIM"| USIM
    S12 --> PRO
    S13 --> PRO
    S14 --> GSM

    classDef foundation fill:#0072B2,stroke:#333,color:#fff
    classDef composition fill:#008060,stroke:#333,color:#fff
    classDef application fill:#E69F00,stroke:#333,color:#000
    classDef std fill:#F0F0F0,stroke:#666,color:#333

    class ISO,BER,RIJ,C128 foundation
    class MIL,FS,PIN,PRO composition
    class GSM,USIM,SIM application
    class S1,S2,S3,S4,S5,S6,S7,S8,S9,S10,S11,S12,S13,S14 std
```

## Generation Scope

| Generation | Auth Method | simrs Coverage | Notes |
|------------|------------|----------------|-------|
| 2G GSM | COMP128 (A3/A8) | `simrs-comp128`, `simrs-gsm` | Implemented |
| 3G UMTS | Milenage (f1-f5) | `simrs-milenage`, `simrs-usim` | Implemented |
| 4G LTE (EPS) | EPS-AKA (Milenage + KASME KDF) | `simrs-usim` | USIM-side identical to 3G; ME-side KDF out of scope |
| 5G NR NSA | EPS-AKA (via LTE anchor) | `simrs-usim` | No 5G-specific USIM changes needed |
| 5G NR SA | 5G-AKA / EAP-AKA' | Future: `simrs-usim` + DF_5GS EFs | USIM-side identical; ME-side key derivation new |

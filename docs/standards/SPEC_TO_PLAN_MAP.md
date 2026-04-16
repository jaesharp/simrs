# Spec-to-Plan Normative Mapping

Maps every normative spec section to the simrs implementation phase, crate, and
identifies gaps where we lack spec coverage.

## GP 2.1.1 Card Specification -> Plan Phases

### Chapter 3: Card Architecture (p28-31)
| Section | Topic | Phase | Crate | Status |
|---------|-------|-------|-------|--------|
| 3.1 | Runtime Environment | 3 | simrs-jcre | JCRE owns the runtime |
| 3.2.1 | OPEN | 4 | simrs-gp-open | Central dispatch, registry |
| 3.2.2 | Issuer Security Domain | 4 | simrs-gp-open | ISD always present |
| 3.2.3 | Cardholder Verification Management | 4 | simrs-gp-open + simrs-pin | Global PIN |
| 3.3 | Security Domains | 4 | simrs-gp-open | Supplementary SDs |
| 3.4 | GlobalPlatform API | 3 | simrs-jcre | GP API on Java Card (Appendix A) |
| 3.5 | Card Content | 4 | simrs-gp-open | Executable Load Files, Modules |

### Chapter 4: Security Architecture (p32-37)
| Section | Topic | Phase | Crate | Notes |
|---------|-------|-------|-------|-------|
| 4.3.1 | Integrity and Auth for CCM | 2 | simrs-gp-scp | DAP, tokens, receipts |
| 4.3.2 | Secure Communication | 2 | simrs-gp-scp | SCP01/SCP02 |

### Chapter 5: Life Cycle Models (p39-50) -- CRITICAL NORMATIVE
| Section | Topic | Phase | Crate | BDD Feature |
|---------|-------|-------|-------|-------------|
| 5.1.1 | Card Life Cycle States | 4 | simrs-gp-open | card_lifecycle.feature |
| 5.1.2 | Card LC Transitions (Fig 5-1, p42) | 4 | simrs-gp-open | State machine impl |
| 5.2.1 | Executable Load File LC | 4 | simrs-gp-open | Part of install_for_load.feature |
| 5.2.2 | Executable Module LC | 4 | simrs-gp-open | Module lifecycle |
| 5.3.1 | Application LC States (Fig 5-2, p46) | 4 | simrs-gp-open | applet_lifecycle.feature |
| 5.3.2 | Security Domain LC States (Fig 5-3, p48) | 4 | simrs-gp-open | security_domain.feature |
| 5.4 | Sample LC Illustration (Fig 5-4, p50) | 9 | simrs-gp-tests | End-to-end BDD scenario |

**Card LC states** (Table 9-6, p107): OP_READY=0x01, INITIALIZED=0x07, SECURED=0x0F, CARD_LOCKED=0x7F, TERMINATED=0xFF

**Application LC states** (Table 9-4, p107): INSTALLED=0x03, SELECTABLE=0x07, PERSONALIZED=0x0F, LOCKED=0x83

**SD LC states** (Table 9-5, p107): INSTALLED=0x03, SELECTABLE=0x07, PERSONALIZED=0x0F, LOCKED=0x83

### Chapter 6: Card Manager (p51-85) -- CORE IMPLEMENTATION
| Section | Topic | Phase | Crate | BDD Feature |
|---------|-------|-------|-------|-------------|
| 6.1.1 | OPEN (Fig 6-1, p52) | 4 | simrs-gp-open | Core dispatch |
| 6.1.2 | Issuer Security Domain | 4 | simrs-gp-open | ISD commands |
| 6.1.3 | CVM Handler | 4 | simrs-gp-open | gp_pin.feature |
| 6.2.1 | App Access to OPEN Services | 3 | simrs-jcre | GP API bridge |
| 6.2.2 | App Access to CVM Services | 3 | simrs-jcre | OwnerPIN wrapper |
| 6.2.3 | App Access to ISD Services | 3 | simrs-jcre | Runtime messaging |
| 6.3.1 | Basic Logical Channel (p56) | 4 | simrs-gp-open | logical_channels.feature |
| 6.3.2 | Supplementary Logical Channel (p59) | 4 | simrs-gp-open | MANAGE CHANNEL |
| 6.4.1 | Card Content Loading (Fig 6-2/3/4, p62-67) | 4 | simrs-gp-open | install_for_load.feature |
| 6.4.2 | Content Removal (Fig 6-5, p69) | 4 | simrs-gp-open | delete_card_content.feature |
| 6.4.3 | Content Extradition (Fig 6-6, p71) | 4 | simrs-gp-open | install_for_extradition |
| 6.5 | Delegated Management (p71) | 4 | simrs-gp-open | security_domain.feature |
| 6.6 | GP Registry (p72) | 4 | simrs-gp-open | get_status.feature |
| 6.7.1 | Application Locking (Fig 6-7, p77) | 4 | simrs-gp-open | applet_lifecycle.feature |
| 6.7.2 | Card Locking (Fig 6-8, p78) | 4 | simrs-gp-open | card_lifecycle.feature |
| 6.7.3 | Card Termination (Fig 6-9, p79) | 4 | simrs-gp-open | card_lifecycle.feature |
| 6.8 | Issuer Security Domain (p81-83) | 4 | simrs-gp-open | get_data.feature |
| 6.8.3 | Card Recognition Data | 4 | simrs-gp-open | Appendix F |
| 6.9 | CVM Management (p84-85) | 4 | simrs-gp-open | gp_pin.feature |

### Chapter 7: Security Domains (p86-100)
| Section | Topic | Phase | Crate | BDD Feature |
|---------|-------|-------|-------|-------------|
| 7.1-7.2 | SD Overview + Services | 4 | simrs-gp-open | security_domain.feature |
| 7.3 | Personalization Support (Fig 7-1, p89) | 4 | simrs-gp-open | STORE DATA |
| 7.4 | Runtime Messaging (Fig 7-2, p90) | 3 | simrs-jcre | GP API |
| 7.5 | DAP Verification (p91) | 4 | simrs-gp-open | JCOP21id only |
| 7.6 | Delegated Management (Fig 7-3/4, p94-96) | 4 | simrs-gp-open | Tokens + receipts |
| 7.7 | Tokens and Receipts (Fig 7-5..7-12, p97-100) | 4 | simrs-gp-open | Crypto verification |

### Chapter 8: Secure Communication (p101-103)
| Section | Topic | Phase | Crate | BDD Feature |
|---------|-------|-------|-------|-------------|
| 8.1 | Secure Channel | 2 | simrs-gp-scp | scp01/scp02_mutual_auth.feature |
| 8.2 | Explicit/Implicit SC Initiation | 2 | simrs-gp-scp | Both modes |
| 8.4 | Entity Authentication | 2 | simrs-gp-scp | Mutual auth flow |
| 8.5 | Secure Messaging | 2 | simrs-gp-scp | scp_secure_messaging.feature |
| 8.6 | SCP Identifier | 2 | simrs-gp-scp | SCP01=0x01, SCP02=0x02 |

### Chapter 9: APDU Command Reference (p105-138) -- COMMAND-LEVEL NORMATIVE
| Section | INS | Phase | Crate | BDD Feature | Tables |
|---------|-----|-------|-------|-------------|--------|
| 9.1 | General coding rules | 4 | simrs-gp-open | All | T9-1..T9-11 |
| 9.2 | DELETE (0xE4) | 4 | simrs-gp-open | delete_card_content | T9-12..T9-16 |
| 9.3 | GET DATA (0xCA) | 4 | simrs-gp-open | get_data | T9-17..T9-19 |
| 9.4 | GET STATUS (0xF2) | 4 | simrs-gp-open | get_status | T9-20..T9-26 |
| 9.5 | INSTALL (0xE6) | 4 | simrs-gp-open | install_for_* | T9-27..T9-37 |
| 9.6 | LOAD (0xE8) | 4 | simrs-gp-open | install_for_load | T9-38..T9-42 |
| 9.7 | MANAGE CHANNEL (0x70) | 4 | simrs-gp-open | logical_channels | T9-43..T9-45 |
| 9.8 | PUT KEY (0xD8) | 4 | simrs-gp-open | key_management | T9-46..T9-51 |
| 9.9 | SELECT (0xA4) | 4 | simrs-gp-open | select_by_aid | T9-52..T9-57 |
| 9.10 | SET STATUS (0xF0) | 4 | simrs-gp-open | card/applet_lifecycle | T9-58..T9-60 |
| 9.11 | STORE DATA (0xE2) | 4 | simrs-gp-open | personalization | T9-61..T9-63 |

### Appendix A: GlobalPlatform API (p140-188)
| Section | Topic | Phase | Crate | Notes |
|---------|-------|-------|-------|-------|
| A.1 | Deprecated OP Java Card API | -- | -- | Legacy, skip |
| A.2 | GP on a Java Card (p160-185) | 3 | simrs-jcre | **KEY**: defines GP API classes |
| A.2 Table A-1 | Security Level constants (p165) | 2 | simrs-gp-scp | NO_SECURITY=0, AUTH=1, C_MAC=3, C_ENC=7 |

### Appendix B: Algorithms (p189-190)
| Section | Topic | Phase | Crate | Have spec? |
|---------|-------|-------|-------|-----------|
| B.1 | DES Enc/Dec + MACing | 1 | simrs-des, simrs-iso9797 | Yes (FIPS 46-3 in telecom-specs/nist/) |
| B.2.1 | SHA-1 | 1 | simrs-sha1 | Yes (FIPS 180-1 referenced) |
| B.3 | PKCS#1 (RFC 2437) | 1 | simrs-rsa | **GAP**: Need RFC 2437 |
| B.4 | DES Padding (Method 2) | 1 | simrs-iso9797 | ISO 9797 referenced but **GAP**: no ISO 9797 spec |

### Appendix C: Secure Content Management (p191-198)
| Section | Topic | Phase | Crate | Notes |
|---------|-------|-------|-------|-------|
| C.1 | ISD Keys + SD Keys | 2 | simrs-gp-keys | T C-1, C-2 |
| C.2 | Load File Data Block Hash | 4 | simrs-gp-open | SHA-1 based |
| C.3 | Tokens (Load/Install/Extradition) | 4 | simrs-gp-open | T C-3..C-6, DES MAC |
| C.4 | Receipts (Load/Install/Delete/Extradition) | 4 | simrs-gp-open | T C-7..C-10, DES MAC |
| C.5 | DAP Verification (PKC + DES) | 4 | simrs-gp-open | RSA or DES scheme |

### Appendix D: SCP01 (p199-212) -- CRITICAL NORMATIVE
| Section | Topic | Phase | Crate | BDD Feature |
|---------|-------|-------|-------|-------------|
| D.1.1 | SCP01 Secure Channel | 2 | simrs-gp-scp | scp01_mutual_auth.feature |
| D.1.2 | Mutual Authentication (Fig D-1/D-2, p201) | 2 | simrs-gp-scp | Auth flow |
| D.1.3 | Message Integrity | 2 | simrs-gp-scp | C-MAC |
| D.1.4 | Message Data Confidentiality | 2 | simrs-gp-scp | C-ENC |
| D.2 | Cryptographic Keys (T D-1, p203) | 2 | simrs-gp-keys | 3 keys: ENC, MAC, KEK |
| D.3.1 | DES Session Keys (Fig D-3/4/5, p204) | 2 | simrs-gp-scp | Key derivation |
| D.3.2 | Auth Cryptograms (p205) | 2 | simrs-gp-scp | Card/host cryptogram |
| D.3.3 | APDU Command MAC (Fig D-6, p206) | 2 | simrs-gp-scp | C-MAC gen/verify |
| D.3.4 | APDU Data Field Enc (Fig D-7, p207) | 2 | simrs-gp-scp | C-ENC |
| D.3.5 | Key Sensitive Data Enc (p208) | 2 | simrs-gp-scp | PUT KEY wrapping |
| D.4.1 | INITIALIZE UPDATE (T D-4..D-6, p209-210) | 2 | simrs-gp-scp | Command format |
| D.4.2 | EXTERNAL AUTHENTICATE (T D-7..D-9, p211-212) | 2 | simrs-gp-scp | Command format |

### Appendix E: SCP02 (p213-234) -- CRITICAL NORMATIVE
| Section | Topic | Phase | Crate | BDD Feature |
|---------|-------|-------|-------|-------------|
| E.1.1 | SCP02 Secure Channel | 2 | simrs-gp-scp | scp02_mutual_auth.feature |
| E.1.2 | Entity Authentication (Fig E-1, p215) | 2 | simrs-gp-scp | Sequence counter |
| E.1.3 | Message Integrity | 2 | simrs-gp-scp | C-MAC with ICV chaining |
| E.1.4 | Message Data Confidentiality | 2 | simrs-gp-scp | C-ENC |
| E.2 | Cryptographic Keys (T E-1/E-2, p218) | 2 | simrs-gp-keys | Base keys + sequence ctr |
| E.3.1 | CBC (p218) | 1 | simrs-iso9797 | Core MAC primitive |
| E.3.2 | Explicit SC ICV (p218) | 2 | simrs-gp-scp | ICV = 0 initially |
| E.3.3 | Implicit SC ICV (p219) | 2 | simrs-gp-scp | ICV from previous MAC |
| E.3.4 | ICV Encryption (p219) | 2 | simrs-gp-scp | ICV encrypted with S-MAC |
| E.4.1 | Session Keys (Fig E-2, p220) | 2 | simrs-gp-scp | Derivation from seq ctr |
| E.4.2 | Auth Cryptograms, Explicit (p220) | 2 | simrs-gp-scp | Host/card proof |
| E.4.3 | Auth Cryptograms, Implicit (p220) | 2 | simrs-gp-scp | Implicit SC variant |
| E.4.4 | C-MAC Gen/Verify (Fig E-3/E-4, p221-222) | 2 | simrs-gp-scp | Core secure messaging |
| E.4.5 | R-MAC Gen (Fig E-5, p223) | 2 | simrs-gp-scp | Response MAC |
| E.4.6 | Data Field Enc (Fig E-6, p225) | 2 | simrs-gp-scp | C-ENC encrypt/decrypt |
| E.4.7 | Sensitive Data Enc (p225) | 2 | simrs-gp-scp | PUT KEY wrapping |
| E.5.1 | INITIALIZE UPDATE (T E-6..E-8, p227-228) | 2 | simrs-gp-scp | SCP02 command |
| E.5.2 | EXTERNAL AUTHENTICATE (T E-9..E-11, p229-230) | 2 | simrs-gp-scp | SCP02 command |
| E.5.3 | BEGIN R-MAC SESSION (T E-12..E-16, p231-232) | 2 | simrs-gp-scp | R-MAC |
| E.5.4 | END R-MAC SESSION (T E-17..E-20, p233-234) | 2 | simrs-gp-scp | R-MAC |

### Appendix F: GP Data Values and Card Recognition Data (p235-237)
| Section | Topic | Phase | Crate | Notes |
|---------|-------|-------|-------|-------|
| F.1 | Data Values | 4 | simrs-gp-open | GET DATA responses |
| F.2 | Card Recognition Data (T F-1, p236) | 4 | simrs-gp-open | TLV structure |
| F.3 | SD Management Data (T F-2, p237) | 4 | simrs-gp-open | SD info |

---

## JC 2.1.1 JCVM Specification -> Plan Phases

| Chapter | Topic | Phase | Crate | Notes |
|---------|-------|-------|-------|-------|
| 2 | Java Subset (p7-24) | 7 | simrs-jcvm | Language restrictions (no float, no long, no threads, etc.) |
| 3 | VM Structure (p25-32) | 7 | simrs-jcvm | Data types, words, frames, contexts |
| 3.1 | Data Types: boolean, byte, short, reference (T 3-1, p30) | 7 | simrs-jcvm | Only 4 types on-card |
| 3.3 | Runtime Data Areas | 7 | simrs-jcvm | Stack, heap, method area |
| 3.4 | Contexts | 7 | simrs-jcvm | Firewall contexts |
| 3.5 | Frames | 7 | simrs-jcvm | Call frames with locals + operand stack |
| 4 | Binary Representation (p33-44) | 7 | simrs-jcvm | AID-based naming, token linking |
| 4.1 | Java Card File Formats | 7 | simrs-jcvm | CAP + Export files |
| 4.2 | AID-based Naming | 7 | simrs-jcvm | Package -> AID mapping |
| 4.3 | Token-based Linking (T 4-1, p39) | 7 | simrs-jcvm | How imports resolve |
| 5 | Export File Format (p47-63) | 7 | simrs-jcvm | For linking, not execution |
| 6 | CAP File Format (p65-116) | 7 | simrs-jcvm | **CRITICAL**: on-card binary format |
| 6.1 | Component Model (T 6-1/6-2, p66-67) | 7 | simrs-jcvm | 12 components |
| 6.3 | Header Component | 7 | simrs-jcvm | Magic, version, pkg AID |
| 6.4 | Directory Component | 7 | simrs-jcvm | Size table |
| 6.5 | Applet Component | 7 | simrs-jcvm | AID -> class mapping |
| 6.7 | Constant Pool Component | 7 | simrs-jcvm | Resolved references |
| 6.8 | Class Component | 7 | simrs-jcvm | Class hierarchy, fields |
| 6.9 | Method Component | 7 | simrs-jcvm | Bytecode methods |
| 6.10 | Static Field Component | 7 | simrs-jcvm | Initial values |
| 6.11 | Reference Location Component | 7 | simrs-jcvm | Linking offsets |
| 7 | Instruction Set (p117-248) | 7 | simrs-jcvm | ~185 bytecodes |
| 7.5 | Full instruction set | 7 | simrs-jcvm | Each opcode page |
| 8 | Instruction Tables (T 8-1/8-2, p249-252) | 7 | simrs-jcvm | By value + by mnemonic |

---

## JC 2.1.1 JCRE Specification -> Plan Phases

| Chapter | Topic | Phase | Crate | BDD Feature |
|---------|-------|-------|-------|-------------|
| 2 | VM Lifetime (p3-4) | 7 | simrs-jcvm | VM persists across resets |
| 3.1 | Method install | 3 | simrs-jcre | Applet trait |
| 3.2 | Method select | 3 | simrs-jcre | Applet trait |
| 3.3 | Method process | 3 | simrs-jcre | Applet trait |
| 3.4 | Method deselect | 3 | simrs-jcre | Applet trait |
| 3.5 | Power Loss and Reset | 3 | simrs-jcre | Transient clear + tx abort |
| 4.1 | Default Applet | 4 | simrs-gp-open | select_by_aid.feature |
| 4.2 | SELECT Command Processing (p10) | 4 | simrs-gp-open | AID-based dispatch |
| 4.3 | Non-SELECT Command Processing | 4 | simrs-gp-open | Forward to applet |
| 5 | Transient Objects (p13-14) | 3 | simrs-jcre | CLEAR_ON_RESET, CLEAR_ON_DESELECT |
| 6.1 | Applet Firewall (p15-18) | 7 | simrs-jcvm | jcvm_firewall.feature |
| 6.1.1 | Contexts and Context Switching | 7 | simrs-jcvm | Context stack |
| 6.1.2 | Object Ownership | 7 | simrs-jcvm | Owner = creating context |
| 6.1.3 | Object Access rules | 7 | simrs-jcvm | Same context only |
| 6.2.1 | JCRE Entry Point Objects | 7 | simrs-jcvm | Temporary vs permanent |
| 6.2.4 | Shareable Interfaces (p22-25) | 7 | simrs-jcvm | SIO pattern |
| 7.1 | Atomicity (p33) | 3 | simrs-jcre | Single field atomic |
| 7.2 | Transactions (p34) | 3 | simrs-jcre | jcvm_transactions.feature |
| 7.3 | Transaction Duration | 3 | simrs-jcre | Within single APDU |
| 7.4 | Nested Transactions | 3 | simrs-jcre | NOT supported (throw) |
| 7.5 | Tear or Reset Transaction Failure | 3 | simrs-jcre | Rollback |
| 7.8 | Commit Capacity | 3 | simrs-jcre | 512/768 bytes |
| 8.4 | APDU Class (p40-44) | 3 | simrs-jcre | T=0 and T=1 specifics |
| 8.5 | Security and Crypto packages | 3 | simrs-jcre | javacard.security API |
| 8.6 | JCSystem Class (p45-46) | 3 | simrs-jcre | Transaction, memory, AID |
| 10 | Applet Installer (p49-53) | 4 | simrs-gp-open | GP INSTALL command |

---

## SCP01 Implementation Reference (GP 2.1.1 Appendix D, p199-212)

Key derivation and crypto operations extracted from normative text:

**Keys** (Table D-1): 3 static DES keys per key set
- S-ENC (key ID 1): encryption key
- S-MAC (key ID 2): MAC key
- DEK (key ID 3): data encryption key (for PUT KEY wrapping)

**Session keys** (Fig D-3/D-4/D-5): derived from static keys
- Derivation data = `[card_challenge[4..8] || host_challenge[0..4] || card_challenge[0..4] || host_challenge[4..8]]`
- Session S-ENC = 3DES_ECB_encrypt(static_S-ENC, derivation_data)
- Session S-MAC = 3DES_ECB_encrypt(static_S-MAC, derivation_data)

**INITIALIZE UPDATE** (Table D-4): CLA=0x80, INS=0x50, P1=key_version, P2=key_id, Lc=0x08
- Command data: 8-byte host challenge
- Response (Table D-5): 28 bytes = key_diversification[10] || key_info[2] || card_challenge[8] || card_cryptogram[8]
- Card cryptogram = MAC(S-ENC, host_challenge || card_challenge), truncated to 8 bytes

**EXTERNAL AUTHENTICATE** (Table D-7): CLA=0x84, INS=0x82, P1=security_level, P2=0x00, Lc=0x10
- Command data: host_cryptogram[8] || C-MAC[8]
- Host cryptogram = MAC(S-ENC, card_challenge || host_challenge)
- Security levels: 0x00=no security, 0x01=C-MAC, 0x03=C-MAC+C-ENC

**C-MAC generation** (Fig D-6): Full-length 3DES CBC-MAC over (modified CLA || INS || P1 || P2 || Lc+8 || data), padded with Method 2

## SCP02 Implementation Reference (GP 2.1.1 Appendix E, p213-234)

**Key differences from SCP01**:
- Session keys derived from static keys AND a 2-byte sequence counter
- Sequence counter is persistent, increments on each successful INITIALIZE UPDATE
- ICV chaining: MAC ICV from previous command (not always zero)
- R-MAC support (response message authentication)

**Session key derivation** (Fig E-2):
- Derivation constants: 0x0182 (S-ENC), 0x0101 (C-MAC), 0x0102 (R-MAC), 0x0181 (DEK)
- For each key: derive = 3DES_CBC(static_key, [derivation_constant || sequence_counter || pad_to_16_bytes])
- IV = 0x0000000000000000

**Sequence counter**: 2-byte big-endian, starts at 0x0000, wraps at 0xFFFF, persistent across resets

**INITIALIZE UPDATE** (Table E-6): Same structure as SCP01 but:
- Response includes sequence counter in key_info field
- Card cryptogram uses session S-ENC (not static)

**C-MAC with ICV chaining** (Fig E-3/E-4):
- Explicit SC: ICV starts at zero, subsequent commands chain from previous MAC
- ICV encryption: each ICV is encrypted with session S-MAC before use as CBC IV

**R-MAC** (Fig E-5): Response authentication
- BEGIN R-MAC SESSION (INS=0x70) starts R-MAC
- END R-MAC SESSION (INS=0x78) ends R-MAC
- R-MAC = MAC(R-MAC_key, response_data || SW1 || SW2)

## JCVM CAP File Format Reference (JC 2.1.1 JCVM Spec Chapter 6, p65-116)

**CAP file structure**: ZIP archive containing 11 component files:
1. Header (magic 0xDECAFFED, minor/major version, pkg AID, pkg name)
2. Directory (component sizes table, static field sizes, import count)
3. Applet (AID -> install_method_offset mapping, one entry per applet in package)
4. Import (list of imported packages with their AIDs and versions)
5. ConstantPool (resolved references: class refs, instance/static field refs, method refs)
6. Class (class hierarchy: super_class, interfaces, field count, public method table)
7. Method (bytecode for each method: flags, max_stack, nargs, max_locals, bytecode[])
8. StaticField (initial values for static fields, both primitive and reference)
9. ReferenceLocation (offsets where imported tokens need runtime resolution)
10. Export (published tokens for other packages to link against)
11. Descriptor (debug info, optional)

**Method info structure**:
```
method_info {
  u1 flags;           // 0x08=extended, bit fields for access
  u2 max_stack;       // max operand stack depth
  u1 nargs;           // number of arguments (including 'this')
  u1 max_locals;      // max local variables
  u2 bytecode_count;  // length of bytecode array
  u1 bytecode[];      // the actual bytecodes
}
```

**Key bytecodes for MVP** (from Chapter 7 instruction tables):
- Stack: sconst_m1..sconst_5, sload_0..sload_3, sstore_0..sstore_3
- Arithmetic: sadd(0x41), ssub(0x43), smul(0x45), sdiv(0x47), srem(0x49)
- Compare: if_scmpeq(0x6A), if_scmpne(0x6B), if_scmplt(0x6C), if_scmpge(0x6D)
- Array: newarray(0x90), arraylength(0x92), saload(0x24), sastore(0x38), baload(0x25), bastore(0x39)
- Object: new(0x8F), getfield_s(0x83), putfield_s(0x84), invokevirtual(0x8B), invokestatic(0x8D)
- Control: goto(0x70), sreturn(0x78), athrow(0xA0)
- Special: invokeinterface(0x8E) -- for SIO access across firewall

## EMV v4.3 -> Plan Mapping

| EMV Book | Topic | Phase | Crate | Priority |
|----------|-------|-------|-------|----------|
| Book 1: ICC to Terminal | Physical interface, ATR, protocol | -- | simrs-t0 (existing) | Already covered |
| Book 2: Security + Key Mgmt | RSA, SHA-1, certificate chain | 1+8 | simrs-rsa, simrs-sha1, simrs-gp-applet-emv | Crypto in Phase 1, applet in Phase 8 |
| Book 3: Application Spec | SELECT, GPO, READ RECORD, auth flow | 8 | simrs-gp-applet-emv | Core EMV applet logic |
| Book 4: Other Interfaces | Cardholder/attendant interface | 8 | simrs-gp-applet-emv | Terminal-side (lower priority) |
| Contactless Book A | Architecture overview | 8+ | (future) | Contactless EMV |
| Contactless Book B | Entry point protocol | 8+ | (future) | ISO 14443 integration |
| Contactless Book C-2 | Kernel 2 (MasterCard) | 8+ | (future) | Scheme-specific |
| Contactless Book D | Communication protocol | 8+ | (future) | ISO 14443-4 APDU mapping |

## Identified Spec Gaps (Updated)

| Gap | What we need | Why | Status |
|-----|-------------|-----|--------|
| RFC 2437 | PKCS#1 v2.0 | GP Appendix B.3 for RSA | Can implement from EMV Book 2 + GP appendix |
| ISO 9797 | MAC Algorithm 1 | GP DES MACing | Can implement from GP Appendix D/E descriptions |
| JC 3.0.5 specs | Full classic edition | Latest classic | **RESOLVED**: Got from GitHub mirror |
| JC 2.2.2 specs | JCVM/JCRE/API | Applet targets | **RESOLVED**: Downloaded from Oracle |
| GP 2.2/2.2.1 | Intermediate versions | Version lineage | **RESOLVED**: Downloaded |
| EMV Books 1-4 | Payment specs | EMV applet | **RESOLVED**: All 8 books from GitHub mirror |
| GP UICC Config v2.0 | UICC card mgmt | SIM+GP bridge | Needs GP membership (not critical) |
| GP Amd C v1.3 | Latest contactless | JCOP21+ | Needs GP portal JS (have v1.2) |

## Remaining Accounts (Optional)

### GlobalPlatform Non-Member Download (free but JS-gated)
- URL: https://globalplatform.org/specs-library/contactless-services-amendment-c-v1-3/
- Process: Click "Free Non-Member Download", fill JS popup (name, company, email), accept license
- Gets: Amendment C v1.3, SE Access Control v1.2
- Priority: Low (we have C v1.2)

### EMVCo (not free)
- Cheapest tier: $850/year individual subscriber
- Gets: Latest EMV v4.4+ with all specification bulletins
- Priority: Not needed (v4.3 from mirrors is sufficient for our EMV applet)

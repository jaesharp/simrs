#![allow(
    missing_docs,
    clippy::missing_const_for_fn,
    clippy::cast_possible_truncation
)]
//! Shared test helpers for the simrs `GlobalPlatform` BDD test suite.
//!
//! Provides GP APDU constructors, card factory functions, and response
//! parsing utilities used by the Cucumber step definitions in
//! `tests/cucumber/`.
//!
//! # Feature coverage
//!
//! | Feature file | GP Spec Clause | Crate(s) under test |
//! |--------------|----------------|---------------------|
//! | `scp01_mutual_auth` | GP 2.1.1 Appendix D | `simrs-gp-scp` |
//! | `scp02_mutual_auth` | GP 2.1.1 Appendix E | `simrs-gp-scp` |
//! | `scp_secure_messaging` | GP 2.1.1 clause 8 | `simrs-gp-scp` |
//! | `card_lifecycle` | GP 2.1.1 clause 5.1 | `simrs-gp-open` |
//! | `applet_lifecycle` | GP 2.1.1 clause 5.3 | `simrs-gp-open` |
//! | `select_by_aid` | GP 2.1.1 clause 9.9 | `simrs-gp-open` |
//! | `get_status` | GP 2.1.1 clause 9.4 | `simrs-gp-open` |
//! | `install_delete` | GP 2.1.1 clauses 9.5/9.2 | `simrs-gp-open` |

/// Default ISD AID (GP 2.1.1 typical value).
pub const ISD_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

/// Default static key set for testing (all-zero keys, key version 0x01).
pub const TEST_KEY_ENC: [u8; 16] = [0x40; 16];
pub const TEST_KEY_MAC: [u8; 16] = [0x40; 16];
pub const TEST_KEY_DEK: [u8; 16] = [0x40; 16];
pub const TEST_KEY_VERSION: u8 = 0x01;
pub const TEST_KEY_ID: u8 = 0x00;

/// GP APDU instruction constants (GP 2.1.1 Chapter 9).
pub mod gp_ins {
    pub const INITIALIZE_UPDATE: u8 = 0x50;
    pub const EXTERNAL_AUTHENTICATE: u8 = 0x82;
    pub const GET_DATA: u8 = 0xCA;
    pub const PUT_KEY: u8 = 0xD8;
    pub const STORE_DATA: u8 = 0xE2;
    pub const DELETE: u8 = 0xE4;
    pub const INSTALL: u8 = 0xE6;
    pub const LOAD: u8 = 0xE8;
    pub const SET_STATUS: u8 = 0xF0;
    pub const GET_STATUS: u8 = 0xF2;
    pub const SELECT: u8 = 0xA4;
    pub const MANAGE_CHANNEL: u8 = 0x70;
}

/// GP CLA values.
pub mod gp_cla {
    /// GP proprietary (no secure messaging).
    pub const GP: u8 = 0x80;
    /// GP proprietary with C-MAC.
    pub const GP_MAC: u8 = 0x84;
    /// Interindustry (for SELECT, MANAGE CHANNEL).
    pub const ISO: u8 = 0x00;
}

/// Card lifecycle state values (GP 2.1.1 Table 9-6).
pub mod card_lifecycle {
    pub const OP_READY: u8 = 0x01;
    pub const INITIALIZED: u8 = 0x07;
    pub const SECURED: u8 = 0x0F;
    pub const CARD_LOCKED: u8 = 0x7F;
    pub const TERMINATED: u8 = 0xFF;
}

/// Application lifecycle state values (GP 2.1.1 Table 9-4).
pub mod app_lifecycle {
    pub const INSTALLED: u8 = 0x03;
    pub const SELECTABLE: u8 = 0x07;
    pub const PERSONALIZED: u8 = 0x0F;
    pub const LOCKED: u8 = 0x83;
}

/// Security level values for EXTERNAL AUTHENTICATE P1 (GP 2.1.1 Table A-1).
pub mod security_level {
    pub const NO_SECURITY: u8 = 0x00;
    pub const C_MAC: u8 = 0x01;
    pub const C_MAC_C_ENC: u8 = 0x03;
}

/// Build a SELECT [by AID] APDU.
pub fn select_by_aid(aid: &[u8]) -> [u8; 261] {
    let mut apdu = [0u8; 261];
    apdu[0] = gp_cla::ISO; // CLA
    apdu[1] = gp_ins::SELECT; // INS
    apdu[2] = 0x04; // P1: select by name
    apdu[3] = 0x00; // P2: first occurrence
    apdu[4] = aid.len() as u8; // Lc
    apdu[5..5 + aid.len()].copy_from_slice(aid);
    apdu
}

/// Build an INITIALIZE UPDATE APDU with 8-byte host challenge.
pub fn initialize_update(key_version: u8, key_id: u8, host_challenge: &[u8; 8]) -> [u8; 13] {
    let mut apdu = [0u8; 13];
    apdu[0] = gp_cla::GP;
    apdu[1] = gp_ins::INITIALIZE_UPDATE;
    apdu[2] = key_version;
    apdu[3] = key_id;
    apdu[4] = 0x08; // Lc = 8
    apdu[5..13].copy_from_slice(host_challenge);
    apdu
}

/// Build an EXTERNAL AUTHENTICATE APDU.
pub fn external_authenticate(
    security_level: u8,
    host_cryptogram: &[u8; 8],
    c_mac: &[u8; 8],
) -> [u8; 21] {
    let mut apdu = [0u8; 21];
    apdu[0] = gp_cla::GP_MAC;
    apdu[1] = gp_ins::EXTERNAL_AUTHENTICATE;
    apdu[2] = security_level;
    apdu[3] = 0x00;
    apdu[4] = 0x10; // Lc = 16
    apdu[5..13].copy_from_slice(host_cryptogram);
    apdu[13..21].copy_from_slice(c_mac);
    apdu
}

/// Build a GET STATUS APDU (P1 determines what to query).
pub fn get_status(p2_filter: u8) -> [u8; 7] {
    let mut apdu = [0u8; 7];
    apdu[0] = gp_cla::GP_MAC;
    apdu[1] = gp_ins::GET_STATUS;
    apdu[2] = p2_filter; // 0x80=ISD, 0x40=apps, 0x20=load files
    apdu[3] = 0x00;
    apdu[4] = 0x02; // Lc = 2 (search criteria: tag 4F, length 00 = all)
    apdu[5] = 0x4F;
    apdu[6] = 0x00;
    apdu
}

/// Build a SET STATUS APDU.
pub fn set_status(scope: u8, new_state: u8, aid: &[u8]) -> [u8; 261] {
    let mut apdu = [0u8; 261];
    apdu[0] = gp_cla::GP_MAC;
    apdu[1] = gp_ins::SET_STATUS;
    apdu[2] = scope; // 0x80=ISD, 0x40=app/SD
    apdu[3] = new_state;
    apdu[4] = aid.len() as u8;
    apdu[5..5 + aid.len()].copy_from_slice(aid);
    apdu
}

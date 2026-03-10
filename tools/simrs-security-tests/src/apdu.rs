//! APDU command builder for security tests.
//!
//! Constructors produce correct-by-construction APDUs (SIM layer).
//! `.with_*()` mutation methods are interposer-style field overrides
//! for testing malformed or corrupted commands on the wire.
//!
//! # Architecture
//!
//! The SIM only produces valid commands through typed constructors.
//! The interposer mutates them. This separation mirrors
//! `simrs-interposer`'s `ShadowSim` (correct) vs `ProxyLoop` (mutate)
//! architecture.

use simrs_fs::Fid;
use simrs_iso7816::ins;
use simrs_pin::PinKey;

// ---------------------------------------------------------------------------
// Well-known identifiers
// ---------------------------------------------------------------------------

/// ADF.USIM application identifier.
pub const AID_USIM: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

/// MF file identifier.
pub const FID_MF: Fid = Fid::new(0x3F00);

/// EF.ICCID file identifier.
pub const FID_ICCID: Fid = Fid::new(0x2FE2);

/// EF.DIR file identifier.
pub const FID_DIR: Fid = Fid::new(0x2F00);

/// Non-existent FID for testing (0xFFFF).
pub const FID_NONEXISTENT: Fid = Fid::new(0xFFFF);

// ---------------------------------------------------------------------------
// Test credential constants (PIN digit strings)
// ---------------------------------------------------------------------------

/// Correct PIN1 value: "1234".
pub const PIN1_CORRECT: &str = "1234";

/// Wrong PIN1 value: "0000".
pub const PIN1_WRONG: &str = "0000";

/// Correct PUK1 value: "12345678".
pub const PUK1_CORRECT: &str = "12345678";

/// New PIN1 value (used in CHANGE/UNBLOCK): "5678".
pub const PIN1_NEW: &str = "5678";

/// Correct PIN2 value: "5678".
pub const PIN2_CORRECT: &str = "5678";

/// Correct PUK2 value: "87654321".
pub const PUK2_CORRECT: &str = "87654321";

// ---------------------------------------------------------------------------
// PIN encoding
// ---------------------------------------------------------------------------

/// Encode a PIN/PUK digit string into the 8-byte ISO format.
///
/// Each character becomes its ASCII byte value (0x30..0x39), right-padded
/// with 0xFF to fill 8 bytes. This matches ETSI TS 102 221 PIN encoding.
///
/// # Panics
///
/// Panics if `digits` is not 4..=8 ASCII digits.
pub fn encode_pin(digits: &str) -> [u8; 8] {
    assert!(
        (4..=8).contains(&digits.len()),
        "PIN must be 4-8 digits, got {} ({digits:?})",
        digits.len(),
    );
    assert!(
        digits.bytes().all(|b| b.is_ascii_digit()),
        "PIN must be ASCII digits, got {digits:?}",
    );
    let mut buf = [0xFF; 8];
    for (i, b) in digits.bytes().enumerate() {
        buf[i] = b;
    }
    buf
}

// ---------------------------------------------------------------------------
// ApduCmd
// ---------------------------------------------------------------------------

/// An APDU command with all ISO 7816-4 short-form fields.
///
/// Constructors guarantee valid structure. `.with_*()` methods are
/// interposer-style mutations that return a modified copy for security
/// testing of malformed or corrupted commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApduCmd {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Command data field.
    pub data: Vec<u8>,
    /// Expected response length (Le).
    pub le: Option<u8>,
}

impl ApduCmd {
    /// Serialize to wire format: `[CLA INS P1 P2]` `[Lc Data...]` `[Le]`.
    #[allow(clippy::cast_possible_truncation)] // short APDUs: data.len() <= 255
    pub fn build(&self) -> Vec<u8> {
        let mut buf = vec![self.cla, self.ins, self.p1, self.p2];
        if !self.data.is_empty() {
            buf.push(self.data.len() as u8);
            buf.extend_from_slice(&self.data);
        }
        if let Some(le) = self.le {
            buf.push(le);
        }
        buf
    }

    // --- Interposer mutations (return modified copy) ---

    /// Override the CLA byte.
    #[must_use]
    pub const fn with_cla(mut self, cla: u8) -> Self {
        self.cla = cla;
        self
    }

    /// Override P1.
    #[must_use]
    pub const fn with_p1(mut self, p1: u8) -> Self {
        self.p1 = p1;
        self
    }

    /// Override P2.
    #[must_use]
    pub const fn with_p2(mut self, p2: u8) -> Self {
        self.p2 = p2;
        self
    }

    /// Replace the data field entirely.
    #[must_use]
    pub fn with_data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Override Le.
    #[must_use]
    pub const fn with_le(mut self, le: u8) -> Self {
        self.le = Some(le);
        self
    }

    /// Serialize to wire format, then truncate to `len` bytes.
    ///
    /// Useful for testing the SIM's handling of truncated APDUs.
    pub fn truncated(&self, len: usize) -> Vec<u8> {
        let mut bytes = self.build();
        bytes.truncate(len);
        bytes
    }
}

// ---------------------------------------------------------------------------
// PIN command constructors (CLA=0x00, P1=0x00)
// ---------------------------------------------------------------------------

/// VERIFY PIN (INS=0x20).
///
/// # Panics
///
/// Panics if `pin` is not 4..=8 ASCII digits.
pub fn verify(key: PinKey, pin: &str) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::VERIFY,
        p1: 0x00,
        p2: key.value(),
        data: encode_pin(pin).to_vec(),
        le: None,
    }
}

/// VERIFY PIN query: empty data returns retry count (SW 63 CX).
///
/// Case 1 APDU per ETSI TS 102 221 V18.0.0 clause 11.1.9: no data, no Le.
pub const fn verify_query(key: PinKey) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::VERIFY,
        p1: 0x00,
        p2: key.value(),
        data: vec![],
        le: None,
    }
}

/// CHANGE REFERENCE DATA (INS=0x24): old PIN + new PIN.
///
/// # Panics
///
/// Panics if either PIN is not 4..=8 ASCII digits.
pub fn change_pin(key: PinKey, old_pin: &str, new_pin: &str) -> ApduCmd {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&encode_pin(old_pin));
    data.extend_from_slice(&encode_pin(new_pin));
    ApduCmd {
        cla: 0x00,
        ins: ins::CHANGE_REF_DATA,
        p1: 0x00,
        p2: key.value(),
        data,
        le: None,
    }
}

/// DISABLE VERIFICATION REQUIREMENT (INS=0x26).
///
/// # Panics
///
/// Panics if `pin` is not 4..=8 ASCII digits.
pub fn disable_pin(key: PinKey, pin: &str) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::DISABLE_PIN,
        p1: 0x00,
        p2: key.value(),
        data: encode_pin(pin).to_vec(),
        le: None,
    }
}

/// ENABLE VERIFICATION REQUIREMENT (INS=0x28).
///
/// # Panics
///
/// Panics if `pin` is not 4..=8 ASCII digits.
pub fn enable_pin(key: PinKey, pin: &str) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::ENABLE_PIN,
        p1: 0x00,
        p2: key.value(),
        data: encode_pin(pin).to_vec(),
        le: None,
    }
}

/// RESET RETRY COUNTER / UNBLOCK (INS=0x2C): PUK + new PIN.
///
/// # Panics
///
/// Panics if PUK or new PIN is not 4..=8 ASCII digits.
pub fn unblock(key: PinKey, puk: &str, new_pin: &str) -> ApduCmd {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&encode_pin(puk));
    data.extend_from_slice(&encode_pin(new_pin));
    ApduCmd {
        cla: 0x00,
        ins: ins::RESET_RETRY_CTR,
        p1: 0x00,
        p2: key.value(),
        data,
        le: None,
    }
}

/// UNBLOCK query: empty data returns PUK retry count.
///
/// Case 1 APDU per ETSI TS 102 221: no data, no Le.
pub const fn unblock_query(key: PinKey) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::RESET_RETRY_CTR,
        p1: 0x00,
        p2: key.value(),
        data: vec![],
        le: None,
    }
}

// ---------------------------------------------------------------------------
// File system command constructors
// ---------------------------------------------------------------------------

/// SELECT by File ID (P1=0x00, P2=0x04 -- return FCP).
pub fn select_fid(fid: Fid) -> ApduCmd {
    let [hi, lo] = fid.to_be_bytes();
    ApduCmd {
        cla: 0x00,
        ins: ins::SELECT,
        p1: 0x00,
        p2: 0x04,
        data: vec![hi, lo],
        le: None,
    }
}

/// SELECT by AID (P1=0x04, P2=0x04 -- return FCP).
pub fn select_aid(aid: &[u8]) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::SELECT,
        p1: 0x04,
        p2: 0x04,
        data: aid.to_vec(),
        le: None,
    }
}

/// GET RESPONSE (INS=0xC0).
pub const fn get_response(le: u8) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::GET_RESPONSE,
        p1: 0x00,
        p2: 0x00,
        data: vec![],
        le: Some(le),
    }
}

/// READ BINARY (INS=0xB0). Offset is encoded in P1:P2.
#[allow(clippy::cast_possible_truncation)] // P1:P2 encoding of 16-bit offset
pub const fn read_binary(offset: u16, le: u8) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::READ_BINARY,
        p1: (offset >> 8) as u8,
        p2: offset as u8,
        data: vec![],
        le: Some(le),
    }
}

/// UPDATE BINARY (INS=0xD6). Offset is encoded in P1:P2.
#[allow(clippy::cast_possible_truncation)] // P1:P2 encoding of 16-bit offset
pub fn update_binary(offset: u16, data: &[u8]) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::UPDATE_BINARY,
        p1: (offset >> 8) as u8,
        p2: offset as u8,
        data: data.to_vec(),
        le: None,
    }
}

/// READ RECORD (INS=0xB2). `record` = P1, `mode` = P2.
pub const fn read_record(record: u8, mode: u8, le: u8) -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::READ_RECORD,
        p1: record,
        p2: mode,
        data: vec![],
        le: Some(le),
    }
}

// ---------------------------------------------------------------------------
// Authentication command constructors
// ---------------------------------------------------------------------------

/// AUTHENTICATE UMTS context (P2=0x81): `0x10 RAND[16] 0x10 AUTN[16]`.
pub fn authenticate_umts(challenge: &[u8; 16], auth_token: &[u8; 16]) -> ApduCmd {
    let mut data = Vec::with_capacity(34);
    data.push(0x10);
    data.extend_from_slice(challenge);
    data.push(0x10);
    data.extend_from_slice(auth_token);
    ApduCmd {
        cla: 0x00,
        ins: ins::AUTHENTICATE,
        p1: 0x00,
        p2: 0x81,
        data,
        le: None,
    }
}

/// AUTHENTICATE GSM context (P2=0x00): `0x10 RAND[16]`.
pub fn authenticate_gsm(challenge: &[u8; 16]) -> ApduCmd {
    let mut data = Vec::with_capacity(17);
    data.push(0x10);
    data.extend_from_slice(challenge);
    ApduCmd {
        cla: 0x00,
        ins: ins::AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data,
        le: None,
    }
}

// ---------------------------------------------------------------------------
// GET IDENTITY command constructors (3GPP TS 31.102 clause 7.5)
// ---------------------------------------------------------------------------

/// GET IDENTITY for SUCI context (INS=0x78, P1=0x00, P2=0x01).
///
/// Per TS 31.102 V19.4.0 clause 7.5: the ME sends GET IDENTITY to request
/// SUCI computation by the USIM. P2=0x01 selects the SUCI context.
pub const fn get_identity_suci() -> ApduCmd {
    ApduCmd {
        cla: 0x00,
        ins: ins::GET_IDENTITY,
        p1: 0x00,
        p2: 0x01,
        data: vec![],
        le: None,
    }
}

// ---------------------------------------------------------------------------
// OTA / proactive command constructors (CLA=0x80)
// ---------------------------------------------------------------------------

/// TERMINAL PROFILE (CLA=0x80, INS=0x10).
pub fn terminal_profile(bitmap: &[u8]) -> ApduCmd {
    ApduCmd {
        cla: 0x80,
        ins: ins::TERMINAL_PROFILE,
        p1: 0x00,
        p2: 0x00,
        data: bitmap.to_vec(),
        le: None,
    }
}

/// ENVELOPE (CLA=0x80, INS=0xC2).
pub fn envelope(data: &[u8]) -> ApduCmd {
    ApduCmd {
        cla: 0x80,
        ins: ins::ENVELOPE,
        p1: 0x00,
        p2: 0x00,
        data: data.to_vec(),
        le: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_pin_1234() {
        assert_eq!(
            encode_pin("1234"),
            [0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn encode_pin_12345678() {
        assert_eq!(
            encode_pin("12345678"),
            [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
        );
    }

    #[test]
    #[should_panic(expected = "PIN must be 4-8 digits")]
    fn encode_pin_too_short() {
        encode_pin("12");
    }

    #[test]
    #[should_panic(expected = "PIN must be ASCII digits")]
    fn encode_pin_non_digit() {
        encode_pin("12AB");
    }

    #[test]
    fn verify_pin1_correct() {
        let cmd = verify(PinKey::PIN1, "1234").build();
        assert_eq!(
            cmd,
            [0x00, 0x20, 0x00, 0x01, 0x08,
             0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn verify_pin2() {
        let cmd = verify(PinKey::PIN2, "5678").build();
        assert_eq!(
            cmd,
            [0x00, 0x20, 0x00, 0x81, 0x08,
             0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn verify_query_pin1() {
        // Case 1 APDU: 4 bytes, no data, no Le.
        let cmd = verify_query(PinKey::PIN1).build();
        assert_eq!(cmd, [0x00, 0x20, 0x00, 0x01]);
    }

    #[test]
    fn change_pin_builds_correctly() {
        let cmd = change_pin(PinKey::PIN1, "1234", "5678").build();
        assert_eq!(
            cmd,
            [0x00, 0x24, 0x00, 0x01, 0x10,
             0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF,
             0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn unblock_builds_correctly() {
        let cmd = unblock(PinKey::PIN1, "12345678", "5678").build();
        assert_eq!(
            cmd,
            [0x00, 0x2C, 0x00, 0x01, 0x10,
             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
             0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn select_mf() {
        let cmd = select_fid(FID_MF).build();
        assert_eq!(cmd, [0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00]);
    }

    #[test]
    fn select_adf_usim() {
        let cmd = select_aid(&AID_USIM).build();
        assert_eq!(
            cmd,
            [0x00, 0xA4, 0x04, 0x04, 0x07,
             0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02],
        );
    }

    #[test]
    fn get_response_le() {
        let cmd = get_response(0x10).build();
        assert_eq!(cmd, [0x00, 0xC0, 0x00, 0x00, 0x10]);
    }

    #[test]
    fn read_binary_offset() {
        let cmd = read_binary(9, 1).build();
        assert_eq!(cmd, [0x00, 0xB0, 0x00, 0x09, 0x01]);
    }

    #[test]
    fn authenticate_umts_builds_correctly() {
        let challenge = [0xAA; 16];
        let auth_token = [0xBB; 16];
        let cmd = authenticate_umts(&challenge, &auth_token).build();
        assert_eq!(cmd.len(), 4 + 1 + 34); // header + Lc + data
        assert_eq!(cmd[0..5], [0x00, 0x88, 0x00, 0x81, 0x22]);
        assert_eq!(cmd[5], 0x10); // RAND length prefix
        assert_eq!(cmd[22], 0x10); // AUTN length prefix
    }

    #[test]
    fn terminal_profile_builds_correctly() {
        let cmd = terminal_profile(&[0xFF; 4]).build();
        assert_eq!(cmd, [0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn envelope_builds_correctly() {
        let cmd = envelope(&[0xD1, 0x00]).build();
        assert_eq!(cmd, [0x80, 0xC2, 0x00, 0x00, 0x02, 0xD1, 0x00]);
    }

    // --- Interposer mutation tests ---

    #[test]
    fn with_p1_mutation() {
        let base = verify(PinKey::PIN1, "1234");
        let mutated = base.with_p1(0x01).build();
        assert_eq!(mutated[2], 0x01); // P1 changed
        assert_eq!(mutated[3], 0x01); // P2 unchanged (PIN1)
    }

    #[test]
    fn with_p2_mutation() {
        let base = verify(PinKey::PIN1, "1234");
        let mutated = base.with_p2(0xFF).build();
        assert_eq!(mutated[3], 0xFF); // P2 changed to unregistered
    }

    #[test]
    fn with_cla_mutation() {
        let base = verify(PinKey::PIN1, "1234");
        let mutated = base.with_cla(0xF0).build();
        assert_eq!(mutated[0], 0xF0); // CLA changed
    }

    #[test]
    fn with_data_wrong_length() {
        let base = verify(PinKey::PIN1, "1234");
        let mutated = base.with_data(&[0x31, 0x32, 0x33, 0x34, 0xFF]).build();
        assert_eq!(mutated.len(), 4 + 1 + 5); // 5 bytes instead of 8
        assert_eq!(mutated[4], 0x05); // Lc = 5
    }

    #[test]
    fn truncated_to_3_bytes() {
        let base = verify(PinKey::PIN1, "1234");
        let truncated = base.truncated(3);
        assert_eq!(truncated.len(), 3);
        assert_eq!(truncated, [0x00, 0x20, 0x00]);
    }
}

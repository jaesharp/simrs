//! Multi-APDU integration tests.
//!
//! Tests exercise end-to-end flows through the full stack:
//! `Sim -> GsmApp/UsimApp -> PinManager/Fs/Milenage/Proactive`.
//!
//! Most tests use `Sim::process()` directly for response-dependent
//! multi-step flows. A few bridge-level tests validate the full
//! shmem path using `QemuBridge` with push-all/step-all/pop-all.

use simrs_fs::{AdfSlot, DfDef, EfDef, Fid, FileRef, Sfi};
use simrs_gsm::GsmApp;
use simrs_milenage::{
    AuthChallenge, AuthManagementField, MilenageParams, OperatorVariant, SequenceNumber,
    SubscriberKey,
};
use simrs_pin::{PinKey, PinValue};
use simrs_proactive::{ProactiveCommand, TextCoding};
use simrs_qemu::{QemuBridge, QemuBridgeError, ShmemMsgType};
use simrs_sim::{Sim, SimEvent, SimResponse};
use simrs_transport_shmem::{HEADER_SIZE, ShmemHeader, ring_read, ring_write};
use simrs_usim::UsimApp;

// ---------------------------------------------------------------------------
// Test filesystem
// ---------------------------------------------------------------------------

static ICCID_DATA: [u8; 10] = [0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0];

static EF_ICCID: EfDef = EfDef::transparent(Fid::new(0x2FE2), Some(Sfi::new(2)), &ICCID_DATA);

static EF_DIR_DATA: [u8; 16] = [
    0x61, 0x06, 0x4F, 0x04, 0xA0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

static EF_DIR: EfDef =
    EfDef::linear_fixed(Fid::new(0x2F00), Some(Sfi::new(30)), 8, 2, &EF_DIR_DATA);

static IMSI_DATA: [u8; 9] = [0x08, 0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0];

static EF_IMSI: EfDef = EfDef::transparent(Fid::new(0x6F07), Some(Sfi::new(7)), &IMSI_DATA);

static EF_KC: EfDef = EfDef::transparent(Fid::new(0x6F20), None, &[0xFF; 9]);

static DF_GSM: DfDef = DfDef {
    fid: Fid::new(0x7F20),
    children: &[FileRef::Ef(&EF_IMSI), FileRef::Ef(&EF_KC)],
};

// USIM ADF.
static EF_USIM_IMSI: EfDef = EfDef::transparent(Fid::new(0x6F07), Some(Sfi::new(7)), &IMSI_DATA);

static EF_UST: EfDef = EfDef::transparent(Fid::new(0x6F38), None, &[0xFF, 0xFF, 0xFF, 0xFF]);

static ADF_USIM_ROOT: DfDef = DfDef {
    fid: Fid::new(0xFF01),
    children: &[FileRef::Ef(&EF_USIM_IMSI), FileRef::Ef(&EF_UST)],
};

static USIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

static ADF_TABLE: [AdfSlot; 1] = [AdfSlot {
    aid: &USIM_AID,
    root: &ADF_USIM_ROOT,
}];

static MF: DfDef = DfDef {
    fid: Fid::new(0x3F00),
    children: &[
        FileRef::Ef(&EF_ICCID),
        FileRef::Ef(&EF_DIR),
        FileRef::Df(&DF_GSM),
    ],
};

static ATR: [u8; 4] = [0x3B, 0x9F, 0x96, 0x80];

static KI: simrs_gsm::SubscriberKey = simrs_gsm::SubscriberKey::classify([
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
]);

// ETSI TS 135 208 Test Set 1.
static USIM_K: SubscriberKey = SubscriberKey::classify([
    0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6, 0xBC,
]);
static USIM_OPC: OperatorVariant = OperatorVariant::operator_cipher([
    0xCD, 0x63, 0xCB, 0x71, 0x95, 0x4A, 0x9F, 0x4E, 0x48, 0xA5, 0x99, 0x4E, 0x37, 0xA0, 0x2B, 0xAF,
]);

static PIN_VAL: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF];
static PUK_VAL: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];

// ---------------------------------------------------------------------------
// Sim-level helpers
// ---------------------------------------------------------------------------

fn make_sim() -> Sim<MilenageParams, 256> {
    let mut gsm = GsmApp::new(&MF, KI);
    let pin = PinValue::new(PIN_VAL);
    let puk = PinValue::new(PUK_VAL);
    gsm.pin_manager()
        .add_pin(PinKey::PIN1, &pin, 3, &puk, 10, true)
        .unwrap();
    let _ = gsm.pin_manager().verify(PinKey::PIN1, &pin);

    let mil = MilenageParams::with_defaults(USIM_K, USIM_OPC);
    let mut usim = UsimApp::new(&MF, &ADF_TABLE, mil);
    let pin2 = PinValue::new(PIN_VAL);
    let puk2 = PinValue::new(PUK_VAL);
    usim.pin_manager()
        .add_pin(PinKey::PIN1, &pin2, 3, &puk2, 10, true)
        .unwrap();
    let _ = usim.pin_manager().verify(PinKey::PIN1, &pin2);

    Sim::<MilenageParams, 256>::new(&ATR, gsm, usim)
}

/// Send an APDU and return (sw1, sw2, data).
fn send(sim: &mut Sim<MilenageParams, 256>, apdu: &[u8]) -> (u8, u8, Vec<u8>) {
    match sim.process(SimEvent::Apdu(apdu)) {
        SimResponse::Apdu { data, sw } => {
            let [sw1, sw2] = sw.to_bytes();
            (sw1, sw2, data.to_vec())
        }
        SimResponse::Ignored => panic!("APDU was ignored"),
        SimResponse::Atr(_) => panic!("unexpected ATR response to APDU"),
    }
}

// ---------------------------------------------------------------------------
// Shmem bridge helpers
// ---------------------------------------------------------------------------

const RING_SIZE: u32 = 1024;
const MSG_MAX: usize = 262;
const HDR_CMD_HEAD: usize = 12;
const HDR_CMD_TAIL: usize = 16;
const HDR_RSP_HEAD: usize = 20;
const HDR_RSP_TAIL: usize = 24;

const fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn make_shmem() -> Vec<u8> {
    let hdr = ShmemHeader::new(RING_SIZE);
    let mut buf = vec![0u8; hdr.total_size()];
    hdr.encode(&mut buf).unwrap();
    buf
}

fn push_cmd(shmem: &mut [u8], msg_type: ShmemMsgType, payload: &[u8]) {
    let mut msg = vec![msg_type as u8];
    msg.extend_from_slice(payload);
    let ring_start = HEADER_SIZE;
    let ring_end = ring_start + RING_SIZE as usize;
    let head = read_u32_le(shmem, HDR_CMD_HEAD);
    let tail = read_u32_le(shmem, HDR_CMD_TAIL);
    let new_head = ring_write(
        &mut shmem[ring_start..ring_end],
        head,
        tail,
        RING_SIZE,
        &msg,
    )
    .expect("ring_write failed");
    write_u32_le(shmem, HDR_CMD_HEAD, new_head);
}

fn pop_rsp(shmem: &mut [u8]) -> Option<(ShmemMsgType, Vec<u8>)> {
    let ring_start = HEADER_SIZE + RING_SIZE as usize;
    let ring_end = ring_start + RING_SIZE as usize;
    let head = read_u32_le(shmem, HDR_RSP_HEAD);
    let tail = read_u32_le(shmem, HDR_RSP_TAIL);
    let mut out = [0u8; MSG_MAX];
    let (new_tail, len) = ring_read(
        &shmem[ring_start..ring_end],
        head,
        tail,
        RING_SIZE,
        &mut out,
    )?;
    write_u32_le(shmem, HDR_RSP_TAIL, new_tail);
    let msg_type = ShmemMsgType::from_u8(out[0])?;
    Some((msg_type, out[1..len].to_vec()))
}

// =========================================================================
// Multi-APDU integration tests (via Sim::process directly)
// =========================================================================

#[test]
fn gsm_select_verify_read_imsi() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT DF.GSM.
    let (sw1, _sw2, _) = send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
    assert_eq!(sw1, 0x9F);

    // GET RESPONSE (23 bytes for DF).
    let (sw1, _sw2, data) = send(&mut sim, &[0xA0, 0xC0, 0x00, 0x00, 0x17]);
    assert_eq!(sw1, 0x90);
    assert_eq!(data.len(), 23);

    // SELECT EF.IMSI.
    let (sw1, _sw2, _) = send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07]);
    assert_eq!(sw1, 0x9F);

    // VERIFY PIN1 ("1234").
    let mut verify = [0u8; 13];
    verify[0] = 0xA0;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&PIN_VAL);
    let (sw1, sw2, _) = send(&mut sim, &verify);
    assert_eq!((sw1, sw2), (0x90, 0x00));

    // READ BINARY (9 bytes IMSI).
    let (sw1, sw2, data) = send(&mut sim, &[0xA0, 0xB0, 0x00, 0x00, 0x09]);
    assert_eq!((sw1, sw2), (0x90, 0x00));
    assert_eq!(data, &IMSI_DATA);
}

#[test]
fn gsm_run_gsm_algorithm_comp128() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT DF.GSM + VERIFY PIN.
    send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
    let mut verify = [0u8; 13];
    verify[0] = 0xA0;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&PIN_VAL);
    send(&mut sim, &verify);

    // RUN GSM ALGORITHM.
    let rand_val = [0x01u8; 16];
    let mut run_algo = [0u8; 21];
    run_algo[0] = 0xA0;
    run_algo[1] = 0x88;
    run_algo[4] = 0x10;
    run_algo[5..21].copy_from_slice(&rand_val);
    let (sw1, sw2, _) = send(&mut sim, &run_algo);
    assert_eq!(sw1, 0x9F);
    assert_eq!(sw2, 0x0C);

    // GET RESPONSE -> SRES(4) + Kc(8).
    let (sw1, sw2, data) = send(&mut sim, &[0xA0, 0xC0, 0x00, 0x00, 0x0C]);
    assert_eq!((sw1, sw2), (0x90, 0x00));
    assert_eq!(data.len(), 12);

    // Verify against independent COMP128 computation.
    let result = simrs_comp128::comp128(KI.as_secret(), &rand_val);
    assert_eq!(&data[..4], result.signed_response.as_bytes());
    assert_eq!(&data[4..12], result.cipher_key.declassify_ref());
}

#[test]
fn usim_select_aid_and_authenticate() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT ADF.USIM by AID.
    let mut select_aid = [0u8; 12];
    select_aid[0] = 0x00;
    select_aid[1] = 0xA4;
    select_aid[2] = 0x04;
    select_aid[3] = 0x04;
    select_aid[4] = 0x07;
    select_aid[5..12].copy_from_slice(&USIM_AID);
    let (sw1, sw2, _) = send(&mut sim, &select_aid);
    assert_eq!(sw1, 0x61);
    let fcp_len = sw2;

    // GET RESPONSE -> FCP.
    let (sw1, _sw2, fcp) = send(&mut sim, &[0x00, 0xC0, 0x00, 0x00, fcp_len]);
    assert_eq!(sw1, 0x90);
    assert_eq!(fcp[0], 0x62); // FCP template tag.

    // Build AUTHENTICATE with ETSI TS 135 208 Test Set 1.
    let rand_val: [u8; 16] = [
        0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D, 0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF,
        0x35,
    ];
    let params = MilenageParams::with_defaults(USIM_K, USIM_OPC);
    let challenge = AuthChallenge::new(rand_val);
    let sequence_number = SequenceNumber::new([0xFF, 0x9B, 0xB4, 0xD0, 0xB6, 0x07]);
    let management_field = AuthManagementField::new([0xB9, 0xB9]);
    let anonymity_key = params.compute_anonymity_key(&challenge);
    let auth_mac = params.compute_auth_mac(&challenge, &sequence_number, &management_field);

    let mut auth_token = [0u8; 16];
    for (dst, (s, a)) in auth_token[..6].iter_mut().zip(
        sequence_number
            .as_bytes()
            .iter()
            .zip(anonymity_key.as_bytes()),
    ) {
        *dst = s ^ a;
    }
    auth_token[6..8].copy_from_slice(management_field.as_bytes());
    auth_token[8..16].copy_from_slice(auth_mac.as_bytes());

    let mut auth_cmd = [0u8; 39];
    auth_cmd[0] = 0x00;
    auth_cmd[1] = 0x88;
    auth_cmd[3] = 0x81;
    auth_cmd[4] = 0x22;
    auth_cmd[5] = 0x10;
    auth_cmd[6..22].copy_from_slice(&rand_val);
    auth_cmd[22] = 0x10;
    auth_cmd[23..39].copy_from_slice(&auth_token);

    let (sw1, sw2, _) = send(&mut sim, &auth_cmd);
    assert_eq!(sw1, 0x61);
    let auth_len = sw2;

    // GET RESPONSE -> DB tag, RES, CK, IK.
    let (sw1, sw2, data) = send(&mut sim, &[0x00, 0xC0, 0x00, 0x00, auth_len]);
    assert_eq!((sw1, sw2), (0x90, 0x00));
    assert_eq!(data[0], 0xDB);

    // Verify RES = f2(RAND).
    let expected_response = params.compute_response(&challenge);
    assert_eq!(&data[3..11], expected_response.as_bytes());

    // Verify CK = f3(RAND).
    let cipher_key = params.compute_cipher_key(&challenge);
    assert_eq!(&data[12..28], cipher_key.declassify().as_slice());

    // Verify IK = f4(RAND).
    let integrity_key = params.compute_integrity_key(&challenge);
    assert_eq!(&data[29..45], integrity_key.declassify().as_slice());
}

#[test]
fn usim_authenticate_mac_failure() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT ADF.USIM.
    let mut select_aid = [0u8; 12];
    select_aid[0] = 0x00;
    select_aid[1] = 0xA4;
    select_aid[2] = 0x04;
    select_aid[3] = 0x04;
    select_aid[4] = 0x07;
    select_aid[5..12].copy_from_slice(&USIM_AID);
    send(&mut sim, &select_aid);

    // AUTHENTICATE with garbage AUTN.
    let mut auth = [0u8; 39];
    auth[0] = 0x00;
    auth[1] = 0x88;
    auth[3] = 0x81;
    auth[4] = 0x22;
    auth[5] = 0x10;
    auth[22] = 0x10;
    // RAND and AUTN are all zeros -> invalid MAC.

    let (sw1, sw2, _) = send(&mut sim, &auth);
    assert_eq!((sw1, sw2), (0x98, 0x62));
}

#[test]
fn gsm_pin_block_unblock_repin() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT DF.GSM.
    send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);

    let wrong: [u8; 8] = [0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut verify = [0u8; 13];
    verify[0] = 0xA0;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&wrong);

    // 3 wrong attempts -> blocked.
    let (sw1, sw2, _) = send(&mut sim, &verify);
    assert_eq!((sw1, sw2 & 0x0F), (0x63, 2));
    let (sw1, sw2, _) = send(&mut sim, &verify);
    assert_eq!((sw1, sw2 & 0x0F), (0x63, 1));
    let (sw1, sw2, _) = send(&mut sim, &verify);
    assert_eq!((sw1, sw2 & 0x0F), (0x63, 0));

    // UNBLOCK (INS=0x2C, data = PUK + new PIN).
    let new_pin: [u8; 8] = [0x35, 0x36, 0x37, 0x38, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut unblock = [0u8; 21];
    unblock[0] = 0xA0;
    unblock[1] = 0x2C;
    unblock[3] = 0x01;
    unblock[4] = 0x10;
    unblock[5..13].copy_from_slice(&PUK_VAL);
    unblock[13..21].copy_from_slice(&new_pin);
    let (sw1, sw2, _) = send(&mut sim, &unblock);
    assert_eq!((sw1, sw2), (0x90, 0x00));

    // VERIFY with new PIN.
    verify[5..13].copy_from_slice(&new_pin);
    let (sw1, sw2, _) = send(&mut sim, &verify);
    assert_eq!((sw1, sw2), (0x90, 0x00));
}

#[test]
fn warm_reset_clears_session_state() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT DF.GSM + VERIFY PIN.
    send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);
    let mut verify = [0u8; 13];
    verify[0] = 0xA0;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&PIN_VAL);
    let (sw1, sw2, _) = send(&mut sim, &verify);
    assert_eq!((sw1, sw2), (0x90, 0x00));

    // Warm reset.
    match sim.process(SimEvent::Reset) {
        SimResponse::Atr(atr) => assert_eq!(atr, &ATR),
        _ => panic!("expected ATR from reset"),
    }

    // After reset the card is powered, SELECT MF should work.
    let (sw1, _sw2, _) = send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
    assert_eq!(sw1, 0x9F);
}

#[test]
fn unsupported_cla_returns_6e00() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    let (sw1, sw2, _) = send(&mut sim, &[0xF0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00]);
    assert_eq!((sw1, sw2), (0x6E, 0x00));
}

#[test]
fn gsm_read_record_linear_fixed() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT EF.DIR (2F00).
    let (sw1, _sw2, _) = send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0x00]);
    assert_eq!(sw1, 0x9F);

    // VERIFY PIN.
    let mut verify = [0u8; 13];
    verify[0] = 0xA0;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&PIN_VAL);
    send(&mut sim, &verify);

    // READ RECORD 1 (absolute mode, 8 bytes).
    let (sw1, sw2, data) = send(&mut sim, &[0xA0, 0xB2, 0x01, 0x04, 0x08]);
    assert_eq!((sw1, sw2), (0x90, 0x00));
    assert_eq!(data.len(), 8);
    assert_eq!(&data, &EF_DIR_DATA[..8]);
}

#[test]
fn gsm_status_returns_current_df() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // SELECT DF.GSM.
    send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20]);

    // STATUS (INS=0xF2) returns data inline with 90 00.
    let (sw1, sw2, data) = send(&mut sim, &[0xA0, 0xF2, 0x00, 0x00, 0x17]);
    assert_eq!((sw1, sw2), (0x90, 0x00));
    assert_eq!(data.len(), 0x17);
    // Byte 4-5 = DF.GSM FID (7F20).
    assert_eq!(data[4], 0x7F);
    assert_eq!(data[5], 0x20);
}

#[test]
fn usim_proactive_display_text_cycle() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // Queue proactive command.
    let text = b"Hello";
    let cmd = ProactiveCommand::DisplayText {
        text,
        coding: TextCoding::Gsm8Bit,
        high_priority: false,
    };
    sim.usim_app_mut()
        .proactive_state()
        .queue_command(&cmd)
        .unwrap();

    // SELECT ADF.USIM.
    let mut select_aid = [0u8; 12];
    select_aid[0] = 0x00;
    select_aid[1] = 0xA4;
    select_aid[2] = 0x04;
    select_aid[3] = 0x04;
    select_aid[4] = 0x07;
    select_aid[5..12].copy_from_slice(&USIM_AID);
    send(&mut sim, &select_aid);

    // TERMINAL PROFILE -> should return 91 XX (proactive pending).
    let (sw1, sw2, _) = send(
        &mut sim,
        &[0x80, 0x10, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF],
    );
    assert_eq!(sw1, 0x91);
    let fetch_len = sw2;

    // FETCH proactive command.
    let (sw1, sw2, data) = send(&mut sim, &[0x80, 0x12, 0x00, 0x00, fetch_len]);
    assert_eq!((sw1, sw2), (0x90, 0x00));
    assert_eq!(data[0], 0xD0); // Proactive command envelope.

    // TERMINAL RESPONSE.
    let (sw1, sw2, _) = send(&mut sim, &[0x80, 0x14, 0x00, 0x00, 0x02, 0x00, 0x00]);
    assert_eq!((sw1, sw2), (0x90, 0x00));
}

#[test]
fn usim_verify_pin_correct_and_wrong() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // Correct PIN (CLA=0x00 for USIM).
    let mut verify = [0u8; 13];
    verify[0] = 0x00;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&PIN_VAL);
    let (sw1, sw2, _) = send(&mut sim, &verify);
    assert_eq!((sw1, sw2), (0x90, 0x00));

    // Wrong PIN.
    let wrong: [u8; 8] = [0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF];
    verify[5..13].copy_from_slice(&wrong);
    let (sw1, _sw2, _) = send(&mut sim, &verify);
    assert_eq!(sw1, 0x63);
}

#[test]
fn multiple_select_read_cycles_consistent() {
    let mut sim = make_sim();
    let _ = sim.process(SimEvent::PowerOn);

    // VERIFY PIN.
    let mut verify = [0u8; 13];
    verify[0] = 0xA0;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&PIN_VAL);
    send(&mut sim, &verify);

    for _ in 0..5 {
        send(&mut sim, &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x2F, 0xE2]);
        let (sw1, sw2, data) = send(&mut sim, &[0xA0, 0xB0, 0x00, 0x00, 0x0A]);
        assert_eq!((sw1, sw2), (0x90, 0x00));
        assert_eq!(data, &ICCID_DATA);
    }
}

// =========================================================================
// QemuBridge end-to-end tests (push-all / step-all / pop-all)
// =========================================================================

#[test]
fn bridge_gsm_auth_flow() {
    let mut shmem = make_shmem();
    let select_gsm = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20];
    let mut verify = [0u8; 13];
    verify[0] = 0xA0;
    verify[1] = 0x20;
    verify[3] = 0x01;
    verify[4] = 0x08;
    verify[5..13].copy_from_slice(&PIN_VAL);
    let select_imsi = [0xA0, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x07];
    let read_binary = [0xA0, 0xB0, 0x00, 0x00, 0x09];

    // Push all commands upfront.
    push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);
    push_cmd(&mut shmem, ShmemMsgType::Apdu, &select_gsm);
    push_cmd(&mut shmem, ShmemMsgType::Apdu, &verify);
    push_cmd(&mut shmem, ShmemMsgType::Apdu, &select_imsi);
    push_cmd(&mut shmem, ShmemMsgType::Apdu, &read_binary);

    // Step through all.
    {
        let sim = make_sim();
        let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
        for _ in 0..5 {
            assert!(bridge.step().unwrap());
        }
        assert!(!bridge.step().unwrap()); // Empty.
    }

    // Pop and verify responses.
    let (mt, atr) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Atr);
    assert_eq!(atr, &ATR);

    let (mt, rsp) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Apdu);
    assert_eq!(rsp[rsp.len() - 2], 0x9F); // SELECT DF.GSM -> response available.

    let (mt, rsp) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Apdu);
    assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]); // VERIFY PIN success.

    let (mt, rsp) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Apdu);
    assert_eq!(rsp[rsp.len() - 2], 0x9F); // SELECT EF.IMSI -> response available.

    let (mt, rsp) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Apdu);
    assert_eq!(&rsp[rsp.len() - 2..], &[0x90, 0x00]); // READ BINARY success.
    assert_eq!(&rsp[..9], &IMSI_DATA);

    assert!(pop_rsp(&mut shmem).is_none());
}

#[test]
fn bridge_power_cycle_and_reset() {
    let mut shmem = make_shmem();

    push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);
    push_cmd(
        &mut shmem,
        ShmemMsgType::Apdu,
        &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x20],
    );
    push_cmd(&mut shmem, ShmemMsgType::WarmReset, &[]);
    push_cmd(
        &mut shmem,
        ShmemMsgType::Apdu,
        &[0xA0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00],
    );
    push_cmd(&mut shmem, ShmemMsgType::PowerOff, &[]);
    push_cmd(&mut shmem, ShmemMsgType::PowerOn, &[]);

    {
        let sim = make_sim();
        let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
        for _ in 0..6 {
            assert!(bridge.step().unwrap());
        }
        assert!(!bridge.step().unwrap());
    }

    // ATR from first PowerOn.
    let (mt, _) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Atr);

    // SELECT response.
    let (mt, _) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Apdu);

    // ATR from WarmReset.
    let (mt, _) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Atr);

    // SELECT MF after reset.
    let (mt, rsp) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Apdu);
    assert_eq!(rsp[rsp.len() - 2], 0x9F); // SELECT MF -> response available.

    // PowerOff -> no response.
    // Second PowerOn -> ATR.
    let (mt, _) = pop_rsp(&mut shmem).unwrap();
    assert_eq!(mt, ShmemMsgType::Atr);

    assert!(pop_rsp(&mut shmem).is_none());
}

#[test]
fn bridge_atr_in_cmd_ring_is_error() {
    let mut shmem = make_shmem();
    push_cmd(&mut shmem, ShmemMsgType::Atr, &[0x3B, 0x00]);

    let sim = make_sim();
    let mut bridge = QemuBridge::new(sim, &mut shmem).unwrap();
    let err = bridge.step().unwrap_err();
    assert_eq!(err, QemuBridgeError::InvalidMessage);
}

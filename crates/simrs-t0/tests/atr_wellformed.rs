//! Regression test guarding the shape of `simrs_card_api::DEFAULT_ATR`.

use simrs_card_api::DEFAULT_ATR;
use simrs_t0::Atr;

#[test]
fn default_atr_parses() {
    let atr = Atr::parse(&DEFAULT_ATR).expect("DEFAULT_ATR must parse as a valid ATR");
    let declared_k = (DEFAULT_ATR[1] & 0x0F) as usize;
    assert_eq!(
        atr.historical_bytes().len(),
        declared_k,
        "K nibble of T0 (=={declared_k}) must match the actual historical byte count"
    );
    assert!(atr.is_well_formed());
}

#[test]
fn default_atr_declares_t0_only() {
    let atr = Atr::parse(&DEFAULT_ATR).unwrap();
    assert!(atr.t0_supported(), "DEFAULT_ATR must indicate T=0 support");
    assert!(
        !atr.t1_indicated(),
        "DEFAULT_ATR must not indicate T=1; simtrace2 firmware only supports T=0"
    );
}

#[test]
fn default_atr_uses_direct_convention() {
    let atr = Atr::parse(&DEFAULT_ATR).unwrap();
    assert_eq!(
        atr.convention(),
        simrs_t0::Convention::Direct,
        "TS byte must be 0x3B (direct convention)"
    );
}

//! In-process APDU-aware fuzzer for the simrs SIM simulator.
//!
//! Structure-aware APDU mutation + snapshot-based state deduplication.
//! Runs entirely in-process via simrs-hle (no QEMU required).
//!
//! Configurable via `SIMRS_FUZZ_ITERS` env var (default 100,000).

use simrs_fs::{DfDef, EfDef, EfStructure, FileRef};
use simrs_hle::{hle_apdu, hle_init, hle_reset, hle_snapshot_restore, hle_snapshot_save, hle_state_hash};
use simrs_sim::Sim;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Test filesystem
// ---------------------------------------------------------------------------

static EF_ICCID: EfDef = EfDef {
    fid: 0x2FE2,
    sfi: None,
    structure: EfStructure::Transparent,
    data: &[0x98, 0x10, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0],
};

static EF_IMSI: EfDef = EfDef {
    fid: 0x6F07,
    sfi: Some(7),
    structure: EfStructure::Transparent,
    data: &[0x08, 0x09, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0xF0],
};

static DF_GSM: DfDef = DfDef {
    fid: 0x7F20,
    children: &[FileRef::Ef(&EF_IMSI)],
};

static MF: DfDef = DfDef {
    fid: 0x3F00,
    children: &[FileRef::Ef(&EF_ICCID), FileRef::Df(&DF_GSM)],
};

static ATR: [u8; 2] = [0x3B, 0x00];

// ---------------------------------------------------------------------------
// FNV-1a hash
// ---------------------------------------------------------------------------

/// Compute FNV-1a 64-bit hash.
fn fnv1a(data: &[u8]) -> u64 {
    const BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = BASIS;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// Xorshift64 PRNG
// ---------------------------------------------------------------------------

struct Rng {
    state: u64,
}

impl Rng {
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    const fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    const fn next_u8(&mut self) -> u8 {
        #[allow(clippy::cast_possible_truncation)]
        { (self.next() & 0xFF) as u8 }
    }

    const fn range(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation)]
        { (self.next() as usize) % max }
    }
}

// ---------------------------------------------------------------------------
// APDU mutator
// ---------------------------------------------------------------------------

/// Known INS values that reach deep code paths.
const KNOWN_INS: &[u8] = &[
    0xA4, // SELECT
    0xC0, // GET RESPONSE
    0xB0, // READ BINARY
    0xB2, // READ RECORD
    0xF2, // STATUS
    0x88, // AUTHENTICATE / RUN GSM ALGO
    0x20, // VERIFY
    0x2C, // UNBLOCK / RESET RETRY CTR
    0x10, // TERMINAL PROFILE
    0x12, // FETCH
    0x14, // TERMINAL RESPONSE
    0xC2, // ENVELOPE
];

/// Known CLA values.
const KNOWN_CLA: &[u8] = &[0x00, 0x80, 0xA0];

/// Generate a structure-aware APDU.
fn generate_apdu(rng: &mut Rng, buf: &mut [u8]) -> usize {
    let cla = KNOWN_CLA[rng.range(KNOWN_CLA.len())];
    let ins = if rng.next().is_multiple_of(4) {
        rng.next_u8()
    } else {
        KNOWN_INS[rng.range(KNOWN_INS.len())]
    };
    let p1 = if rng.next().is_multiple_of(3) { rng.next_u8() } else { 0x00 };
    let p2 = if rng.next().is_multiple_of(3) {
        rng.next_u8()
    } else {
        // Common P2 values.
        [0x00, 0x04, 0x81][rng.range(3)]
    };

    buf[0] = cla;
    buf[1] = ins;
    buf[2] = p1;
    buf[3] = p2;

    // Decide on data presence.
    let has_data = !rng.next().is_multiple_of(3);
    if has_data {
        let lc = match ins {
            0xA4 => 2,                                   // SELECT FID
            0x20 => 8,                                   // VERIFY PIN
            0x2C => 16,                                  // UNBLOCK
            0x88 if cla == 0xA0 => 16,                   // RUN GSM ALGO
            0x88 => 34,                                   // AUTHENTICATE
            _ => rng.range(16).min(buf.len().saturating_sub(5)),
        };
        #[allow(clippy::cast_possible_truncation)]
        {
            buf[4] = lc as u8;
        }
        for i in 0..lc {
            buf[5 + i] = rng.next_u8();
        }
        5 + lc
    } else {
        // Case 1 or Case 2: optional Le.
        if rng.next().is_multiple_of(2) {
            buf[4] = rng.next_u8();
            5
        } else {
            4
        }
    }
}

/// Mutate an existing APDU in-place.
fn mutate_apdu(rng: &mut Rng, buf: &mut [u8], len: usize) -> usize {
    if len < 4 {
        return generate_apdu(rng, buf);
    }
    match rng.range(4) {
        0 => {
            // Flip a random byte.
            let idx = rng.range(len);
            buf[idx] ^= 1 << rng.range(8);
            len
        }
        1 => {
            // Replace INS with a known one.
            buf[1] = KNOWN_INS[rng.range(KNOWN_INS.len())];
            len
        }
        2 => {
            // Replace CLA.
            buf[0] = KNOWN_CLA[rng.range(KNOWN_CLA.len())];
            len
        }
        _ => {
            // Generate fresh.
            generate_apdu(rng, buf)
        }
    }
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

struct Corpus {
    /// Set of state hashes seen.
    seen: HashSet<u64>,
    /// Number of interesting sequences found.
    interesting: usize,
}

impl Corpus {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
            interesting: 0,
        }
    }

    /// Returns `true` if this hash is new (the sequence is interesting).
    fn is_new(&mut self, hash: u64) -> bool {
        if self.seen.insert(hash) {
            self.interesting += 1;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let iters: usize = std::env::var("SIMRS_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    eprintln!("[simrs-fuzz] initializing SIM...");
    hle_init(&ATR, &MF, [0x11; 16], [0x22; 16], [0x33; 16]);
    hle_reset();

    // Take initial snapshot.
    let snap_size = Sim::<256>::SNAPSHOT_SIZE;
    let mut snapshot = vec![0u8; snap_size];
    let n = hle_snapshot_save(&mut snapshot);
    assert_eq!(n, snap_size, "initial snapshot failed");

    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_BABE);
    let mut corpus = Corpus::new();
    let mut apdu_buf = [0u8; 261];
    let mut rsp_buf = [0u8; 261];
    let seq_len_max = 8;

    eprintln!("[simrs-fuzz] fuzzing {iters} iterations...");

    for i in 0..iters {
        // Restore snapshot.
        assert!(
            hle_snapshot_restore(&snapshot[..n]),
            "snapshot restore failed at iter {i}"
        );

        // Generate/mutate an APDU sequence.
        let seq_len = 1 + rng.range(seq_len_max);
        let mut combined_hash: u64 = 0;

        for _ in 0..seq_len {
            let apdu_len = if rng.next().is_multiple_of(2) {
                generate_apdu(&mut rng, &mut apdu_buf)
            } else {
                let base_len = generate_apdu(&mut rng, &mut apdu_buf);
                mutate_apdu(&mut rng, &mut apdu_buf, base_len)
            };

            let _ = hle_apdu(&apdu_buf[..apdu_len], &mut rsp_buf);

            // Hash the APDU for sequence tracking.
            combined_hash = combined_hash.wrapping_add(fnv1a(&apdu_buf[..apdu_len]));
        }

        // Collect state hash after the sequence, combined with APDU path hash.
        let state_hash = hle_state_hash();
        if state_hash != 0 {
            corpus.is_new(state_hash.wrapping_add(combined_hash));
        }
    }

    eprintln!(
        "[simrs-fuzz] done: {iters} iterations, {} unique states, {} corpus entries",
        corpus.seen.len(),
        corpus.interesting,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_deterministic() {
        let data = b"hello";
        assert_eq!(fnv1a(data), fnv1a(data));
    }

    #[test]
    fn fnv1a_different_inputs_different_hashes() {
        assert_ne!(fnv1a(b"hello"), fnv1a(b"world"));
    }

    #[test]
    fn rng_produces_different_values() {
        let mut rng = Rng::new(42);
        let a = rng.next();
        let b = rng.next();
        assert_ne!(a, b);
    }

    #[test]
    fn generate_apdu_produces_valid_length() {
        let mut rng = Rng::new(123);
        let mut buf = [0u8; 261];
        for _ in 0..100 {
            let len = generate_apdu(&mut rng, &mut buf);
            assert!(len >= 4, "APDU too short: {len}");
            assert!(len <= 261, "APDU too long: {len}");
        }
    }

    #[test]
    fn corpus_dedup() {
        let mut corpus = Corpus::new();
        assert!(corpus.is_new(1));
        assert!(corpus.is_new(2));
        assert!(!corpus.is_new(1)); // duplicate
        assert_eq!(corpus.interesting, 2);
    }

    #[test]
    fn mutate_apdu_preserves_min_length() {
        let mut rng = Rng::new(999);
        let mut buf = [0u8; 261];
        let base_len = generate_apdu(&mut rng, &mut buf);
        for _ in 0..50 {
            let new_len = mutate_apdu(&mut rng, &mut buf, base_len);
            assert!(new_len >= 4);
        }
    }

    #[test]
    fn smoke_test_short_fuzz_run() {
        hle_init(&ATR, &MF, [0x11; 16], [0x22; 16], [0x33; 16]);
        hle_reset();

        let snap_size = Sim::<256>::SNAPSHOT_SIZE;
        let mut snapshot = vec![0u8; snap_size];
        let n = hle_snapshot_save(&mut snapshot);
        assert!(n > 0);

        let mut rsp_buf = [0u8; 261];
        let mut corpus = Corpus::new();

        // Known state-changing APDU sequences to ensure diversity.
        let sequences: &[&[u8]] = &[
            // SELECT MF
            &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00],
            // SELECT DF.GSM
            &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x7F, 0x20],
            // SELECT EF.ICCID
            &[0x00, 0xA4, 0x00, 0x04, 0x02, 0x2F, 0xE2],
            // Unsupported CLA (changes nothing but tests path)
            &[0xF0, 0xA4, 0x00, 0x00],
        ];

        for seq in sequences {
            hle_snapshot_restore(&snapshot[..n]);
            let _ = hle_apdu(seq, &mut rsp_buf);
            let h = hle_state_hash();
            if h != 0 {
                corpus.is_new(h);
            }
        }

        // Also run some random APDUs.
        let mut rng = Rng::new(0x1234);
        let mut apdu_buf = [0u8; 261];
        for _ in 0..100 {
            hle_snapshot_restore(&snapshot[..n]);
            let apdu_len = generate_apdu(&mut rng, &mut apdu_buf);
            let _ = hle_apdu(&apdu_buf[..apdu_len], &mut rsp_buf);
            let h = hle_state_hash();
            if h != 0 {
                corpus.is_new(h);
            }
        }
        // Known sequences guarantee at least 2 distinct states (base + selected file).
        assert!(corpus.interesting >= 2, "expected diverse states, got {}", corpus.interesting);
    }
}

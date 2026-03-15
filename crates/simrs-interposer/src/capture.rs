//! PCAP file capture for APDU traffic.

use simrs_pcap::{Direction, LinkType, PcapEncoder};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// Wraps a file and a [`PcapEncoder`] for PCAP output.
pub struct PcapCapture {
    writer: BufWriter<File>,
    encoder: PcapEncoder,
}

#[allow(clippy::similar_names)] // ts_sec / ts_usec are standard PCAP field names
impl PcapCapture {
    /// Create a new PCAP capture file, writing the global header.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be created or written to.
    pub fn create(path: &str, link_type: LinkType) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        let encoder = PcapEncoder::new(link_type);

        let mut hdr_buf = [0u8; 24];
        let n = encoder.global_header(&mut hdr_buf);
        writer.write_all(&hdr_buf[..n])?;

        Ok(Self { writer, encoder })
    }

    /// Get current timestamp as `(sec, usec)` since UNIX epoch.
    #[allow(clippy::cast_possible_truncation)]
    fn timestamp() -> (u32, u32) {
        let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return (0, 0);
        };
        (dur.as_secs() as u32, dur.subsec_micros())
    }

    /// Record an APDU packet with direction.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file write fails.
    pub fn record_apdu(&mut self, direction: Direction, apdu: &[u8]) -> std::io::Result<()> {
        let (ts_sec, ts_usec) = Self::timestamp();
        let mut buf = [0u8; 512];
        let n = self
            .encoder
            .encode_apdu(&mut buf, ts_sec, ts_usec, direction, apdu);
        self.writer.write_all(&buf[..n])
    }

    /// Record an ATR.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file write fails.
    pub fn record_atr(&mut self, atr: &[u8]) -> std::io::Result<()> {
        let (ts_sec, ts_usec) = Self::timestamp();
        let mut buf = [0u8; 512];
        let n = self.encoder.encode_atr(&mut buf, ts_sec, ts_usec, atr);
        self.writer.write_all(&buf[..n])
    }

    /// Record an APDU with mismatch flag.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file write fails.
    pub fn record_apdu_mismatch(
        &mut self,
        direction: Direction,
        apdu: &[u8],
    ) -> std::io::Result<()> {
        let (ts_sec, ts_usec) = Self::timestamp();
        let mut buf = [0u8; 512];
        let n = self
            .encoder
            .encode_apdu_mismatch(&mut buf, ts_sec, ts_usec, direction, apdu);
        self.writer.write_all(&buf[..n])
    }

    /// Flush the file.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the flush fails.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simrs_pcap::{
        GLOBAL_HEADER_SIZE, GSMTAP_HEADER_SIZE, RECORD_HEADER_SIZE, SIMPLE_FRAME_SIZE,
    };

    fn temp_path(name: &str) -> String {
        format!("{}/{name}", std::env::temp_dir().display())
    }

    #[test]
    fn create_writes_global_header() {
        let path = temp_path("interposer_test_global_hdr.pcap");
        {
            let cap = PcapCapture::create(&path, LinkType::GsmTap).unwrap();
            drop(cap);
        }
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len(), GLOBAL_HEADER_SIZE);
        // Verify PCAP magic number (little-endian).
        assert_eq!(
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            simrs_pcap::PCAP_MAGIC,
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_apdu_grows_file() {
        let path = temp_path("interposer_test_apdu_grow.pcap");
        {
            let mut cap = PcapCapture::create(&path, LinkType::GsmTap).unwrap();
            cap.record_apdu(Direction::Command, &[0x00, 0xA4, 0x00, 0x00])
                .unwrap();
            cap.flush().unwrap();
        }
        let data = std::fs::read(&path).unwrap();
        let expected_min = GLOBAL_HEADER_SIZE + RECORD_HEADER_SIZE + GSMTAP_HEADER_SIZE + 4;
        assert!(
            data.len() >= expected_min,
            "file too small: {} < {expected_min}",
            data.len()
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_atr_writes_packet() {
        let path = temp_path("interposer_test_atr.pcap");
        {
            let mut cap = PcapCapture::create(&path, LinkType::User0).unwrap();
            cap.record_atr(&[0x3B, 0x9F, 0x96, 0x80]).unwrap();
            cap.flush().unwrap();
        }
        let data = std::fs::read(&path).unwrap();
        let expected_min = GLOBAL_HEADER_SIZE + RECORD_HEADER_SIZE + SIMPLE_FRAME_SIZE + 4;
        assert!(
            data.len() >= expected_min,
            "file too small: {} < {expected_min}",
            data.len()
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_mismatch_writes_packet() {
        let path = temp_path("interposer_test_mismatch.pcap");
        {
            let mut cap = PcapCapture::create(&path, LinkType::User0).unwrap();
            cap.record_apdu_mismatch(Direction::Response, &[0x90, 0x00])
                .unwrap();
            cap.flush().unwrap();
        }
        let data = std::fs::read(&path).unwrap();
        // Check that mismatch flag is set in the flags byte.
        let flags_offset = GLOBAL_HEADER_SIZE + RECORD_HEADER_SIZE;
        // flags: response(1) | not_atr(0) | mismatch(4) = 0x05
        assert_eq!(data[flags_offset], 0x05);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn flush_succeeds_on_empty() {
        let path = temp_path("interposer_test_flush_empty.pcap");
        {
            let mut cap = PcapCapture::create(&path, LinkType::GsmTap).unwrap();
            cap.flush().unwrap();
        }
        std::fs::remove_file(&path).ok();
    }
}

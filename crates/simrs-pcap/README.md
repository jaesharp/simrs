# simrs-pcap

PCAP + GSMTAP SIM frame encoder.

Encodes PCAP file headers and packet records with GSMTAP or simplified
User0 framing for SIM APDU and ATR captures. All encoding writes to
caller-provided `&mut [u8]` slices.

`no_std`. No heap allocation, zero dependencies.

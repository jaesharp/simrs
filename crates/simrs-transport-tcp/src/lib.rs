//! TCP transport for the swICC PC/SC server protocol.
//!
//! Implements `Transport` over a TCP socket, connecting to the swICC network
//! server (or any compatible PC/SC server). Requires `std`.
//!
//! # Protocol
//! swICC framing: 4-byte big-endian length prefix followed by APDU payload.
//!
//! # Standards
//! Interoperates with the swICC network protocol (not formally standardized;
//! based on the swICC open-source PC/SC bridge).

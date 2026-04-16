# simrs-des

DES and Triple-DES (3DES) block ciphers.

Self-contained implementation with constant-time S-box lookups (via
`simrs-consttime`) to prevent cache-timing side-channel attacks. Used by
the OTA secured packet layer (TS 102 225) for legacy DES/3DES cipher and
MAC operations.

Implements NIST FIPS 46-3 (DES) and NIST SP 800-67 Rev.2 (Triple-DES).

`no_std`, no alloc.

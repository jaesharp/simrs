# simrs-gp-scp

GlobalPlatform SCP01, SCP02, and SCP03 secure channel protocols.

Implements session key derivation, mutual authentication (cryptogram
generation/verification), and secure messaging (C-MAC, C-ENC, R-MAC)
per GP Card Specification v2.1.1 Appendices D (SCP01) and E (SCP02),
and GP Amendment D v1.1.2 (SCP03).

`no_std`. No heap allocation.

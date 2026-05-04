# simrs-gp-scp

GlobalPlatform SCP01, SCP02, and SCP03 secure channel protocols.

Implements session key derivation, mutual authentication (cryptogram
generation/verification), and secure messaging (C-MAC, C-ENC, R-MAC).

Primary spec target is GP 2.3.1 Appendices D (SCP01) and E (SCP02),
plus GP Amendment D v1.1.2 (SCP03). The SCP01 and SCP02 implementations
were derived from GP 2.1.1 (the spec the inline figure numbers like
D-3 / E-2 were verified against); SCP01/SCP02 are unchanged in 2.3.1
relative to 2.1.1, with SCP01 retained but deprecated in 2.3.1.

`no_std`. No heap allocation.

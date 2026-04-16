# simrs-iso9797

ISO 9797-1 CBC-MAC and CBC encrypt/decrypt for DES, 3DES, and AES-128.

Provides the MAC and block-cipher-mode primitives used by GlobalPlatform
SCP01/SCP02 secure messaging, GP token/receipt generation, and ETSI
TS 102 225 OTA secured packets. Supports Method 1 (zero-pad) and
Method 2 (0x80-pad) padding.

`no_std`. No heap allocation.

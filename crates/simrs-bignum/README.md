# simrs-bignum

Const-generic big integer arithmetic for RSA.

Provides `BigUint<LIMBS>`, a fixed-size unsigned integer stored as
`[u64; LIMBS]` in little-endian limb order with constant-time arithmetic.
The primary use case is RSA modular exponentiation via Montgomery
multiplication (`MontParams`, `mod_exp`).

`no_std`, no alloc. All operations are performed on stack values.

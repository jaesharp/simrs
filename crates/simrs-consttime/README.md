# simrs-consttime

Constant-time primitives for cryptographic operations.

Provides building blocks that execute in data-independent time,
preventing cache-timing and branch-prediction side-channel attacks.

Core type: `CtBool` -- an opaque constant-time boolean that prevents
accidental branching. Traits: `CtEq`, `CtSelect`, `CtSwap`, `CtZero`.
Implementations for `u8`, `u64`, `[u8; N]`, `[u64; N]`, and tuples.

`no_std`.

# simrs-rijndael

AES-128 (Rijndael) block cipher -- encryption only, `const fn`.

**Layer:** Foundation | **`no_std`:** yes | **Status:** Implemented

## Standards

| Spec | Clause | Coverage |
|------|--------|----------|
| NIST FIPS 197 | all | AES-128 encrypt |
| ETSI TS 135 206 V19.0.0 | Annex 3 | Rijndael for Milenage |

## Dependencies

None (leaf crate).

## Dependents

| Crate | Uses |
|-------|------|
| [simrs-milenage](../simrs-milenage/) | f1-f5 computation |

## API

- `Rijndael::new(&[u8; 16]) -> Self` -- `const fn` key schedule
- `Rijndael::encrypt(&self, &[u8; 16]) -> [u8; 16]` -- `const fn` encryption

Both functions are `const fn` -- key schedule can run at compile time.

## Tests

8 unit tests + 3 doctests: FIPS 197 Appendix B, NIST SP 800-38A, zero-key known answer, determinism, XTIME self-consistency.

## Specs

- [Architecture](../../docs/architecture/#simrs-rijndael)
- [Standards: Authentication](../../docs/standards/02-authentication.md)

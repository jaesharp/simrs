# simrs-apdu-schema

APDU response schema types for semantic comparison.

Defines the vocabulary for describing APDU response field layouts and
comparison policies. Protocol crates use these types to declare
`ResponseSchema` statics describing their response formats. This crate
is purely type definitions; the comparison engine lives elsewhere.

`no_std`, zero dependencies. All types use `&'static` references and
can be constructed as `const`/`static` items.

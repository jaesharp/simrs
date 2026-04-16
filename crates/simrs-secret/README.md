# simrs-secret

Zero-cost compile-time secret data protection.

`Secret<T>` restricts a value to constant-time operations only.
Deliberately omits `PartialEq`, `Display`, `Hash`, and `Deref`;
comparison is via `CtEq::ct_eq`, extraction via `Secret::declassify`.

Also provides `CtOption<T>`, a constant-time option type where the
discriminant is a `CtBool`, avoiding cache-timing leaks from
allocation/deallocation patterns.

`no_std`, no alloc.

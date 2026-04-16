# simrs-redact

Feature-gated Debug/Display redaction for secret byte arrays.

`Redact` wraps a reference and controls its debug output via
compile-time feature flags:

- **Production** (default): prints `[REDACTED]`
- **Development** (`fingerprint-secrets-in-logs`): prints `[masked:a7b3c2d1]`
- **Testing** (no features): pass-through to inner type

`Secret<T>` delegates its Debug/Display impls to `Redact`.

`no_std`.

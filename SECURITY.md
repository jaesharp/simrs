# Security Policy

## Project Maturity

SimRS is pre-1.0 and under active development. It has not undergone independent
security audit. While significant effort goes into correctness -- constant-time
enforcement, information flow controls, Miri validation, adversarial testing,
and differential compliance against reference implementations -- this project
should not be used in production security-critical applications without
independent review.

## Scope

The following are considered security issues in SimRS:

- Timing side-channels in cryptographic operations (AES, DES, SHA, KDF, ECIES,
  Milenage, TUAK, COMP128, SCP key derivation)
- Information leakage through `PartialEq`, `Display`, `Debug`, `Hash`, or
  `Deref` on types that should be protected by `Secret<T>` or `CtEq`
- PIN/PUK oracle attacks (timing, error code, or behavioural differentiation)
- Protocol-level vulnerabilities in SCP01/SCP02/SCP03 (replay, padding oracle,
  cryptogram forgery, session key recovery)
- OTA secured packet bypass or downgrade
- JCVM sandbox escape (applet isolation, firewall bypass, type confusion)
- Filesystem access control bypass (PIN verification state, access conditions)
- Memory disclosure through uninitialised buffers or improper zeroisation

General code quality issues, panics in non-security paths, and feature requests
are not security issues -- use the issue tracker for those.

## Supported Versions

Only the current HEAD of `dev` receives security fixes. There are no stable
releases or backport branches yet.

## Reporting a Vulnerability

Report security issues privately to **j@jaesharp.com**.

Please include:

- Affected component (crate name, module, function)
- Description of the vulnerability and its impact
- Steps to reproduce, proof of concept, or test case if possible
- Suggested fix if you have one

Do **not** open a public issue for security vulnerabilities.

## Response

- Acknowledgement within 7 days.
- Assessment and fix timeline depends on severity. Critical issues (key
  recovery, sandbox escape, side-channel in deployed crypto) are prioritised
  over lower-severity findings.
- There is no bug bounty program.

## Disclosure

Coordinated disclosure with a 90-day window from acknowledgement. If a fix is
published sooner, disclosure may happen sooner with mutual agreement. Credit
is given to reporters unless they prefer otherwise.

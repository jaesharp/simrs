# simrs-gp-open

GlobalPlatform OPEN runtime and Issuer Security Domain (ISD). Primary
spec target is GP 2.3.1 (clauses 5 / 11); implementation derived from
GP Card Specification v2.1.1 Chapters 5-9 (the spec the inline clause
numbers were verified against). See
`docs/standards/06-globalplatform.md` for the dual-spec map.

The GP OPEN is the card manager that dispatches APDUs to on-card applets.
Maintains the applet registry, manages logical channels, enforces
lifecycle state transitions, and handles the GP secure channel protocol.

`no_std`.

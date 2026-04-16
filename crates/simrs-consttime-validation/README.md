# simrs-consttime-validation

Constant-time validation facade backed by tacet.

Provides a two-class test pattern with a deterministic PRNG, using
tacet's adaptive Bayesian methodology and platform-specific
high-resolution timers (rdtsc on x86_64). Reports pass/fail/inconclusive
based on statistical analysis of timing distributions.

Requires `std`. Must be compiled with `--release` (debug builds produce
false positives).

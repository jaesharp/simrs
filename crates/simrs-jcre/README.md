# simrs-jcre

Java Card Runtime Environment core per JC RE Specification 2.1.1.

Provides the `Applet` trait, three-tier memory model (persistent,
CLEAR_ON_RESET, CLEAR_ON_DESELECT), and `TransactionJournal` for atomic
multi-field updates with rollback. Every applet -- native Rust or JCVM
bytecode -- implements the `Applet` trait defined here.

`no_std`. No heap allocation.

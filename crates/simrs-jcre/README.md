# simrs-jcre

Java Card Runtime Environment core. Primary spec target is JC RE 3.2;
implementation derived from JC RE 2.1.1 (the spec the inline clause
numbers were verified against). See
`docs/standards/06-globalplatform.md` for the dual-spec map.

Provides the `Applet` trait, three-tier memory model (persistent,
CLEAR_ON_RESET, CLEAR_ON_DESELECT), and `TransactionJournal` for atomic
multi-field updates with rollback. Every applet -- native Rust or JCVM
bytecode -- implements the `Applet` trait defined here.

`no_std`. No heap allocation.

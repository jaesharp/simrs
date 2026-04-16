# simrs-jcasm

Java Card assembler proc-macro for simrs JCVM.

Provides the `jcasm!` macro that compiles Java Card assembly into
CAP-format bytecode at compile time. Assembly errors are reported as
compiler errors with source spans.

Instruction set per JCVM 3.1 Chapter 7.

# simrs-jcvm

Java Card Virtual Machine bytecode interpreter per JCVM 3.2 (with
JCVM 2.1.1 retained as a legacy compatibility target for the
JCOP10-31bio family). See `docs/standards/06-globalplatform.md` for
the dual-spec map.

Fully deterministic, snapshotable JCVM with object heap, package
registry, static fields, operand stack, and call frames. `JcVMApplet`
wraps a `JcVM` and implements the JCRE `Applet` trait, allowing bytecode
applets to run alongside native Rust applets in the GP card.

The CAP file parser surfaces 10 of the 13 components defined in
JCVM 3.2 § 6 (Header / Method / Descriptor / ConstantPool / Applet /
Import / Export / RefLocation / StaticField summary / Class MVP); a
legacy pre-component blob format is also accepted for the embedded
smoke-test path.

`no_std`, no alloc.

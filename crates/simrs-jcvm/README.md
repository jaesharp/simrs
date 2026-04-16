# simrs-jcvm

Java Card Virtual Machine bytecode interpreter per JCVM 2.1.1.

Fully deterministic, snapshotable JCVM with object heap, package
registry, static fields, operand stack, and call frames. `JcVMApplet`
wraps a `JcVM` and implements the JCRE `Applet` trait, allowing bytecode
applets to run alongside native Rust applets in the GP card.

`no_std`, no alloc.

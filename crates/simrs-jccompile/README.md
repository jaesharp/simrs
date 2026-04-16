# simrs-jccompile

JVA compiler core: IR, type system, type checker, and code generator
for Java Card smartcard applets.

Compiles a high-level IR (`ir::JcClass`) into JCVM bytecodes. Includes
type checking, bytecode generation, peephole optimization, constant
folding, dead code elimination, and source map support.

`no_std` (uses `alloc`).

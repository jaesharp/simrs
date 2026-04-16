# jacc

JavaCard-Approximately-Compatible Compiler.

Compiles Java Card applet source files and classfiles to JCVM CAP packages, and decompiles CAP files back to assembly or source.

## Usage

Compile source files (`.java`, `.jva`) or classfiles (`.class`, `.jvc`) to CAP packages:

```
cargo run -p jacc -- input.java -o output.cap
cargo run -p jacc -- input.class -o output.cap
```

If `-o` is omitted, the output file is the input path with a `.cap` extension.

Generate a `.jvamap` source map alongside the output:

```
cargo run -p jacc -- input.java --source-map
```

Disassemble a CAP file to assembly text (stdout):

```
cargo run -p jacc -- --disasm applet.cap
```

Decompile a CAP file to JVA source (stdout):

```
cargo run -p jacc -- --decompile applet.cap
```

## Supported input formats

| Extension       | Description                      |
|-----------------|----------------------------------|
| `.java`, `.jva` | Java Card / JVA source           |
| `.class`, `.jvc`| Java classfile / JVC bytecode    |

## Architecture

`jacc` is a thin CLI around two workspace crates:

- `jacc` (library) -- Java parser, classfile reader, CAP writer, and decompiler
- `simrs-jccompile` -- IR compilation, optimization, and codegen

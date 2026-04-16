# jvac

Java Card applet compiler and decompiler for the JCVM.

## Usage

Compile source files (`.java`, `.jva`) or classfiles (`.class`, `.jvc`) to CAP packages:

```
cargo run -p jvac -- input.java -o output.cap
cargo run -p jvac -- input.class -o output.cap
```

If `-o` is omitted, the output file is the input path with a `.cap` extension.

Generate a `.jvamap` source map alongside the output:

```
cargo run -p jvac -- input.java --source-map
```

Disassemble a CAP file to assembly text (stdout):

```
cargo run -p jvac -- --disasm applet.cap
```

Decompile a CAP file to JVA source (stdout):

```
cargo run -p jvac -- --decompile applet.cap
```

## Supported input formats

| Extension       | Description                      |
|-----------------|----------------------------------|
| `.java`, `.jva` | Java Card / JVA source           |
| `.class`, `.jvc`| Java classfile / JVC bytecode    |

## Architecture

`jvac` is a thin CLI around two workspace crates:

- `jvac` (library) -- Java parser, classfile reader, CAP writer, and decompiler
- `simrs-jccompile` -- IR compilation, optimization, and codegen

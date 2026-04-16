# simrs-jcsl

Oracle Java Card Simulator (jcsl) binary discovery, configuration, and process management.

## Usage

```
cargo run -p simrs-jcsl -- status              # show jcsl installation status
cargo run -p simrs-jcsl -- install <path>       # install from Oracle SDK directory or binary
cargo run -p simrs-jcsl -- validate <path>      # validate a jcsl binary
cargo run -p simrs-jcsl -- guide                # print acquisition instructions
```

## Binary discovery

The library searches for the jcsl binary in this order:

1. `SIMRS_JCSL_BINARY` environment variable (explicit override)
2. `$XDG_CACHE_HOME/simrs/jcsl` (default: `~/.cache/simrs/jcsl`)
3. Workspace-relative `tools/oracle-jcvm-ref/runtime/bin/jcsl.orig`

## Prerequisites

The jcsl binary is part of the Oracle Java Card Development Kit Simulator, available at no cost from Oracle (requires an Oracle account). Download from:

https://www.oracle.com/java/technologies/javacard-sdk-downloads.html

After downloading, extract and install:

```
unzip java_card_kit-classic-*.zip -d /tmp/jcdk
cargo run -p simrs-jcsl -- install /tmp/jcdk
```

The jcsl binary is a 32-bit x86 Linux ELF. On 64-bit systems you may need 32-bit compatibility libraries (`libc6-i386` or equivalent).

## Library API

The `simrs-jcsl` crate also provides:

- `discovery` -- binary search chain and validation
- `configurator` -- SCP keyset and Global PIN injection into the binary
- `JcslProcess` -- managed subprocess spawning (with memfd-based binary patching)
- `JcslClient` -- TCP transport client for communicating with a running jcsl instance

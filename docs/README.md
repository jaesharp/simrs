# Documentation

Top-level index for simrs documentation. Source of truth for any
component is the code; the docs here trace shape, intent, and the
spec map.

## Architecture

Higher-level design and stack-wide reasoning.

| Doc | Contents |
|-----|----------|
| [architecture/README.md](architecture/README.md) | API surface, layered crate map (cellular + JavaCard/GP stacks), data-flow diagrams |
| [architecture/controlplane-applet.md](architecture/controlplane-applet.md) | Test-only hypervisor-style introspection surface (`80 F0` APDUs, capabilities, nested cards) |

## Standards

3GPP / ETSI / GlobalPlatform / JavaCard spec map and per-area depth.

| Doc | Contents |
|-----|----------|
| [standards/README.md](standards/README.md) | Standards-area index and navigation |
| [standards/01-catalog.md](standards/01-catalog.md) | Comprehensive standards catalog; primary spec targets per crate |
| [standards/02-authentication.md](standards/02-authentication.md) | 3G/4G/5G authentication flows; Milenage, TUAK, key derivation |
| [standards/03-filesystem.md](standards/03-filesystem.md) | EF catalog (USIM / DF_5GS / ISIM / HPSIM); selection contexts |
| [standards/04-proactive.md](standards/04-proactive.md) | CAT / proactive command set, event downloads, PROVIDE LOCAL INFORMATION |
| [standards/05-crate-impact.md](standards/05-crate-impact.md) | Crate-by-crate matrix of 4G / 5G / GP impact and status |
| [standards/06-globalplatform.md](standards/06-globalplatform.md) | GP 2.3.1 / JC 3.2 conformance status, phased upgrade plan, JCOP variant map |

## Style

Conventions for docs, code, and visuals.

| Doc | Contents |
|-----|----------|
| [style/diagrams.md](style/diagrams.md) | Okabe-Ito colour palette, WCAG AA compliance |

## Specs

`docs/specs/` is reserved for upstream specification PDFs. Citations
in code (`crates/.../src/`) link back into this directory using
relative paths. PDFs are kept out of git; see
[standards/01-catalog.md](standards/01-catalog.md) for sources.

## ADRs

`docs/adrs/` is reserved for architecture decision records. Empty
today; populated when significant architectural choices are made
that require durable rationale.

## See also

- [../crates/README.md](../crates/README.md) -- Crate map, dependency graph, per-crate scope
- [../README.md](../README.md) -- Project overview and quick start
- [../exports/README.md](../exports/README.md) -- Public ABI surface and external bindings layout

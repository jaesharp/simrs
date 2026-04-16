# simrs-spec-tests

Specification-driven BDD test suite for simrs core SIM/USIM functionality, using cucumber-rs.

## Usage

```
cargo test -p simrs-spec-tests --test cucumber
```

Note: this crate has its own `[workspace]` declaration and lives outside the main simrs workspace. It depends on simrs crates via relative path.

## Feature files

Located in `features/` (not symlinked from specs/).

| Feature                    | Domain                          |
|----------------------------|---------------------------------|
| `bertlv.feature`          | BER-TLV encoding/decoding       |
| `comp128.feature`         | COMP128v1 authentication         |
| `fs.feature`              | SIM filesystem operations        |
| `gsm.feature`             | GSM SIM application              |
| `iso7816.feature`         | ISO 7816 APDU framing            |
| `milenage.feature`        | Milenage authentication          |
| `pin.feature`             | PIN/PUK management               |
| `proactive.feature`       | Proactive UICC commands          |
| `sim.feature`             | Top-level SIM state machine      |
| `transport.feature`       | Transport abstraction            |
| `transport-tcp.feature`   | TCP transport                    |
| `usim.feature`            | USIM application                 |

## Step definition modules

Step definitions mirror the feature files: `bertlv`, `comp128`, `fs`, `gsm`, `iso7816`, `milenage`, `pin`, `proactive`, `sim`, `transport`, `transport_tcp`, `usim`. Shared initialization and generic assertions live in `common`.

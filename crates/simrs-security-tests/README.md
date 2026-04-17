# simrs-security-tests

Security regression and proof-of-concept BDD test suite for simrs, using cucumber-rs.

## Usage

```
cargo test -p simrs-security-tests --test cucumber
```

## Feature files

| Feature                          | Vulnerability class                        |
|----------------------------------|--------------------------------------------|
| `apdu_boundary.feature`         | APDU boundary conditions / malformed input |
| `auth_protocol.feature`         | AUTHENTICATE protocol attacks              |
| `bip_channel.feature`           | BIP channel security                       |
| `channel_isolation.feature`     | Logical channel isolation                  |
| `confinement.feature`           | Command side-effect confinement            |
| `data_leakage.feature`          | GET RESPONSE data leakage                  |
| `ecies_suci.feature`            | ECIES/SUCI privacy attacks                 |
| `fs_access_control.feature`     | Filesystem access control bypass           |
| `ota_envelope.feature`          | OTA/ENVELOPE injection                     |
| `pin_state_machine.feature`     | PIN/PUK state machine attacks              |
| `snapshot_integrity.feature`    | Snapshot integrity verification            |

## Step definition modules

Step definitions mirror the feature files: `pin_state_machine`, `apdu_boundary`, `fs_access_control`, `ota_envelope`, `auth_protocol`, `data_leakage`, `bip_channel`, `channel_isolation`, `ecies_suci`, and `snapshot_integrity`. Shared SIM initialization and generic APDU/SW assertions live in `common`.

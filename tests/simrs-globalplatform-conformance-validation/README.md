# simrs-globalplatform-conformance-validation

GlobalPlatform BDD test suite for the simrs GP card emulator, using cucumber-rs.

## Usage

```
cargo test -p simrs-globalplatform-conformance-validation --test cucumber
```

By default, scenarios tagged `@wip` are excluded. To include them:

```
SIMRS_GP_RUN_WIP=1 cargo test -p simrs-globalplatform-conformance-validation --test cucumber
```

## Feature files

| Feature                          | Domain                              |
|----------------------------------|-------------------------------------|
| `applet_lifecycle.feature`       | Applet lifecycle management         |
| `card_lifecycle.feature`         | Card lifecycle state machine        |
| `get_status.feature`             | GET STATUS command                  |
| `install_delete.feature`         | INSTALL / DELETE operations         |
| `jcvm_security.feature`          | JCVM security boundary checks      |
| `scp01_mutual_auth.feature`      | SCP01 mutual authentication         |
| `scp02_mutual_auth.feature`      | SCP02 mutual authentication         |
| `scp03_mutual_auth.feature`      | SCP03 mutual authentication         |
| `scp_secure_messaging.feature`   | SCP secure messaging                |
| `scp_security.feature`           | SCP security policy enforcement     |
| `select_by_aid.feature`          | SELECT by AID                       |

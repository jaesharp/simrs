# Open5GS 4G EPC test network for simrs

A scripted, reproducible Open5GS Evolved Packet Core that a simrs SIM
(driven by `simrs-vpcd`, `simrs-swicc`, or eventually `simrs-simtrace2`)
can register against end-to-end.

This is the core network only. A radio access network (eNodeB) is
required to actually run a UE against this stack; see
[Section 6 -- Radio access network](#6-radio-access-network) below.

## 1. What you get

`docker compose up -d` brings up nine containers on a private docker
bridge network named `open5gs`:

| Container | Image | Role |
|---|---|---|
| `open5gs-mongo` | `mongo:6.0` | Subscriber database |
| `open5gs-hss` | `gradiant/open5gs:2.7.7` | Home Subscriber Server (S6a Diameter) |
| `open5gs-mme` | `gradiant/open5gs:2.7.7` | Mobility Management Entity (S1AP/S11) |
| `open5gs-sgwc` | `gradiant/open5gs:2.7.7` | Serving Gateway control plane |
| `open5gs-sgwu` | `gradiant/open5gs:2.7.7` | Serving Gateway user plane |
| `open5gs-smf` | `gradiant/open5gs:2.7.7` | Session Management Function (P-GW-C) |
| `open5gs-upf` | `gradiant/open5gs:2.7.7` | User Plane Function (P-GW-U) |
| `open5gs-pcrf` | `gradiant/open5gs:2.7.7` | Policy / Charging Rules Function |
| `open5gs-webui` | `gradiant/open5gs-webui:2.7.7` | Subscriber inspection UI |

PLMN is configured to **MCC=001 MNC=01** (the standard test PLMN),
TAC is **7**, and the default APN is **internet**. These values are
baked into the per-service YAML in `config/`. If you change them, see
[Section 7 -- simrs binding](#7-simrs-binding) for the matching changes
that must land in `simrs-vpcd` flags.

The image registry `gradiant/open5gs` is the maintained successor to
the now-deprecated `openverso/open5gs` published by the same authors.
`2.7.7` is pinned because that was the most recent stable release at
the time of writing; the `latest` tag floats and is not pinned here.

## 2. Prerequisites

1. **Docker** with Compose v2 (`docker compose`, not the legacy
   `docker-compose` binary). Tested with Docker 24.x.
2. **~6 GB free RAM** for all nine containers under light load.
3. **Linux host** if you intend to attach a real eNodeB later. The
   compose stack runs on macOS / WSL2 for development, but the
   `cap_add: NET_ADMIN` and TUN device requirements on the UPF make
   bare-metal Linux strongly preferred.
4. About **2 GB of disk** for the docker images on first pull.

The compose file does not require root, but the UPF container is
privileged (it creates a TUN device for the UE data plane).

## 3. Bring the network up

From this directory:

```bash
docker compose up -d
```

First boot will pull the four images (`mongo`, `gradiant/open5gs`,
`gradiant/open5gs-webui`, and -- on first subscriber provisioning --
`gradiant/open5gs-dbctl`). Subsequent runs reuse the cached images.

Wait roughly 10-20 seconds for the components to settle. The
gradiant entrypoint deliberately sleeps 10s in MME/PCRF/SGWC/UPF to
let Docker DNS resolve sibling container names; that delay is why the
stack is not instant.

Confirm everything is up:

```bash
docker compose ps
```

You should see all nine services in the `Up` state.

## 4. Provision the simrs subscriber

```bash
./bootstrap-subscriber.sh
```

This script runs `open5gs-dbctl add_ue_with_apn` inside a transient
container attached to the `open5gs` docker network. It provisions the
following subscriber:

| Field | Value | Where this comes from |
|---|---|---|
| IMSI | `001010000000001` | `simrs-vpcd --imsi` default |
| Ki / K | `22222222222222222222222222222222` | `simrs-vpcd --k` default |
| OPc | `33333333333333333333333333333333` | `simrs-vpcd --opc` default |
| APN | `internet` | `config/smf.yaml` and `config/upf.yaml` |
| AMBR DL | 1 Gbps | `bootstrap-subscriber.sh` |
| AMBR UL | 100 Mbps | `bootstrap-subscriber.sh` |

The script is **idempotent**: it removes any existing record for
the IMSI before adding, so re-running after editing the script (or
after `docker compose down -v`) is safe.

The `open5gs-dbctl` command set is documented inline in the upstream
script at
[github.com/open5gs/open5gs/blob/main/misc/db/open5gs-dbctl](https://github.com/open5gs/open5gs/blob/main/misc/db/open5gs-dbctl).
Use `add_ue_with_apn {imsi key opc apn}` to create with a non-default
APN; bare `add {imsi key opc}` defaults to APN=`internet`.

## 5. Verify the network is healthy

### 5.1 HSS started

```bash
docker compose logs open5gs-hss
```

Look for a line ending in `HSS Started` (case may vary by Open5GS
release). Diameter `s6a` peer associations from the MME show up here
as the MME comes online.

### 5.2 MME bound to S1AP

```bash
docker compose logs open5gs-mme
```

Look for `s1ap_server() ... listen ...:36412` and Diameter peer up
messages mentioning `hss.open5gs.org`.

### 5.3 PFCP associations

```bash
docker compose logs open5gs-smf | grep -i pfcp
docker compose logs open5gs-upf | grep -i pfcp
```

Both sides should log a successful PFCP association
(`PFCP associated` or similar). If only one side reports it, the
TUN device on UPF most likely failed to come up; verify with
`docker compose exec open5gs-upf ip addr show ogstun`.

### 5.4 Subscriber visible in WebUI

Browse to <http://localhost:9999>.

Default credentials (provisioned automatically by the WebUI on first
run): username `admin`, password `1423`. See the upstream
[Quickstart guide](https://open5gs.org/open5gs/docs/guide/01-quickstart/)
if these no longer apply for the pinned image version.

You should see `001010000000001` listed with APN `internet`.

### 5.5 Quick MongoDB sanity check

```bash
docker compose exec open5gs-mongo \
    mongosh open5gs --eval 'db.subscribers.find().pretty()'
```

The subscriber document should include the IMSI, the K (as the
`security.k` field), and the OPc (as `security.opc`).

## 6. Radio access network

This compose stack provides the **core only**. To run a UE against it
you also need an eNodeB. Three options that are known to work with
Open5GS:

1. **srsRAN Project** (free / open source) with a USRP B-series or
   similar SDR. See <https://docs.srsran.com/projects/4g/en/latest/>
   for srsenb setup. Point `enb.conf` at the host running this compose
   stack with `mme_addr = <host IP>` and PLMN matching `001/01`.
2. **Amarisoft Callbox** (commercial). Configure with the same PLMN
   `001/01` and point the MME endpoint at the host running this
   compose stack on SCTP/36412.
3. **A physical eNodeB** (e.g. Baicells, Sercomm). Provision the
   same way; PLMN `001/01`, MME address = host IP, S1AP port 36412.

If you do not have any of these, the compose stack still serves a
useful purpose: it lets you exercise `bootstrap-subscriber.sh`,
inspect the subscriber record in the WebUI, and (with future work)
run isolated end-to-end protocol tests with `srsRAN-zmq` against a
software UE such as `srsue`. End-to-end UE attach validation requires
either RF or a software UE+gNB simulation.

## 7. simrs binding

The four values that must agree between this stack and `simrs-vpcd`:

| Stack file | Stack value | simrs-vpcd flag |
|---|---|---|
| `config/mme.yaml` `gummei.plmn_id` | `mcc: 001 mnc: 01` | `--imsi` (first 5 digits) |
| `bootstrap-subscriber.sh` `IMSI` | `001010000000001` | `--imsi 001010000000001` |
| `bootstrap-subscriber.sh` `KI` | `22222222222222222222222222222222` | `--k 22222222222222222222222222222222` |
| `bootstrap-subscriber.sh` `OPC` | `33333333333333333333333333333333` | `--opc 33333333333333333333333333333333` |

If you change one, change the other. To verify after a change,
restart `simrs-vpcd` and force a fresh attach attempt; AUTHENTICATE
mismatches surface as SW `9862` (sync failure) or `6300` (auth
failed).

A non-default subscriber example:

```bash
# Provision a second test IMSI in the network:
IMSI=001010000000002 \
KI=44444444444444444444444444444444 \
OPC=55555555555555555555555555555555 \
    ./bootstrap-subscriber.sh

# Run simrs-vpcd against it:
cargo run --release -p simrs-vpcd -- \
    --imsi 001010000000002 \
    --k    44444444444444444444444444444444 \
    --opc  55555555555555555555555555555555
```

## 8. Teardown

```bash
docker compose down
```

This stops and removes containers but preserves the MongoDB volumes,
so subscribers survive a restart.

```bash
docker compose down -v
```

This additionally deletes the `open5gs_mongo_data` and
`open5gs_mongo_config` volumes. Subscribers are gone; you must
re-run `bootstrap-subscriber.sh` after the next `docker compose up -d`.

## 9. References

- [Open5GS first-LTE tutorial](https://open5gs.org/open5gs/docs/tutorial/01-your-first-lte/)
- [Open5GS quickstart](https://open5gs.org/open5gs/docs/guide/01-quickstart/)
- [open5gs-dbctl script source (subcommand reference)](https://github.com/open5gs/open5gs/blob/main/misc/db/open5gs-dbctl)
- [gradiant/open5gs Docker Hub](https://hub.docker.com/r/gradiant/open5gs)
- [gradiant/5g-images repo (Dockerfile + bundled configs)](https://github.com/Gradiant/5g-images/tree/main/images/open5gs)
- [Upstream Open5GS source config samples](https://github.com/open5gs/open5gs/tree/main/configs/open5gs)
- [WS-5 spec](../../../docs/specs/simtrace2-cardem-workstreams.md)
- [Path A runbook](../../../docs/runbooks/simtrace2-cardem-path-a.md)

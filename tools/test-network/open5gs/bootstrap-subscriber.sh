#!/usr/bin/env bash
#
# bootstrap-subscriber.sh
#
# Provisions the simrs default subscriber in the Open5GS HSS/MongoDB so
# that an out-of-the-box simrs-vpcd authenticates against this test
# network without further configuration.
#
# Idempotent: if the IMSI already exists, it is removed and re-added
# with current values. Re-run after editing the values below or after
# `docker compose down -v`.
#
# The values here mirror the simrs-vpcd CLI defaults (see WS-2 in
# docs/specs/simtrace2-cardem-workstreams.md):
#
#   IMSI: 001010000000001  (15-digit, MCC=001 MNC=01)
#   K:    32 hex chars of 0x22  (--k default in simrs-vpcd)
#   OPc:  32 hex chars of 0x33  (--opc default in simrs-vpcd)
#   APN:  internet            (matches SMF/UPF config)
#
# open5gs-dbctl subcommand reference (v0.10.3, distributed with
# Open5GS 2.7.x):
#   https://github.com/open5gs/open5gs/blob/main/misc/db/open5gs-dbctl
#
# Usage:
#   ./bootstrap-subscriber.sh                  # provision defaults
#   IMSI=001010000000002 ./bootstrap-subscriber.sh   # override one field

set -euo pipefail

# --- subscriber parameters ---------------------------------------------------

# These defaults match `simrs-vpcd --help` exactly. If you change one,
# you must pass the matching --imsi / --k / --opc flag to simrs-vpcd or
# the AUTHENTICATE will mismatch (typically SW 9862 "Authentication
# error - synchronisation failure" or 6300 "Authentication failed").
IMSI="${IMSI:-001010000000001}"
KI="${KI:-22222222222222222222222222222222}"
OPC="${OPC:-33333333333333333333333333333333}"
APN="${APN:-internet}"

# AMBR: 1 Gbps DL / 100 Mbps UL. Units in open5gs-dbctl ambr_speed:
#   0=bps  1=Kbps  2=Mbps  3=Gbps  4=Tbps
AMBR_DL_VALUE="${AMBR_DL_VALUE:-1}"
AMBR_DL_UNIT="${AMBR_DL_UNIT:-3}"   # Gbps
AMBR_UL_VALUE="${AMBR_UL_VALUE:-100}"
AMBR_UL_UNIT="${AMBR_UL_UNIT:-2}"   # Mbps

# Compose project / mongo network. Defaults follow docker-compose.yml.
COMPOSE_FILE="${COMPOSE_FILE:-${0%/*}/docker-compose.yml}"
DBCTL_IMAGE="${DBCTL_IMAGE:-gradiant/open5gs-dbctl:2.7.7}"
NETWORK="${NETWORK:-open5gs}"
DB_URI="${DB_URI:-mongodb://mongo/open5gs}"

# --- helpers -----------------------------------------------------------------

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
}

dbctl() {
    # Run open5gs-dbctl inside the 'open5gs' docker network so the
    # script can reach the 'mongo' service by name. --rm so we don't
    # accumulate container debris; --network attaches to the network
    # the compose stack created.
    docker run --rm \
        --network "${NETWORK}" \
        --env "DB_URI=${DB_URI}" \
        "${DBCTL_IMAGE}" \
        "/usr/local/bin/open5gs-dbctl $*"
}

require_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        log "ERROR: docker is not on PATH; install Docker and try again."
        exit 1
    fi
}

require_network() {
    if ! docker network inspect "${NETWORK}" >/dev/null 2>&1; then
        log "ERROR: docker network '${NETWORK}' not found."
        log "       Did you run 'docker compose up -d' from this directory?"
        exit 1
    fi
}

# --- main --------------------------------------------------------------------

require_docker
require_network

log "Provisioning subscriber: IMSI=${IMSI} APN=${APN}"

# Idempotent re-provision: remove first (ignore failure if not yet
# present), then add. open5gs-dbctl returns nonzero when removing a
# nonexistent IMSI so the failure is silenced.
log "Removing any existing record for IMSI=${IMSI}"
dbctl "remove ${IMSI}" >/dev/null 2>&1 || true

log "Adding subscriber with APN=${APN}"
dbctl "add_ue_with_apn ${IMSI} ${KI} ${OPC} ${APN}"

log "Setting AMBR to ${AMBR_DL_VALUE} (unit=${AMBR_DL_UNIT}) DL / ${AMBR_UL_VALUE} (unit=${AMBR_UL_UNIT}) UL"
dbctl "ambr_speed ${IMSI} ${AMBR_DL_VALUE} ${AMBR_DL_UNIT} ${AMBR_UL_VALUE} ${AMBR_UL_UNIT}"

log "Subscriber provisioned. Verify with: docker run --rm --network ${NETWORK} --env DB_URI=${DB_URI} ${DBCTL_IMAGE} '/usr/local/bin/open5gs-dbctl showpretty'"

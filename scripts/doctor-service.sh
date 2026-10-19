#!/usr/bin/env bash
# Run doctor with the same capabilities as mutekizu.service, without making
# the GUI or the diagnostic shell root. Uses a transient systemd unit.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONFIG=${1:-/etc/mutekizu/mutekizu.conf}
if [ -n "${MUTEKIZU_BIN:-}" ]; then
    BIN=$MUTEKIZU_BIN
elif [ -x "$ROOT/build/mutekizu" ]; then
    BIN="$ROOT/build/mutekizu"
else
    BIN=/usr/local/bin/mutekizu
fi

if [ ! -x "$BIN" ]; then
    echo "error: $BIN not found" >&2
    exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
    exec "$BIN" --config "$CONFIG" doctor
fi
exec systemd-run --quiet --pipe --wait --collect \
    --uid="$(id -u)" --gid="$(id -g)" \
    --property=AmbientCapabilities='CAP_NET_ADMIN CAP_NET_RAW' \
    --property=CapabilityBoundingSet='CAP_NET_ADMIN CAP_NET_RAW' \
    --property=NoNewPrivileges=yes \
    "$BIN" --config "$CONFIG" doctor

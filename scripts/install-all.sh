#!/usr/bin/env bash
# One-shot install/update: engine + config + systemd unit (+ GUI), enable and
# start the service, then show status and diagnostics.
#
#   sudo ~/mutekizu/scripts/install-all.sh
#   sudo ~/mutekizu/scripts/install-all.sh --reset-config   # replace config+domains with defaults
#   sudo ~/mutekizu/scripts/install-all.sh --no-gui
#   sudo ~/mutekizu/scripts/install-all.sh --polkit-noauth  # wheel: no prompt for this service/helper only
#   sudo ~/mutekizu/scripts/install-all.sh --autostart      # open the GUI at login (normal user)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WITH_GUI=1
RESET_CONFIG=0
POLKIT_NOAUTH=0
AUTOSTART=0
for arg in "$@"; do
    case "$arg" in
        --no-gui) WITH_GUI=0 ;;
        --reset-config) RESET_CONFIG=1 ;;
        --polkit-noauth) POLKIT_NOAUTH=1 ;;
        --autostart) AUTOSTART=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run with sudo: sudo $ROOT/scripts/install-all.sh" >&2
    exit 1
fi

if [ "$RESET_CONFIG" = 1 ] && [ -d /etc/mutekizu ]; then
    ts=$(date +%Y%m%d-%H%M%S)
    echo "== backup existing config to /etc/mutekizu/backup-$ts =="
    mkdir -p "/etc/mutekizu/backup-$ts"
    cp -a /etc/mutekizu/mutekizu.conf "/etc/mutekizu/backup-$ts/" 2>/dev/null || true
    cp -a /etc/mutekizu/domains.txt "/etc/mutekizu/backup-$ts/" 2>/dev/null || true
    cp -a /etc/mutekizu/mss_targets.txt "/etc/mutekizu/backup-$ts/" 2>/dev/null || true
fi

echo "== engine, config, systemd unit =="
if [ "$RESET_CONFIG" = 1 ]; then
    FORCE=1 bash "$ROOT/scripts/install.sh"
else
    bash "$ROOT/scripts/install.sh"
fi

if [ "$WITH_GUI" = 1 ] && [ -x "$ROOT/gui/install-gui.sh" ]; then
    echo "== GUI (Mutekizu) =="
    AUTOSTART="$AUTOSTART" ALLOW_NOAUTH="$POLKIT_NOAUTH" \
        bash "$ROOT/gui/install-gui.sh"
fi

echo "== enable and start mutekizu.service =="
systemctl daemon-reload
systemctl enable --now mutekizu

for _ in $(seq 1 20); do
    systemctl is-active --quiet mutekizu && break
    sleep 0.5
done

echo "== status =="
systemctl status mutekizu --no-pager || true

if ! systemctl is-active --quiet mutekizu; then
    echo
    echo "error: mutekizu.service is not active; recent journal:" >&2
    journalctl -u mutekizu -n 40 --no-pager >&2 || true
    exit 1
fi

echo "== doctor (read-only) =="
"$ROOT/build/mutekizu" doctor || true

cat <<EOF

Done.

  config:  /etc/mutekizu/mutekizu.conf
  domains: /etc/mutekizu/domains.txt
  service: systemctl status mutekizu

Launch the GUI as your normal user:
  mutekizu-gui
Demo without touching the system:
  mutekizu-gui --demo

Edit domains in the GUI or in /etc/mutekizu/domains.txt; after saving,
restart the service (the GUI does it via D-Bus).
EOF

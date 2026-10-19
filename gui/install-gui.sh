#!/usr/bin/env bash
# Install only the GUI, its narrow helper, desktop entry and icon.
# The engine, service unit and /etc/mutekizu are not installed or started here.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${PREFIX:-/usr/local}
LIBEXEC=${LIBEXEC:-/usr/libexec}
DATADIR=${DATADIR:-/usr/share}
FORCE=${FORCE:-0}
ALLOW_NOAUTH=${ALLOW_NOAUTH:-0}
AUTOSTART=${AUTOSTART:-0}

for arg in "$@"; do
    case "$arg" in
        --polkit-noauth) ALLOW_NOAUTH=1 ;;
        --autostart) AUTOSTART=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run with sudo $0" >&2
    exit 1
fi
for t in cmake g++ pkg-config; do
    command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }
done

echo "== build GUI =="
cmake -S "$ROOT" -B "$ROOT/gui/build" -DCMAKE_BUILD_TYPE=Release -DMUTEKIZU_GUI=ON
cmake --build "$ROOT/gui/build" -j"$(nproc)"

install -d "$PREFIX/bin" "$LIBEXEC" "$DATADIR/applications" \
    "$DATADIR/icons/hicolor/scalable/apps"
install -m 0755 "$ROOT/gui/build/gui/mutekizu-gui" "$PREFIX/bin/mutekizu-gui"
install -m 0755 "$ROOT/gui/build/gui/mutekizu-config-helper" \
    "$LIBEXEC/mutekizu-config-helper"
# The helper must be root-owned and must NOT be setuid; pkexec authorizes it.
chown root:root "$LIBEXEC/mutekizu-config-helper"
chmod 0755 "$LIBEXEC/mutekizu-config-helper"
install -m 0644 "$ROOT/gui/mutekizu.desktop" "$DATADIR/applications/mutekizu.desktop"
install -m 0644 "$ROOT/gui/icons/mutekizu.svg" \
    "$DATADIR/icons/hicolor/scalable/apps/mutekizu.svg"
command -v update-desktop-database >/dev/null && update-desktop-database "$DATADIR/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "$DATADIR/icons/hicolor" || true

if [ "$ALLOW_NOAUTH" = 1 ]; then
    POLKITDIR=${POLKITDIR:-/etc/polkit-1/rules.d}
    install -d -m 0750 "$POLKITDIR"
    install -m 0644 "$ROOT/gui/polkit/49-mutekizu-wheel.rules" \
        "$POLKITDIR/49-mutekizu-wheel.rules"
    systemctl try-reload-or-restart polkit 2>/dev/null || true
    echo "Polkit: passwordless management of mutekizu.service and the config helper for wheel/sudo (opt-in)."
fi

if [ "$AUTOSTART" = 1 ]; then
    target_user=${SUDO_USER:-}
    if [ -n "$target_user" ] && [ "$target_user" != root ]; then
        target_home=$(getent passwd "$target_user" | cut -d: -f6)
        target_group=$(id -gn "$target_user")
        install -d -o "$target_user" -g "$target_group" -m 0755 \
            "$target_home/.config/autostart"
        install -m 0644 -o "$target_user" -g "$target_group" \
            "$ROOT/gui/autostart/mutekizu.desktop" \
            "$target_home/.config/autostart/mutekizu.desktop"
        echo "Autostart: Mutekizu will open at $target_user's next login."
    else
        echo "Autostart: skipped (run via sudo from the target user)." >&2
    fi
fi

cat <<EOF

Installed GUI:
  $PREFIX/bin/mutekizu-gui
  $LIBEXEC/mutekizu-config-helper (root-owned, not setuid)
  $DATADIR/applications/mutekizu.desktop
  $DATADIR/icons/hicolor/scalable/apps/mutekizu.svg

The GUI starts as your normal user. Start/stop uses systemd D-Bus + Polkit.
Config writes use pkexec + the narrow helper. The engine and service unit are
NOT installed or enabled by this script.

Remove only the GUI: $ROOT/gui/uninstall-gui.sh
EOF

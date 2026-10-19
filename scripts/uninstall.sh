#!/usr/bin/env bash
# Remove mutekizu. --purge also removes /etc/mutekizu (config + domain list).
set -euo pipefail

PREFIX=${PREFIX:-/usr/local}
SYSCONFDIR=${SYSCONFDIR:-/etc}
UNITDIR=${UNITDIR:-/usr/lib/systemd/system}
LIBEXEC=${LIBEXEC:-/usr/libexec}
DATADIR=${DATADIR:-/usr/share}
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root" >&2
    exit 1
fi

systemctl disable --now mutekizu 2>/dev/null || true
# Remove only our own nft table, if the binary is still present.
if [ -x "$PREFIX/bin/mutekizu" ]; then
    "$PREFIX/bin/mutekizu" --config "$SYSCONFDIR/mutekizu/mutekizu.conf" rules remove || true
fi
rm -f "$UNITDIR/mutekizu.service" "$PREFIX/bin/mutekizu"
rm -f "$PREFIX/bin/mutekizu-gui" "$LIBEXEC/mutekizu-config-helper"
rm -f "$DATADIR/applications/mutekizu.desktop"
rm -f "$DATADIR/icons/hicolor/scalable/apps/mutekizu.svg"
rm -f /etc/polkit-1/rules.d/49-mutekizu-wheel.rules
rmdir "$PREFIX/share/doc/mutekizu" 2>/dev/null || true
systemctl daemon-reload

if [ "$PURGE" = 1 ]; then
    rm -rf "$SYSCONFDIR/mutekizu" /var/lib/mutekizu /run/mutekizu
fi

if getent passwd mutekizu >/dev/null; then
    userdel mutekizu 2>/dev/null || true
fi
if getent group mutekizu >/dev/null; then
    groupdel mutekizu 2>/dev/null || true
fi

if [ "$PURGE" = 1 ]; then
    echo "mutekizu removed (config purged)"
else
    echo "mutekizu removed (config kept)"
fi

#!/usr/bin/env bash
# Remove only GUI/helper/desktop/icon. The mutekizu engine, service unit and
# /etc/mutekizu configuration are left untouched.
set -euo pipefail

PREFIX=${PREFIX:-/usr/local}
LIBEXEC=${LIBEXEC:-/usr/libexec}
DATADIR=${DATADIR:-/usr/share}

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run with sudo $0" >&2
    exit 1
fi

rm -f "$PREFIX/bin/mutekizu-gui"
rm -f "$LIBEXEC/mutekizu-config-helper"
rm -f "$DATADIR/applications/mutekizu.desktop"
rm -f "$DATADIR/icons/hicolor/scalable/apps/mutekizu.svg"
command -v update-desktop-database >/dev/null && update-desktop-database "$DATADIR/applications" || true

echo "GUI removed. Engine, service unit and /etc/mutekizu were not touched."

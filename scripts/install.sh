#!/usr/bin/env bash
# Install mutekizu. Does NOT enable or start the service automatically.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${PREFIX:-/usr/local}
SYSCONFDIR=${SYSCONFDIR:-/etc}
UNITDIR=${UNITDIR:-/usr/lib/systemd/system}
DOCDIR=${DOCDIR:-$PREFIX/share/doc/mutekizu}
FORCE=${FORCE:-0}

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (sudo $0)" >&2
    exit 1
fi

for tool in cmake g++ pkg-config nft systemctl; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: missing '$tool'. On CachyOS/Arch install:" >&2
        echo "  sudo pacman -S --needed base-devel cmake pkgconf nftables libnetfilter_queue" >&2
        exit 1
    }
done
pkg-config --exists libnetfilter_queue || {
    echo "error: libnetfilter_queue development files not found" >&2
    echo "  sudo pacman -S --needed libnetfilter_queue" >&2
    exit 1
}

echo "== build =="
cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$ROOT/build" -j"$(nproc)"

install -d "$PREFIX/bin" "$SYSCONFDIR/mutekizu" "$UNITDIR" "$DOCDIR"
install -m 0755 "$ROOT/build/mutekizu" "$PREFIX/bin/mutekizu"
sed "s#/usr/local/bin/mutekizu#$PREFIX/bin/mutekizu#g; s#/usr/local/share/doc/mutekizu#$DOCDIR#g" \
    "$ROOT/systemd/mutekizu.service" > "$UNITDIR/mutekizu.service"
chmod 0644 "$UNITDIR/mutekizu.service"
install -m 0644 "$ROOT/README.md" "$DOCDIR/README.md" 2>/dev/null || true

install -m 0644 "$ROOT/config/mutekizu.conf" "$SYSCONFDIR/mutekizu/mutekizu.conf.new"
if [ -f "$SYSCONFDIR/mutekizu/mutekizu.conf" ] && [ "$FORCE" != 1 ]; then
    echo "keeping existing $SYSCONFDIR/mutekizu/mutekizu.conf (new: .new)"
else
    install -m 0644 "$ROOT/config/mutekizu.conf" "$SYSCONFDIR/mutekizu/mutekizu.conf"
fi
if [ -f "$SYSCONFDIR/mutekizu/domains.txt" ] && [ "$FORCE" != 1 ]; then
    echo "keeping existing $SYSCONFDIR/mutekizu/domains.txt (example: .new)"
    install -m 0644 "$ROOT/config/domains.txt" "$SYSCONFDIR/mutekizu/domains.txt.new"
else
    install -m 0644 "$ROOT/config/domains.txt" "$SYSCONFDIR/mutekizu/domains.txt"
fi
if [ -f "$SYSCONFDIR/mutekizu/profiles.conf" ] && [ "$FORCE" != 1 ]; then
    echo "keeping existing $SYSCONFDIR/mutekizu/profiles.conf (example: .new)"
    install -m 0644 "$ROOT/config/profiles.conf" "$SYSCONFDIR/mutekizu/profiles.conf.new"
else
    install -m 0644 "$ROOT/config/profiles.conf" "$SYSCONFDIR/mutekizu/profiles.conf"
fi
if [ -f "$SYSCONFDIR/mutekizu/ip_frag_targets.txt" ] && [ "$FORCE" != 1 ]; then
    echo "keeping existing $SYSCONFDIR/mutekizu/ip_frag_targets.txt (example: .new)"
    install -m 0644 "$ROOT/config/ip_frag_targets.txt" "$SYSCONFDIR/mutekizu/ip_frag_targets.txt.new"
else
    install -m 0644 "$ROOT/config/ip_frag_targets.txt" "$SYSCONFDIR/mutekizu/ip_frag_targets.txt"
fi
if [ -f "$SYSCONFDIR/mutekizu/mss_targets.txt" ] && [ "$FORCE" != 1 ]; then
    echo "keeping existing $SYSCONFDIR/mutekizu/mss_targets.txt (example: .new)"
    install -m 0644 "$ROOT/config/mss_targets.txt" "$SYSCONFDIR/mutekizu/mss_targets.txt.new"
else
    install -m 0644 "$ROOT/config/mss_targets.txt" "$SYSCONFDIR/mutekizu/mss_targets.txt"
fi

if ! getent group mutekizu >/dev/null; then
    groupadd --system mutekizu
fi
if ! getent passwd mutekizu >/dev/null; then
    useradd --system --gid mutekizu --home-dir /nonexistent \
        --shell /usr/sbin/nologin --comment "mutekizu" mutekizu
fi

systemctl daemon-reload
cat <<EOF

Installed.

Next steps:
  1. Review $SYSCONFDIR/mutekizu/mutekizu.conf and domains.txt
  2. $PREFIX/bin/mutekizu doctor
  3. $PREFIX/bin/mutekizu --dry-run run
  4. sudo systemctl enable --now mutekizu
  5. journalctl -u mutekizu -f

Uninstall: $ROOT/scripts/uninstall.sh [--purge]
EOF

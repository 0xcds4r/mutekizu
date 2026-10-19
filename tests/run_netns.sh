#!/usr/bin/env bash
# Isolated lab. Run as:  unshare -rn tests/run_netns.sh
#
# Creates a client (current) netns and a server netns connected by veth.
# The lab models a stateless DPI that drops any single TCP payload containing
# the full SNI string. It never touches the host network or firewall.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/build"
WORK=$(mktemp -d /tmp/dpi-lab.XXXXXX)
FAILS=0
CHECKS=0

if [ "$(id -u)" -ne 0 ]; then
    echo "run inside a user+network namespace: unshare -rn $0" >&2
    exit 2
fi

log()  { printf '\n=== %s ===\n' "$*"; }
pass() { CHECKS=$((CHECKS+1)); printf 'PASS: %s\n' "$*"; }
fail() { CHECKS=$((CHECKS+1)); FAILS=$((FAILS+1)); printf 'FAIL: %s\n' "$*"; }

SRV=""
SHIELD=""
MODEL=""
SERVER_APP=""
cleanup() {
    for p in "$SHIELD" "$MODEL" "$SERVER_APP"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    nft delete table inet mutekizu 2>/dev/null
    nft delete table inet dpi_model 2>/dev/null
    nft delete table inet keepme 2>/dev/null
    ip link del veth-cli 2>/dev/null
    [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

wait_for_file_line() {
    local file=$1 needle=$2 n=0
    while [ $n -lt 100 ]; do
        grep -q "$needle" "$file" 2>/dev/null && return 0
        sleep 0.05
        n=$((n+1))
    done
    return 1
}

# ---------------------------------------------------------------- namespaces
log "setup namespaces and veth"
unshare -n sleep 3600 & SRV=$!
ip link add veth-cli type veth peer name veth-srv || exit 1
ip link set veth-srv netns "$SRV"
ip addr add 10.0.0.2/24 dev veth-cli
ip link set veth-cli up
nsenter -t "$SRV" -n ip addr add 10.0.0.1/24 dev veth-srv
nsenter -t "$SRV" -n ip addr add 10.0.0.3/24 dev veth-srv
nsenter -t "$SRV" -n ip link set veth-srv up
nsenter -t "$SRV" -n ip link set lo up
ip link set lo up
ip -6 addr add fd00::2/64 dev veth-cli nodad
nsenter -t "$SRV" -n ip -6 addr add fd00::1/64 dev veth-srv nodad
nsenter -t "$SRV" -n ip -6 addr add fd00::3/64 dev veth-srv nodad
echo "client: $(ip -4 -o addr show veth-cli | awk '{print $4}') | $(ip -6 -o addr show veth-cli | awk '{print $4}')"
echo "server: $(nsenter -t "$SRV" -n ip -4 -o addr show veth-srv | awk '{print $4}')"

# ---------------------------------------------------------------- certificates
log "generate lab CA and server certificate"
LONG_SNI="$(python3 -c 'print("a"*60 + "." + "b"*60 + ".test.example")')"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=mutekizu-lab-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$WORK/ca.key" -out "$WORK/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=test.example" \
    -keyout "$WORK/server.key" -out "$WORK/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:test.example,DNS:other.example,DNS:*.test.example,DNS:%s,IP:10.0.0.1,IP:10.0.0.3,IP:fd00::1,IP:fd00::3\nextendedKeyUsage=serverAuth\n' "$LONG_SNI" > "$WORK/san.cnf"
openssl x509 -req -days 1 -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
    -CAcreateserial -extfile "$WORK/san.cnf" -out "$WORK/server.pem" >/dev/null 2>&1

# ---------------------------------------------------------------- TLS server
log "start TLS echo server in server netns"
nsenter -t "$SRV" -n python3 "$ROOT/tests/tls_echo.py" server \
    --host :: --port 443 --cert "$WORK/server.pem" --key "$WORK/server.key" \
    > "$WORK/server.log" 2>&1 &
SERVER_APP=$!
wait_for_file_line "$WORK/server.log" "listening" || { cat "$WORK/server.log"; exit 1; }

restart_server() {
    [ -n "$SERVER_APP" ] && kill "$SERVER_APP" 2>/dev/null
    [ -n "$SERVER_APP" ] && wait "$SERVER_APP" 2>/dev/null
    : > "$WORK/server.log"
    nsenter -t "$SRV" -n python3 "$ROOT/tests/tls_echo.py" server \
        --host :: --port 443 --cert "$WORK/server.pem" --key "$WORK/server.key" \
        > "$WORK/server.log" 2>&1 &
    SERVER_APP=$!
    wait_for_file_line "$WORK/server.log" "listening" || { cat "$WORK/server.log"; exit 1; }
}

# ---------------------------------------------------------------- config
cat > "$WORK/domains.txt" <<'EOF'
test.example
EOF
cat > "$WORK/config.conf" <<EOF
queue_num=2000
fwmark=0x44495054
max_queue_len=256
copy_range=65535
split_delta=4
mss=1200
inspect_packets=10
ipv4=true
ipv6=true
ports=443
domains_file=$WORK/domains.txt
log_level=debug
log_sni=true
max_flows=1024
flow_buffer=8192
flow_timeout_s=30
EOF

start_shield() {
    local conf=${1:-$WORK/config.conf}
    MUTEKIZU_PIDFILE="$WORK/pid" "$BIN/mutekizu" --config "$conf" run \
        >> "$WORK/shield.log" 2>&1 &
    SHIELD=$!
    local n=0
    while [ $n -lt 100 ]; do
        nft list table inet mutekizu >/dev/null 2>&1 && return 0
        sleep 0.05
        n=$((n+1))
    done
    return 1
}
stop_shield() {
    [ -n "$SHIELD" ] && kill "$SHIELD" 2>/dev/null
    wait "$SHIELD" 2>/dev/null
    SHIELD=""
}

start_model() { # [needle] [mode]
    local needle=${1:-} mode=${2:-needle}
    nft add table inet dpi_model
    nft add chain inet dpi_model out '{ type filter hook output priority -100; policy accept; }'
    nft add rule inet dpi_model out tcp dport 443 'tcp flags & (syn|rst|fin) == 0' \
        queue num 2001 bypass
    if [ "$mode" = hello ]; then
        "$BIN/dpi-model" --queue 2001 --mode hello >> "$WORK/model.log" 2>&1 &
    else
        "$BIN/dpi-model" --queue 2001 --needle "$needle" >> "$WORK/model.log" 2>&1 &
    fi
    MODEL=$!
    sleep 0.3
}
stop_model() {
    [ -n "$MODEL" ] && kill "$MODEL" 2>/dev/null
    wait "$MODEL" 2>/dev/null
    MODEL=""
    nft delete table inet dpi_model 2>/dev/null
}

run_client() { # host sni [size] [timeout] [curve]
    local host=$1 sni=$2 size=${3:-262144} tmo=${4:-6} curve=${5:-X25519}
    timeout $((tmo+4)) python3 "$ROOT/tests/tls_echo.py" client \
        --host "$host" --port 443 --sni "$sni" --ca "$WORK/ca.pem" \
        --size "$size" --timeout "$tmo" --curve "$curve" 2>&1
}

# ---------------------------------------------------------------- baseline
log "baseline without shield/model (IPv4, IPv6)"
if run_client 10.0.0.1 test.example | grep -q '^OK'; then pass "baseline IPv4 TLS"; else fail "baseline IPv4 TLS"; fi
if run_client fd00::1 test.example | grep -q '^OK'; then pass "baseline IPv6 TLS"; else fail "baseline IPv6 TLS"; fi

# ---------------------------------------------------------------- model only
log "model only: naive DPI must break the handshake"
start_model "" hello
if run_client 10.0.0.1 test.example 4096 3 | grep -q '^OK'; then
    fail "model-only did not block (lab invalid)"
else
    pass "model-only blocks the unmodified ClientHello"
fi
stop_model

# ---------------------------------------------------------------- shield + model
log "shield + model"
start_shield || { fail "shield did not start"; cat "$WORK/shield.log"; exit 1; }
start_model "" hello
if out=$(run_client 10.0.0.1 test.example 262144 8); then
    echo "$out"
    echo "$out" | grep -q '^OK' && pass "split ClientHello passes naive DPI (IPv4, 256 KiB integrity)" || fail "split ClientHello (IPv4)"
else
    fail "split ClientHello (IPv4) - client error"
fi
if out=$(run_client fd00::1 test.example 262144 8); then
    echo "$out"
    echo "$out" | grep -q '^OK' && pass "split ClientHello passes naive DPI (IPv6)" || fail "split ClientHello (IPv6)"
else
    fail "split ClientHello (IPv6) - client error"
fi
stop_model

# ---------------------------------------------------------------- selectivity
log "selectivity: non-target SNI must be left untouched"
start_model "other.example" needle
if run_client 10.0.0.1 other.example 4096 3 | grep -q '^OK'; then
    fail "non-target traffic was modified unexpectedly"
else
    pass "non-target SNI is still dropped by the model (shield did not help it)"
fi
stop_model
stop_shield

if grep -q "target ClientHello for test.example" "$WORK/shield.log"; then
    pass "shield matched only the configured SNI"
else
    fail "shield did not log the expected target match"
fi

# ---------------------------------------------------------------- MTU
log "MTU 1280 and 9000"
for mtu in 1280 9000; do
    ip link set veth-cli mtu $mtu
    nsenter -t "$SRV" -n ip link set veth-srv mtu $mtu
    restart_server
    start_shield
    start_model "" hello
    out=$(run_client 10.0.0.1 test.example 131072 8)
    if echo "$out" | grep -q '^OK'; then
        pass "MTU $mtu with split + 128 KiB integrity"
    else
        fail "MTU $mtu"
        echo "$out" | tail -5
        echo "--- shield tail ---"; tail -12 "$WORK/shield.log"
        echo "--- model tail ---"; tail -4 "$WORK/model.log"
    fi
    stop_model
    stop_shield
done
ip link set veth-cli mtu 1500
nsenter -t "$SRV" -n ip link set veth-srv mtu 1500
restart_server

# ---------------------------------------------------------------- long SNI
log "long SNI (ClientHello spans segments at MTU 1280)"
long_sni="$LONG_SNI"
ip link set veth-cli mtu 1280
nsenter -t "$SRV" -n ip link set veth-srv mtu 1280
restart_server
start_shield
start_model "$long_sni" needle
if run_client 10.0.0.1 "$long_sni" 65536 8 default | grep -q '^OK'; then
    pass "long SNI split across TCP segments"
else
    fail "long SNI split across TCP segments"
fi
stop_model
stop_shield
ip link set veth-cli mtu 1500
nsenter -t "$SRV" -n ip link set veth-srv mtu 1500
restart_server

# ---------------------------------------------------------------- loss
log "loss/retransmission (5% netem)"
tc qdisc add dev veth-cli root netem loss 5% || true
start_shield
start_model "" hello
if run_client 10.0.0.1 test.example 131072 10 | grep -q '^OK'; then
    pass "5% loss with retransmissions and integrity"
else
    fail "5% loss"
fi
stop_model
stop_shield
tc qdisc del dev veth-cli root 2>/dev/null

# ---------------------------------------------------------------- restart / crash
log "restart and crash behaviour"
start_shield
start_model "" hello
run_client 10.0.0.1 test.example 4096 6 | grep -q '^OK' && pass "pre-restart connection" || fail "pre-restart connection"
kill -9 "$SHIELD" 2>/dev/null; wait "$SHIELD" 2>/dev/null; SHIELD=""
if nft list table inet mutekizu >/dev/null 2>&1; then
    pass "table survives SIGKILL (bypass keeps traffic flowing)"
else
    fail "table unexpectedly gone after SIGKILL"
fi
# With the dead queue and bypass, the model still blocks. Traffic must not be lost by nft.
if run_client 10.0.0.1 test.example 4096 3 | grep -q '^OK'; then
    fail "model bypassed after shield crash (unexpected)"
else
    pass "after crash, traffic continues unprocessed (model still blocks)"
fi
start_shield
if run_client 10.0.0.1 test.example 4096 6 | grep -q '^OK'; then
    pass "restart re-binds the queue and splits again"
else
    fail "restart"
fi
stop_model
stop_shield

# ---------------------------------------------------------------- foreign rules
log "foreign nftables objects are preserved"
nft add table inet keepme
nft add chain inet keepme c '{ type filter hook input priority 0; policy accept; }'
nft add rule inet keepme c counter
start_shield
stop_shield
if nft list table inet keepme >/dev/null 2>&1; then
    pass "foreign table survived apply/remove"
else
    fail "foreign table was removed"
fi
nft delete table inet keepme

# ---------------------------------------------------------------- ownership
log "a foreign table with our name must not be deleted"
nft add table inet mutekizu
nft add chain inet mutekizu foreign '{ type filter hook input priority 0; policy accept; }'
if "$BIN/mutekizu" -c "$WORK/config.conf" rules remove >/dev/null 2>&1; then
    fail "removed a foreign table with our name"
else
    pass "refused to touch a foreign table with our name"
fi
if nft list table inet mutekizu >/dev/null 2>&1; then
    pass "foreign table preserved"
else
    fail "foreign table disappeared"
fi
nft delete table inet mutekizu

# ---------------------------------------------------------------- MSS mode
log "MSS clamp mode (split disabled, explicit IP targets)"
printf '10.0.0.1\nfd00::1\n' > "$WORK/mss_targets.txt"
cat > "$WORK/mss.conf" <<EOF
split_enabled=false
mss_clamp=true
mss_value=96
mss_targets_file=$WORK/mss_targets.txt
queue_num=2000
fwmark=0x44495054
max_queue_len=256
copy_range=65535
inspect_packets=10
ipv4=true
ipv6=true
ports=443
domains_file=$WORK/domains.txt
log_level=debug
EOF
mss_of() { sed -n 's/.*mss=\([-0-9]*\).*/\1/p' <<<"$1"; }
start_shield "$WORK/mss.conf" || fail "MSS-only shield did not start"
out=$(run_client 10.0.0.1 test.example 4096 6); v=$(mss_of "$out")
echo "selected IPv4 mss=$v"
[ -n "$v" ] && [ "$v" -gt 0 ] && [ "$v" -le 96 ] && pass "MSS clamped on selected IPv4 (mss=$v)" || fail "MSS clamp selected IPv4 (mss=$v)"
out=$(run_client fd00::1 test.example 4096 6); v=$(mss_of "$out")
echo "selected IPv6 mss=$v"
[ -n "$v" ] && [ "$v" -gt 0 ] && [ "$v" -le 96 ] && pass "MSS clamped on selected IPv6 (mss=$v)" || fail "MSS clamp selected IPv6 (mss=$v)"
out=$(run_client 10.0.0.3 test.example 4096 6); v=$(mss_of "$out")
echo "unselected IPv4 mss=$v"
[ -n "$v" ] && [ "$v" -gt 96 ] && pass "MSS untouched on unselected IPv4 (mss=$v)" || fail "unselected IPv4 MSS (mss=$v)"
out=$(run_client fd00::3 test.example 4096 6); v=$(mss_of "$out")
echo "unselected IPv6 mss=$v"
[ -n "$v" ] && [ "$v" -gt 96 ] && pass "MSS untouched on unselected IPv6 (mss=$v)" || fail "unselected IPv6 MSS (mss=$v)"
run_client 10.0.0.1 test.example 32768 6 | grep -q '^OK' && pass "TLS integrity with clamped MSS" || fail "TLS integrity with clamped MSS"
stop_shield
out=$(run_client 10.0.0.1 test.example 4096 6); v=$(mss_of "$out")
echo "after stop mss=$v"
[ -n "$v" ] && [ "$v" -gt 96 ] && pass "rules removed on stop (mss=$v)" || fail "rules not removed on stop (mss=$v)"
start_shield "$WORK/mss.conf" || fail "MSS-only restart failed"
kill -9 "$SHIELD" 2>/dev/null; wait "$SHIELD" 2>/dev/null; SHIELD=""
out=$(run_client 10.0.0.1 test.example 4096 6); v=$(mss_of "$out")
[ -n "$v" ] && [ "$v" -le 96 ] && pass "stale MSS rules survive SIGKILL (mss=$v)" || fail "stale MSS rules (mss=$v)"
"$BIN/mutekizu" -c "$WORK/mss.conf" rules remove >/dev/null 2>&1
out=$(run_client 10.0.0.1 test.example 4096 6); v=$(mss_of "$out")
[ -n "$v" ] && [ "$v" -gt 96 ] && pass "rules remove after crash restores MSS (mss=$v)" || fail "rules remove after crash (mss=$v)"


# ---------------------------------------------------------------- auto discovery
log "auto-discovery: probe a blocked unknown SNI, remember it, split next time"
printf 'other.example\n' > "$WORK/auto-static.txt"
cat > "$WORK/auto.conf" <<EOF
split_enabled=true
mss_clamp=false
split_delta=4
split_stride=4
split_max=64
split_gap_ms=0
mss=1200
inspect_packets=10
queue_num=2000
fwmark=0x44495054
max_queue_len=256
copy_range=65535
ipv4=true
ipv6=true
ports=443
domains_file=$WORK/auto-static.txt
mss_targets_file=$WORK/mss_targets.txt
log_level=debug
log_sni=true
auto_discover=true
auto_domains_file=$WORK/auto-domains.txt
auto_probe_timeout_ms=2000
auto_probe_max=4
auto_domain_limit=4096
auto_probe_interval_s=60
max_flows=1024
flow_buffer=8192
flow_timeout_s=30
EOF
rm -f "$WORK/auto-domains.txt"
start_shield "$WORK/auto.conf"
start_model "test.example" needle
if run_client 10.0.0.1 test.example 4096 3 | grep -q '^OK'; then
    fail "auto-discovery first attempt unexpectedly bypassed"
else
    pass "unknown blocked SNI fails before auto-discovery"
fi
sleep 4
if grep -qx "test.example" "$WORK/auto-domains.txt" 2>/dev/null; then
    pass "blocked SNI was added to the auto list"
else
    fail "blocked SNI was not added to the auto list"
    tail -20 "$WORK/shield.log"
    cat "$WORK/auto-domains.txt" 2>/dev/null || true
fi
if run_client 10.0.0.1 test.example 4096 8 | grep -q '^OK'; then
    pass "next connection for the auto-added SNI is split and passes"
else
    fail "auto-added SNI was not split on the next connection"
fi
stop_model
stop_shield

# ---------------------------------------------------------------- disorder
log "advanced: reverse-order split segments still deliver TLS"
cat > "$WORK/order.conf" <<EOF
split_enabled=true
mss_clamp=false
split_delta=4
split_stride=4
split_max=64
split_gap_ms=0
split_disorder=true
fake_enabled=false
fake_ttl=3
fake_repeats=3
fake_sni=www.google.com
mss=1200
inspect_packets=10
queue_num=2000
fwmark=0x44495054
max_queue_len=256
copy_range=65535
ipv4=true
ipv6=true
ports=443
domains_file=$WORK/domains.txt
mss_targets_file=$WORK/mss_targets.txt
log_level=debug
log_sni=false
auto_discover=false
max_flows=1024
flow_buffer=8192
flow_timeout_s=30
EOF
start_shield "$WORK/order.conf"
start_model "" hello
if run_client 10.0.0.1 test.example 131072 8 | grep -q '^OK'; then
    pass "disorder split passes a stateless DPI with 128 KiB integrity"
else
    fail "disorder split failed TLS integrity"
fi
stop_model
stop_shield

log "advanced: multidisorder split segments still deliver TLS"
sed 's/^split_disorder=true/split_disorder=false/; s/^split_multidisorder=false/split_multidisorder=true/' \
    "$WORK/order.conf" > "$WORK/multiorder.conf"
start_shield "$WORK/multiorder.conf"
start_model "" hello
if run_client 10.0.0.1 test.example 131072 8 | grep -q '^OK'; then
    pass "multidisorder split passes a stateless DPI with 128 KiB integrity"
else
    fail "multidisorder split failed TLS integrity"
fi
stop_model
stop_shield

# ---------------------------------------------------------------- profiles
log "profiles: per-domain override is applied"
cat > "$WORK/profiles.conf" <<EOF
[test-profile]
domains = test.example
split_delta = 1
split_stride = 0
split_disorder = true
fake_enabled = false
seqovl_enabled = false
EOF
cp "$WORK/config" "$WORK/profile-main.conf"
printf 'profiles_file=%s\n' "$WORK/profiles.conf" >> "$WORK/profile-main.conf"
start_shield "$WORK/profile-main.conf"
start_model "" hello
if run_client 10.0.0.1 test.example 131072 8 | grep -q '^OK'; then
    pass "profile override keeps TLS integrity"
else
    fail "profile override failed TLS integrity"
fi
stop_model
stop_shield

# ---------------------------------------------------------------- auto profiles
log "auto-profile: failed candidate rotates on the next attempt"
cat > "$WORK/auto-profiles.conf" <<EOF
[bad]
domains = test.example
split_enabled = false

[good]
domains = test.example
split_enabled = true
split_disorder = true
fake_enabled = false
seqovl_enabled = false
EOF
cp "$WORK/config" "$WORK/auto-profile-main.conf"
printf 'profiles_file=%s\nauto_profile=true\nauto_retry_window_s=10\n' \
    "$WORK/auto-profiles.conf" >> "$WORK/auto-profile-main.conf"
start_shield "$WORK/auto-profile-main.conf"
start_model "" hello
if run_client 10.0.0.1 test.example 4096 3 | grep -q '^OK'; then
    fail "auto-profile bad candidate unexpectedly passed"
else
    pass "auto-profile first (bad) candidate fails"
fi
if run_client 10.0.0.1 test.example 131072 8 | grep -q '^OK'; then
    pass "auto-profile rotates to the good candidate"
else
    fail "auto-profile did not rotate"
fi
stop_model
stop_shield

# ---------------------------------------------------------------- performance




log "performance: 10 sequential connections x 64 KiB"
bench() {
    local label=$1 ok=0 start end
    start=$(date +%s%N)
    for _ in $(seq 1 10); do
        run_client 10.0.0.1 test.example 65536 8 | grep -q '^OK' && ok=$((ok+1))
    done
    end=$(date +%s%N)
    printf '%s: %d/10 ok, %d ms total\n' "$label" "$ok" "$(( (end-start)/1000000 ))"
}
bench "baseline (no shield/model)"
start_shield
start_model "" hello
bench "shield + naive model"
if [ -n "$SHIELD" ] && kill -0 "$SHIELD" 2>/dev/null; then
    ticks=$(awk '{print $14+$15}' "/proc/$SHIELD/stat" 2>/dev/null)
    rss=$(awk '/VmHWM/{print $2" "$3}' "/proc/$SHIELD/status" 2>/dev/null)
    echo "shield cpu ticks: ${ticks:-n/a}; peak RSS: ${rss:-n/a}"
    pass "shield alive after benchmark"
else
    fail "shield died during benchmark"
fi
stop_model
stop_shield

# ---------------------------------------------------------------- overflow
log "queue overflow with max_queue_len=1"
sed 's/^max_queue_len=.*/max_queue_len=1/' "$WORK/config.conf" > "$WORK/config-small.conf"
start_shield "$WORK/config-small.conf" || { fail "shield with small queue did not start"; }
start_model "" hello
ok=0
pids=()
for i in $(seq 1 6); do
    ( run_client 10.0.0.1 test.example 32768 6 | grep -q '^OK' && echo ok >> "$WORK/overflow.ok" ) &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
ok=$(wc -l < "$WORK/overflow.ok" 2>/dev/null || echo 0)
echo "overflow run: $ok/6 connections succeeded (fail-open, unprocessed packets may be filtered)"
if kill -0 "$SHIELD" 2>/dev/null; then
    pass "shield survived queue overflow"
else
    fail "shield crashed on queue overflow"
fi
# Removing our rules must never remove connectivity.
stop_model
stop_shield

# ---------------------------------------------------------------- summary
log "summary"
echo "checks: $CHECKS, failures: $FAILS"
if [ "$FAILS" -ne 0 ]; then
    echo "--- shield log (tail) ---"
    tail -40 "$WORK/shield.log" 2>/dev/null
    echo "--- model log ---"
    cat "$WORK/model.log" 2>/dev/null
    exit 1
fi
exit 0

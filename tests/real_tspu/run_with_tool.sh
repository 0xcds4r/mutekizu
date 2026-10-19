#!/usr/bin/env bash
# Apply the real mutekizu binary on the real path for a short, explicit test.
# Run with sudo. Only our own nft table is created/removed. DNS and QUIC are
# never changed. If --pause-zapret is given, zapret is stopped and restarted.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TOOL=${TOOL:-$ROOT/build/mutekizu}
IPMAP=${IPMAP:-$ROOT/tests/real_tspu/results/ip-map.txt}
OUT=${OUT:-$ROOT/tests/real_tspu/results/tool-run-$(date +%Y%m%d-%H%M%S)}
DOMAINS=""
REPEAT=1
SPLIT_STRIDE=4
SPLIT_DELTA=4
SPLIT_GAP=0
MAX_TIME=8
PAUSE_ZAPRET=0
ASSUME_YES=0
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --domains) DOMAINS=$2; shift 2 ;;
        --repeat) REPEAT=$2; shift 2 ;;
        --split-stride) SPLIT_STRIDE=$2; shift 2 ;;
        --split-delta) SPLIT_DELTA=$2; shift 2 ;;
        --split-gap) SPLIT_GAP=$2; shift 2 ;;
        --max-time) MAX_TIME=$2; shift 2 ;;
        --pause-zapret) PAUSE_ZAPRET=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

ZAP_WAS_ACTIVE=0
TOOL_PID=""
cleanup() {
    if [ -n "$TOOL_PID" ] && kill -0 "$TOOL_PID" 2>/dev/null; then
        kill -TERM "$TOOL_PID" 2>/dev/null || true
        wait "$TOOL_PID" 2>/dev/null || true
    fi
    "$TOOL" rules remove 2>/dev/null || true
    if [ "$PAUSE_ZAPRET" = 1 ] && [ "$ZAP_WAS_ACTIVE" = 1 ]; then
        systemctl start zapret 2>/dev/null || true
    fi
}
trap cleanup EXIT

if [ "$DRY_RUN" = 1 ]; then
    echo "dry-run: would use $TOOL, output $OUT"
    echo "dry-run: domains: ${DOMAINS:-all from $IPMAP}"
    [ "$PAUSE_ZAPRET" = 1 ] && echo "dry-run: would stop/restart zapret"
    echo "dry-run: would apply only inet mutekizu, run curl via --resolve, then remove it"
    exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run with sudo (needs CAP_NET_ADMIN and CAP_NET_RAW)" >&2
    exit 1
fi
for t in nft curl ip; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 1; }; done
[ -x "$TOOL" ] || { echo "missing $TOOL (build first)" >&2; exit 1; }

if nft list table inet mutekizu >/dev/null 2>&1; then
    echo "error: table inet mutekizu already exists; refusing to touch it" >&2
    exit 1
fi
mkdir -p "$OUT"
nft list ruleset > "$OUT/rules-before.txt" || true
if systemctl is-active --quiet zapret 2>/dev/null; then ZAP_WAS_ACTIVE=1; fi

if [ "$ASSUME_YES" -eq 0 ]; then
    echo "This will briefly apply the real mutekizu on this host."
    echo "  tool: $TOOL"
    echo "  domains: ${DOMAINS:-all from $IPMAP}"
    echo "  pause zapret: $PAUSE_ZAPRET (current active: $ZAP_WAS_ACTIVE)"
    echo "DNS and QUIC are not changed. Only inet mutekizu is created/removed."
    read -r -p "Continue? [y/N] " a
    [ "$a" = y ] || [ "$a" = Y ] || exit 1
fi

if [ "$PAUSE_ZAPRET" = 1 ] && [ "$ZAP_WAS_ACTIVE" = 1 ]; then
    systemctl stop zapret
fi

# Build the domain list and tool config.
if [ -z "$DOMAINS" ]; then
    DOMAINS=$(awk '!/^#/ && NF>=2 {printf "%s%s", sep, $1; sep=","}' "$IPMAP")
fi
: > "$OUT/domains.txt"
printf '%s\n' "$DOMAINS" | tr ',' '\n' | sed '/^$/d' >> "$OUT/domains.txt"
cat > "$OUT/config.conf" <<EOF
split_enabled=true
mss_clamp=false
split_delta=$SPLIT_DELTA
split_stride=$SPLIT_STRIDE
split_gap_ms=$SPLIT_GAP
split_max=64
queue_num=2000
fwmark=0x44495054
max_queue_len=256
copy_range=65535
inspect_packets=10
mss=1200
ipv4=true
ipv6=true
ports=443
domains_file=$OUT/domains.txt
log_level=info
log_sni=false
EOF

ip_for() {
    awk -v d="$1" '$1==d {print $2; exit}' "$IPMAP"
}

curl_phase() { # phase
    local phase=$1 d ip code time rc attempt
    for attempt in $(seq 1 "$REPEAT"); do
        while IFS= read -r d; do
            [ -z "$d" ] && continue
            ip=$(ip_for "$d")
            if [ -z "$ip" ]; then
                echo "{\"phase\":\"$phase\",\"domain\":\"$d\",\"attempt\":$attempt,\"ok\":false,\"error\":\"no_ip_map\"}" >> "$OUT/results.jsonl"
                continue
            fi
            set +e
            out=$(curl --http1.1 -H 'Connection: close' --resolve "$d:443:$ip" --max-time "$MAX_TIME" \
                       -sS -o /dev/null -w '%{http_code} %{time_total}' "https://$d/" \
                       2>"$OUT/curl.err")
            rc=$?
            set -e
            code=${out%% *}; time=${out##* }
            # A non-000 HTTP code means TCP+TLS+HTTP completed. rc=28 can still
            # happen when the peer keeps a connection open after the response.
            if [ "$code" != "000" ]; then ok=true; else ok=false; fi
            printf '{"phase":"%s","domain":"%s","ip":"%s","attempt":%d,"ok":%s,"code":"%s","time_s":%s,"rc":%d,"error":"%s"}\n' \
                "$phase" "$d" "$ip" "$attempt" "$ok" "${code:-}" "${time:-null}" "$rc" \
                "$(tr '\n' ' ' < "$OUT/curl.err" | cut -c1-160)" >> "$OUT/results.jsonl"
            echo "$phase#$attempt $d -> $ok (code=${code:-} rc=$rc)"
        done < "$OUT/domains.txt"
    done
}

echo "== baseline =="
curl_phase baseline

echo "== tool =="
"$TOOL" -c "$OUT/config.conf" run >> "$OUT/tool.log" 2>&1 &
TOOL_PID=$!
for _ in $(seq 1 100); do
    nft list table inet mutekizu >/dev/null 2>&1 && break
    kill -0 "$TOOL_PID" 2>/dev/null || { echo "tool exited" >&2; cat "$OUT/tool.log"; exit 1; }
    sleep 0.1
done
nft list table inet mutekizu >/dev/null 2>&1 || { echo "tool did not install rules" >&2; exit 1; }
curl_phase tool

kill -TERM "$TOOL_PID" 2>/dev/null || true
wait "$TOOL_PID" 2>/dev/null || true
TOOL_PID=""
"$TOOL" rules remove 2>/dev/null || true
if nft list table inet mutekizu >/dev/null 2>&1; then
    echo "warning: inet mutekizu still present; remove manually" >&2
fi

echo "== summary =="
python3 - "$OUT/results.jsonl" <<'PY'
import json, sys, collections
rows=[json.loads(l) for l in open(sys.argv[1])]
counts=collections.defaultdict(lambda: {"baseline":[0,0],"tool":[0,0]})
last=collections.defaultdict(dict)
for r in rows:
    d=r.get("domain"); ph=r.get("phase")
    if not d or ph not in ("baseline","tool"): continue
    counts[d][ph][1]+=1
    if r.get("ok"): counts[d][ph][0]+=1
    last[d][ph]=r.get("code","-")
for d in sorted(counts):
    b=counts[d]["baseline"]; t=counts[d]["tool"]
    print(f"{d:22s} baseline={b[0]}/{b[1]} tool={t[0]}/{t[1]} "
          f"last_code {last[d].get('baseline','-')}/{last[d].get('tool','-')}")
PY
echo "results: $OUT/results.jsonl"
echo "rules snapshot: $OUT/rules-before.txt"
if [ "$PAUSE_ZAPRET" = 1 ] && [ "$ZAP_WAS_ACTIVE" = 1 ]; then
    echo "zapret will be restarted by cleanup (or is already active)"
fi

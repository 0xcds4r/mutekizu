#!/usr/bin/env bash
set -euo pipefail
helper=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 - "$tmp" <<'PY'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
base = {
    "version": 1,
    "settings": {
        "split_enabled": True, "mss_clamp": False, "split_delta": 4,
        "split_stride": 4, "split_max": 64, "split_gap_ms": 0, "mss": 1200,
        "mss_value": 96, "inspect_packets": 10, "queue_num": 2000,
        "fwmark": "0x44495054", "max_queue_len": 256, "copy_range": 65535,
        "ipv4": True, "ipv6": True, "ports": "443", "log_level": "info",
        "log_sni": False, "max_flows": 1024, "flow_buffer": 8192,
        "flow_timeout_s": 30, "domains_file": "/etc/mutekizu/domains.txt",
        "mss_targets_file": "/etc/mutekizu/mss_targets.txt"
    },
    "domains": ["example.com"], "mss_targets": []
}
(d/"valid.json").write_text(json.dumps(base))
bad = json.loads(json.dumps(base)); bad["domains"] = ["bad domain"]
(d/"bad-domain.json").write_text(json.dumps(bad))
bad2 = json.loads(json.dumps(base)); bad2["settings"]["split_delta"] = 0
(d/"bad-range.json").write_text(json.dumps(bad2))
bad3 = json.loads(json.dumps(base)); bad3["settings"]["mss_clamp"] = True; bad3["mss_targets"] = ["192.0.2.0/24"]
(d/"bad-cidr.json").write_text(json.dumps(bad3))
PY
"$helper" --check < "$tmp/valid.json" | grep -q '"ok":true' || { echo "valid payload rejected"; exit 1; }
for f in bad-domain bad-range bad-cidr; do
    if "$helper" --check < "$tmp/$f.json" >/dev/null 2>&1; then
        echo "$f unexpectedly accepted"; exit 1
    fi
done
echo "helper check tests OK"

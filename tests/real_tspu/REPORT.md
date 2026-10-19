# Real-path check — 2026-10-20

## 0. Privilege status

The actual privileged binary **was executed by the user** with `sudo` on
2026-10-20 02:55–02:58 (see §8). The agent's own shell has no
CAP_NET_ADMIN/CAP_NET_RAW, so the agent could not run it directly; the
unprivileged parts below were run by the agent.

What *was* run unprivileged on the real path:

1. read-only probe of DNS/TCP/TLS behavior (`tests/real_probe.py`);
2. a direct, certificate-verified TLS client that reproduces **the same wire
   mechanism** as mutekizu's split (real ClientHello from `ssl.MemoryBIO`,
   written as separate TCP segments with `TIOCOUTQ` pacing) — no proxy, no VPN,
   no MITM, no firewall/DNS/QUIC changes (`tests/real_split_probe.py`);
3. a sudo-ready experiment script for the actual binary
   (`tests/real_tspu/run_with_tool.sh`), which was only dry-run here.

## 1. Environment and method

* `Linux 7.2.9-2-cachyos`, zapret active (queue 200), mutekizu **not active**.
* Public IP unchanged; direct connections to real destination IPs.
* DNS: system resolver, plaintext 1.1.1.1/8.8.8.8, and DoH (dns.google /
  cloudflare-dns.com).
* TLS client: Python/OpenSSL, certificate and hostname verification **enabled**
  (no `-k`, no custom CA). Split modes: baseline (one write), `split`
  (SNI+4), `multi` (every 4 bytes inside SNI).
* All measurements are single-shot probes from one network/time; not statistics.

## 2. DNS findings

* System DNS is poisoned for several targets, e.g. Instagram/Facebook/X/
  Telegram return `89.125.87.96` (`hugedev.ru`).
* **Plaintext** queries to 1.1.1.1 and 8.8.8.8 also return forged answers or
  `NXDOMAIN` for `www.youtube.com` and `rutracker.org` (`status: NXDOMAIN`,
  `flags: qr aa`) — the DNS path is intercepted regardless of the resolver IP.
* DoH gave real addresses for most blocked targets (Facebook, X, Telegram,
  Discord, YouTube), but **not for all** (`example.com`, `meduza.io` got
  `8.47.69.x`, which is not the real Cloudflare address). DoH cannot be assumed
  clean on this path.
* mutekizu does not change DNS. Any target whose failure starts at DNS needs a
  separate DNS solution.

## 3. Real segmentation experiment

Control destinations (prove the probe and split path are correct):

| target | baseline | split | multi | cert |
|---|---|---|---|---|
| example.com | OK (HTTP 200) | OK | OK | example.com |
| github.com | OK | OK | OK | github.com |
| en.wikipedia.org | OK | OK | OK | *.wikipedia.org |

Controls verify successfully with the system CA; the split/multi writes reach
the server and the TLS transcript is intact.

Blocked/restricted destinations (real IPs from DoH/system, explicit `--resolve`
in the privileged script; here direct IPs):

| target | TCP | baseline | split | multi | outcome |
|---|---|---|---|---|---|
| facebook.com / www | connect | timeout | timeout | timeout | no change |
| x.com / twitter.com | connect | timeout | timeout | timeout | no change |
| linkedin.com / www | connect | timeout | timeout | timeout | no change |
| rutracker.org | connect | timeout | timeout | timeout | no change |
| discord.com | connect | timeout | timeout | timeout | no change |
| www.youtube.com | connect | timeout | timeout | timeout | no change |
| meduza.io | connect | timeout | timeout | timeout | no change |
| instagram.com / www | **TCP fail** (real IP) | — | — | — | IP-level |
| telegram.org / web.telegram.org | **TCP fail** (real IP) | — | — | — | IP-level |

Small (`X25519`, ~300 B) and large (PQ, ~1.5 KB) ClientHellos gave the same
negative result for Facebook/X/Discord/YouTube: the block is not merely
"complete ClientHello in one TCP segment" in this network.

Additional observation from `real_probe.py`: for Facebook, a **neutral SNI**
handshake succeeded on the same real IP while the real SNI timed out; for
Discord/YouTube a no-SNI handshake succeeded. That suggests SNI/flow-sensitive
filtering, but segmentation alone did not change the outcome. This is consistent
with TCP reassembly, IP/flow-level filtering, or a ClientHello-fingerprint rule;
the probe cannot distinguish those.

## 4. Confounds and limits

* The actual mutekizu binary was not applied (no CAP_NET_ADMIN). The split was
  reproduced by the client's own TCP stack; the wire-level segment shape is the
  same, but the tool's raw-packet path (and its `SO_MARK`, conntrack selection)
  was not exercised on the real host.
* zapret is active and may already desync these flows; the comparison is
  "baseline vs split, both under zapret", not a clean TSPU-only measurement.
  `run_with_tool.sh --pause-zapret` is provided for an isolated run, but it was
  not executed here.
* Python/OpenSSL ClientHello differs from Chromium/Electron (extensions, ALPN,
  PQ). The browser may pass where the probe fails (the user's Discord/YouTube
  work), so this is not a browser-equivalent test.
* DNS/DoH answers and IPs change; the IP map is a snapshot.
* Real DPI placement, asymmetry and reassembly behavior are unknown; these
  results do not generalize to every ISP or to all protocols.

## 5. Privileged experiment (for the user)

`tests/real_tspu/run_with_tool.sh` (run with `sudo`):

* refuses if a foreign `inet mutekizu` exists;
* snapshots `nft list ruleset` (read-only) to the output dir;
* optional `--pause-zapret` (explicit, restarted in the exit trap);
* applies only `inet mutekizu` (queue 2000, split at SNI+4, multi stride 4),
  writes domains from `results/ip-map.txt`;
* baseline phase: `curl --http1.1 --resolve domain:443:real_ip` (TLS verify on,
  no DNS use);
* tool phase: the same curl with the real binary active;
* stops the tool, removes only its table, restarts zapret if paused;
* never changes DNS or QUIC, never flushes the ruleset.

Commands:

```bash
cd ~/mutekizu
sudo tests/real_tspu/run_with_tool.sh --dry-run
sudo tests/real_tspu/run_with_tool.sh --pause-zapret --yes
# or without --pause-zapret to keep the current zapret state
```

Interpretation: only `baseline=false → tool=true` (with verified TLS) is a real
positive for the mechanism on that path. `baseline=true` means zapret/other
factors already handle it. Both false means the block is outside the
segment-boundary family (DNS/IP/reassembly/flow).

## 6. Actual privileged run (user-executed)

Command (zapret paused for both phases):

```
sudo tests/real_tspu/run_with_tool.sh --pause-zapret --yes
```

Run dir: `tests/real_tspu/results/tool-run-20261020-025533/`.
Tool log: `packets=2875 splits=38 parse_errors=11 send_errors=0`.

| target | baseline | tool | code | verdict |
|---|---|---|---|---|
| example.com | true | true | 200/200 | control OK |
| en.wikipedia.org | true | true | 301/301 | control OK |
| github.com | true* | true* | 200/200 | control OK (see note) |
| **rutracker.org** | **false** | **true** | **000/301** | **real positive** |
| facebook.com / www | false | false | 000/000 | not helped |
| x.com / twitter.com | false | false | 000/000 | not helped |
| linkedin.com / www | false | false | 000/000 | not helped |
| discord.com | false | false | 000/000 | not helped |
| www.youtube.com | false | false | 000/000 | not helped |
| meduza.io | false | false | 000/000 | not helped |
| telegram.org / web.telegram.org | false | false | 000/000 | TCP/IP-level |

`*` `curl` returned `code=200` but `rc=28` after 8 s with a partial body; the
TLS handshake, certificate verification and HTTP response succeeded. The first
script version incorrectly treated `rc!=0` as failure; the updated script treats
any non-`000` HTTP code as success and adds `Connection: close`.

Interpretation: with zapret paused, mutekizu's split (`split_delta=4`,
`split_stride=4`) made **rutracker.org** work on the real path (baseline 000 →
tool 301), while the controls stayed green. It did not help Meta/X/LinkedIn/
Discord/YouTube/Meduza or Telegram in this run. This is a genuine real-path
positive for one SNI-filtered destination and a negative for the others; it is
also a single run, not a reliability measurement.

## 7. Honest conclusion

The real tool has now been run on the real path and bypassed **intermittently**
several SNI-blocked destinations: rutracker (~29%), x.com, www.youtube.com and
gateway.discord.gg (1/5 each), aggregate ~21%. `discord.com` remained blocked
(0/5), and Facebook/LinkedIn/Meduza/Telegram were not helped in the earlier run.
The effect is real but weak and not a dependable bypass; the x.com success took
10 s and is marginal. The unprivileged
mechanism probe gave the same negative result for those destinations; controls
passed with verified certificates, so it is not a probe failure.

The synthetic arena (`tests/arena/results/REPORT.md`) shows where segmentation
works (L1/L2) and where it cannot (L4/L5). The real positive on rutracker is
consistent with an SNI/segment-boundary filter there; the remaining negatives
are consistent with deeper filtering. Do not generalize either result to all
ISPs or all protocols.

## 7b. x.com, YouTube, Discord (5 attempts, zapret off)

Run: `tool-run-20261020-034321`. Tool log: `packets=4984 splits=50
send_errors=0 parse_errors=5`.

| target | baseline | tool | notes |
|---|---|---|---|
| x.com | 0/5 | **1/5** | code 200, but 10.0 s (rc 28) — marginal |
| www.youtube.com | 0/5 | **1/5** | code 200, 1.08 s |
| gateway.discord.gg | 0/5 | **1/5** | code 404, 0.51 s (TLS+HTTP OK; 404 is normal for a plain GET) |
| discord.com | 0/5 | 0/5 | not helped |

Aggregate with the rutracker runs: multi-split **7/34 ≈ 21%** across the tested
SNI-blocked destinations; baseline **0/46**. The successes are real but sparse.
`www.youtube.com` is only the page; video uses `googlevideo.com` and was not
tested. Discord Desktop uses `gateway.discord.gg` and CDNs in addition to
`discord.com`.

## 7c. Segment gap experiment (x.com, YouTube, Discord gateway; 5 attempts each)

All runs with zapret off, multi split (`split_stride=4`), `--max-time 8`:

| split_gap_ms | x.com | www.youtube.com | gateway.discord.gg | total |
|---|---|---|---|---|
| 0 | 0/5 | **1/5** | **1/5** | **2/15** |
| 2 | 0/5 | 0/5 | 0/5 | 0/15 |
| 5 | 0/5 | 0/5 | 0/5 | 0/15 |
| 10 | 0/5 | 0/5 | 0/5 | 0/15 |

Baseline in all four runs: 0/5 per target (0/60). Tool logs: 33-38 splits per
run, **0 send errors** in all runs.

Conclusion: **no evidence that a delay helps**; in this sample gap 0 is the only
one with successes (2/15), and gaps 2/5/10 are 0/15. The sample is small and the
runs were sequential, so time-varying DPI state cannot be excluded, but the
hypothesis "the DPI needs a gap to be confused" is not supported. `split_gap_ms`
stays experimental and defaults to 0.

## 7a. Reproducibility run (rutracker, 3 attempts each)

The user repeated the focused test:

| split mode | baseline | tool |
|---|---|---|
| `split_stride=4` (multi) | 0/3 | **1/3** (code 301 on attempt 2) |
| `split_stride=0` (single) | 0/3 | 0/3 |

Then 10 attempts per mode with `--max-time 10`:

| split mode | baseline | tool |
|---|---|---|
| multi (`split_stride=4`) | 0/10 | **2/10** |
| single (`split_stride=0`) | 0/10 | **1/10** |

Aggregate over all runs on rutracker:

* multi: 1/1 + 1/3 + 2/10 = **4/14 (28.6%)**;
* single: 0/3 + 1/10 = **1/13 (7.7%)**;
* baseline: 0/6 + 0/10 + 0/10 = **0/26**.

Tool logs: 2306/2488 packets, 25/27 splits, 0 send errors, 5/1 parse errors.
The 301 responses are fast (~0.5 s); failures are 10 s timeouts.

The effect is **real but weak and intermittent**, not a reliable bypass. Multi is
better than single, but 2/10 is not a dependable success rate. Possible causes:
stateful/probabilistic DPI, CDN/IP path variation, raw-segment ordering, or
success depending on a specific flow. These runs cannot separate those causes.

## 8. Reproducibility next step

For a focused repeat (3 attempts) and to compare single vs multi split:

```bash
sudo tests/real_tspu/run_with_tool.sh --pause-zapret --yes \
  --domains rutracker.org --repeat 3
sudo tests/real_tspu/run_with_tool.sh --pause-zapret --yes \
  --domains rutracker.org --repeat 3 --split-stride 0
```

`--split-stride 4` is multi (current); `--split-stride 0` is one boundary at
`split_delta=4`. Results are appended as JSONL with an `attempt` field.

For a more meaningful rate estimate, use more attempts and a longer timeout
(the current 8 s may cut off tool-induced retransmission):

```bash
sudo tests/real_tspu/run_with_tool.sh --pause-zapret --yes \
  --domains rutracker.org --repeat 10 --max-time 15
```

Run the same with `--split-stride 0` for the single-boundary control. Report
successes as `k/N`, not as a single PASS; one 301 is not a guarantee.

## 7. Files

* `tests/real_probe.py`, `tests/real_split_probe.py`
* `tests/real_tspu/run_with_tool.sh`
* `results/real-probe.jsonl`, `results/real-split.jsonl`,
  `results/real-split-x25519.jsonl`, `results/ip-map.txt`

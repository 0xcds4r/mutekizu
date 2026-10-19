#!/usr/bin/env python3
"""Adversarial arena: mutekizu vs a synthetic DPI ladder.

Topology (inside one unprivileged user namespace):
    client netns (current) --veth-- mid netns --veth-- server netns

Client runs the real mutekizu binary. The mid runs dpi-ladder, a configurable
NFQUEUE model. The server is a local TLS echo server with a lab CA. Nothing
touches the host firewall, DNS or QUIC settings.

Run:
    unshare -rn python3 tests/arena/arena.py --out tests/arena/results/arena.jsonl
"""
import argparse
import json
import os
import pathlib
import re
import select
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "build"
SHIELD = BIN / "mutekizu"
LADDER = BIN / "dpi-ladder"
TLS = ROOT / "tests" / "tls_echo.py"

CLIENT4 = "10.90.1.2"
CLIENT6 = "fd90:1::2"
MID4 = "10.90.1.1"
MID42 = "10.90.2.1"
MID6 = "fd90:1::1"
MID62 = "fd90:2::1"
SERVER4 = "10.90.2.2"
SERVER42 = "10.90.2.3"
SERVER6 = "fd90:2::2"
SERVER62 = "fd90:2::3"

BLOCKED = "test.example"
ALLOWED = "other.example"
LONG_SNI = "a" * 60 + "." + "b" * 60 + "." + BLOCKED

STRATEGIES = {
    "none": None,
    "split_d1": {"split": True, "mss": False, "delta": 1, "mss_value": 96},
    "split_d4": {"split": True, "mss": False, "delta": 4, "mss_value": 96},
    "split_d8": {"split": True, "mss": False, "delta": 8, "mss_value": 96},
    "mss96": {"split": False, "mss": True, "delta": 4, "mss_value": 96},
    "mss136": {"split": False, "mss": True, "delta": 4, "mss_value": 136},
    "split4_mss136": {"split": True, "mss": True, "delta": 4, "mss_value": 136},
    "split_multi": {"split": True, "mss": False, "delta": 4, "stride": 4,
                    "mss_value": 96},
    "split_multi_gap": {"split": True, "mss": False, "delta": 4, "stride": 4,
                        "gap": 5, "mss_value": 96},
}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def run(argv, timeout=20, input_text=None):
    return subprocess.run(argv, input=input_text, capture_output=True, text=True,
                          timeout=timeout)


def must(argv, timeout=20, input_text=None):
    r = run(argv, timeout=timeout, input_text=input_text)
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(argv)}\n"
                           f"stdout: {r.stdout}\nstderr: {r.stderr}")
    return r


def cap_effective():
    try:
        for line in pathlib.Path("/proc/self/status").read_text().splitlines():
            if line.startswith("CapEff:"):
                return int(line.split()[1], 16)
    except OSError:
        pass
    return 0


def has_caps():
    eff = cap_effective()
    # CAP_NET_ADMIN=12, CAP_NET_RAW=13
    return bool(eff & (1 << 12)) and bool(eff & (1 << 13))


def wait_line(proc, needle, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r, _, _ = select.select([proc.stdout], [], [], 0.2)
        if r:
            line = proc.stdout.readline()
            if not line:
                break
            if needle in line:
                return line
        if proc.poll() is not None:
            break
    err = proc.stderr.read() if proc.stderr else ""
    raise RuntimeError(f"process did not print {needle!r}; stderr={err}")


class Netns:
    def __init__(self):
        self.proc = subprocess.Popen(["unshare", "-n", "sleep", "3600"])
        time.sleep(0.15)

    def argv(self, args):
        return ["nsenter", "-t", str(self.proc.pid), "-n", *args]

    def run(self, args, **kw):
        return run(self.argv(args), **kw)

    def must(self, args, **kw):
        return must(self.argv(args), **kw)

    def popen(self, args, **kw):
        return subprocess.Popen(self.argv(args), **kw)

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def write_certificates(work):
    ca_key = work / "ca.key"
    ca = work / "ca.pem"
    srv_key = work / "server.key"
    srv_csr = work / "server.csr"
    srv = work / "server.pem"
    san = work / "san.cnf"
    must(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
          "-subj", "/CN=mutekizu-arena-ca",
          "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign",
          "-keyout", str(ca_key), "-out", str(ca)])
    must(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
          "-subj", "/CN=test.example", "-keyout", str(srv_key), "-out", str(srv_csr)])
    san.write_text(
        f"subjectAltName=DNS:{BLOCKED},DNS:{ALLOWED},DNS:*.{BLOCKED},DNS:{LONG_SNI},"
        f"IP:{SERVER4},IP:{SERVER42},IP:{SERVER6},IP:{SERVER62}\n"
        "extendedKeyUsage=serverAuth\n")
    must(["openssl", "x509", "-req", "-days", "1", "-in", str(srv_csr),
          "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
          "-extfile", str(san), "-out", str(srv)])
    return ca, srv, srv_key


def setup_topology(mid, srv):
    must(["ip", "link", "add", "cli", "type", "veth", "peer", "name", "mc"])
    must(["ip", "link", "set", "mc", "netns", str(mid.proc.pid)])
    srv.must(["ip", "link", "add", "srv0", "type", "veth", "peer", "name", "ms"])
    srv.must(["ip", "link", "set", "ms", "netns", str(mid.proc.pid)])

    must(["ip", "addr", "add", f"{CLIENT4}/24", "dev", "cli"])
    must(["ip", "-6", "addr", "add", f"{CLIENT6}/64", "dev", "cli", "nodad"])
    must(["ip", "link", "set", "cli", "up"])
    must(["ip", "route", "add", "default", "via", MID4])
    must(["ip", "-6", "route", "add", "default", "via", MID6])

    mid.must(["ip", "addr", "add", f"{MID4}/24", "dev", "mc"])
    mid.must(["ip", "-6", "addr", "add", f"{MID6}/64", "dev", "mc", "nodad"])
    mid.must(["ip", "addr", "add", f"{MID42}/24", "dev", "ms"])
    mid.must(["ip", "-6", "addr", "add", f"{MID62}/64", "dev", "ms", "nodad"])
    mid.must(["ip", "link", "set", "mc", "up"])
    mid.must(["ip", "link", "set", "ms", "up"])
    mid.must(["ip", "link", "set", "lo", "up"])
    mid.must(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    mid.must(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])

    srv.must(["ip", "addr", "add", f"{SERVER4}/24", "dev", "srv0"])
    srv.must(["ip", "addr", "add", f"{SERVER42}/24", "dev", "srv0"])
    srv.must(["ip", "-6", "addr", "add", f"{SERVER6}/64", "dev", "srv0", "nodad"])
    srv.must(["ip", "-6", "addr", "add", f"{SERVER62}/64", "dev", "srv0", "nodad"])
    srv.must(["ip", "link", "set", "srv0", "up"])
    srv.must(["ip", "link", "set", "lo", "up"])
    srv.must(["ip", "route", "add", "default", "via", MID42])
    srv.must(["ip", "-6", "route", "add", "default", "via", MID62])

    must(["ip", "link", "set", "lo", "up"])


def set_offloads(mid, srv, on):
    state = "on" if on else "off"
    for args in (
        ["ethtool", "-K", "cli", "tso", state, "gso", state, "gro", state],
    ):
        run(args)
    mid.run(["ethtool", "-K", "mc", "tso", state, "gso", state, "gro", state])
    mid.run(["ethtool", "-K", "ms", "tso", state, "gso", state, "gro", state])
    srv.run(["ethtool", "-K", "srv0", "tso", state, "gso", state, "gro", state])


def write_files(work):
    (work / "domains.txt").write_text(BLOCKED + "\n")
    (work / "mss_targets.txt").write_text(f"{SERVER4}\n{SERVER6}\n")
    configs = {}
    for name, params in STRATEGIES.items():
        if params is None:
            configs[name] = None
            continue
        path = work / f"{name}.conf"
        path.write_text(f"""\
split_enabled={"true" if params["split"] else "false"}
mss_clamp={"true" if params["mss"] else "false"}
mss_value={params["mss_value"]}
mss_targets_file={work}/mss_targets.txt
split_delta={params["delta"]}
split_stride={params.get("stride", 0)}
split_max=64
split_gap_ms={params.get("gap", 0)}
queue_num=2000
fwmark=0x44495054
max_queue_len=256
copy_range=65535
inspect_packets=10
mss=1200
ipv4=true
ipv6=true
ports=443
domains_file={work}/domains.txt
log_level=info
log_sni=false
max_flows=1024
flow_buffer=8192
flow_timeout_s=30
""")
        configs[name] = path
    return configs


class Arena:
    def __init__(self, work, records, args):
        self.work = work
        self.records = records
        self.args = args
        self.levels = [int(x) for x in args.levels.split(",") if x]
        self.strategy_filter = [x for x in args.strategies.split(",") if x]
        self.family_filter = [x for x in args.families.split(",") if x]
        self.mid = None
        self.srv = None
        self.server = None
        self.dpi = None
        self.shield = None
        self.dpi_stats = None
        self.ca = None
        self.server_proc = None

    def log(self, **kw):
        rec = {"ts": now_iso(), **kw}
        self.records.append(rec)
        line = (f"[{rec.get('corpus','?')}] L{rec.get('level','?')} "
                f"{rec.get('strategy','?'):15s} {rec.get('family','?'):4s} "
                f"{rec.get('sni','?'):<18s} "
                f"{rec.get('result','?'):14s} "
                f"tls={rec.get('tls_ok')} mss={rec.get('mss')}")
        print(line, flush=True)

    def setup(self):
        if not has_caps():
            print("SKIP: CAP_NET_ADMIN/CAP_NET_RAW are not effective. "
                  "Run inside: unshare -rn python3 tests/arena/arena.py", file=sys.stderr)
            return False
        self.ca, srv_cert, srv_key = write_certificates(self.work)
        self.mid = Netns()
        self.srv = Netns()
        setup_topology(self.mid, self.srv)
        set_offloads(self.mid, self.srv, on=False)
        self.configs = write_files(self.work)

        self.server_proc = self.srv.popen(
            [sys.executable, str(TLS), "server", "--host", "::", "--port", "443",
             "--cert", str(srv_cert), "--key", str(srv_key)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_line(self.server_proc, "listening")
        return True

    def start_dpi(self, level):
        self.stop_dpi()
        p = self.mid.popen([str(LADDER), "--level", str(level), "--queue", "3001",
                            "--block", BLOCKED],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_line(p, "READY")
        self.mid.must(["nft", "add", "table", "inet", "arena_dpi"])
        self.mid.must(["nft", "add", "chain", "inet", "arena_dpi", "forward",
                       "{ type filter hook forward priority 0; policy accept; }"])
        self.mid.must(["nft", "add", "rule", "inet", "arena_dpi", "forward",
                       "ip", "saddr", "10.90.1.0/24", "tcp", "dport", "443",
                       "counter", "queue", "num", "3001"])
        self.mid.must(["nft", "add", "rule", "inet", "arena_dpi", "forward",
                       "ip6", "saddr", "fd90:1::/64", "tcp", "dport", "443",
                       "counter", "queue", "num", "3001"])
        self.dpi = p

    def stop_dpi(self):
        if self.dpi is not None:
            run(self.mid.argv(["nft", "delete", "table", "inet", "arena_dpi"]))
            self.dpi.terminate()
            try:
                _, err = self.dpi.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                self.dpi.kill()
                _, err = self.dpi.communicate()
            m = re.search(r"packets=(\d+) dropped=(\d+) flows=(\d+) "
                          r"overflow_blocks=(\d+) parse_errors=(\d+)", err or "")
            if m:
                self.dpi_stats = {
                    "packets": int(m.group(1)), "dropped": int(m.group(2)),
                    "flows": int(m.group(3)), "overflow_blocks": int(m.group(4)),
                    "parse_errors": int(m.group(5)),
                }
            self.dpi = None

    def start_shield(self, strategy):
        self.stop_shield()
        cfg = self.configs.get(strategy)
        if cfg is None:
            return
        env = os.environ.copy()
        env["MUTEKIZU_PIDFILE"] = str(self.work / "shield.pid")
        log = open(self.work / f"shield-{strategy}.log", "a")
        p = subprocess.Popen([str(SHIELD), "-c", str(cfg), "run"], env=env,
                             stdout=log, stderr=log, text=True)
        for _ in range(100):
            if run(["nft", "list", "table", "inet", "mutekizu"]).returncode == 0:
                self.shield = p
                return
            if p.poll() is not None:
                break
            time.sleep(0.05)
        log.close()
        raise RuntimeError("shield did not install its table; see shield log")

    def stop_shield(self):
        if self.shield is not None:
            self.shield.terminate()
            try:
                self.shield.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.shield.kill()
                self.shield.wait()
            self.shield = None
        # Safety: cleanup must not depend on a graceful exit.
        run([str(SHIELD), "rules", "remove"])

    def client(self, host, sni, curve="X25519", max_tls=None, size=16384):
        cmd = [sys.executable, str(TLS), "client", "--host", host, "--port", "443",
               "--sni", sni, "--ca", str(self.ca), "--size", str(size),
               "--timeout", "2", "--curve", curve]
        if max_tls:
            cmd += ["--max-tls", max_tls]
        t0 = time.monotonic()
        try:
            r = run(cmd, timeout=8)
        except subprocess.TimeoutExpired:
            return {"ok": False, "mss": None, "ms": 8000.0, "reason": "outer_timeout"}
        dt = (time.monotonic() - t0) * 1000.0
        ok = r.returncode == 0 and "OK" in r.stdout
        m = re.search(r"mss=(-?\d+)", r.stdout)
        reason = ""
        if not ok:
            err = r.stderr
            if "timed out" in err or "TimeoutError" in err:
                reason = "tls_timeout"
            elif "CERTIFICATE" in err:
                reason = "tls_error"
            else:
                reason = "error"
        return {"ok": ok, "mss": int(m.group(1)) if m else None, "ms": dt,
                "reason": reason}

    def one(self, corpus, level, strategy, family, host, sni, expected,
            curve="X25519", max_tls=None, repeat=1, note=""):
        r = self.client(host, sni, curve=curve, max_tls=max_tls)
        if expected == "blocked":
            result = "bypassed" if r["ok"] else "blocked"
        else:
            result = "allowed_ok" if r["ok"] else "false_positive"
        self.log(corpus=corpus, level=level, strategy=strategy, family=family,
                 sni=sni, expected=expected, result=result, tls_ok=r["ok"],
                 mss=r["mss"], duration_ms=round(r["ms"], 1),
                 reason=r["reason"], repeat=repeat, curve=curve,
                 max_tls=max_tls or "1.3", note=note)
        return r

    def run_matrix(self):
        tuning_strategies = ["none", "split_d1", "split_d4", "split_d8",
                             "mss96", "mss136", "split4_mss136", "split_multi",
                             "split_multi_gap"]
        tuning_strategies = [s for s in tuning_strategies if s in self.strategy_filter]
        families = [("ipv4", SERVER4), ("ipv6", SERVER6)]
        families = [f for f in families if f[0] in self.family_filter]
        for level in self.levels:
            self.start_dpi(level)
            for strategy in tuning_strategies:
                self.start_shield(strategy)
                for family, host in families:
                    for expected, sni in (("blocked", BLOCKED), ("allowed", ALLOWED)):
                        self.one("tuning", level, strategy, family, host, sni, expected)
                self.stop_shield()
            self.stop_dpi()
            self.log(corpus="dpi-stats", level=level, stats=self.dpi_stats)

    def run_validation(self):
        strategies = ["none", "split_d4", "mss136", "split4_mss136", "split_multi",
                      "split_multi_gap"]
        strategies = [x for x in strategies if x in self.strategy_filter]
        for level in (1, 2, 4, 5):
            self.start_dpi(level)
            for strategy in strategies:
                self.start_shield(strategy)
                for repeat in (1, 2):
                    for expected, sni in (("blocked", LONG_SNI), ("allowed", ALLOWED)):
                        self.one("validation", level, strategy, "ipv4", SERVER4, sni,
                                 expected, curve="default", repeat=repeat,
                                 note="PQ ClientHello, long SNI")
                self.stop_shield()
            self.stop_dpi()
        # TLS 1.2 boundary cases.
        for level in (4, 5):
            self.start_dpi(level)
            for strategy in ("none", "split_d4"):
                self.start_shield(strategy)
                for expected, sni in (("blocked", BLOCKED), ("allowed", ALLOWED)):
                    self.one("validation-tls12", level, strategy, "ipv4", SERVER4,
                             sni, expected, curve="X25519", max_tls="1.2",
                             note="TLS 1.2")
                self.stop_shield()
            self.stop_dpi()

    def run_lower(self):
        # 1. Offloads on: does the logical stream change?
        set_offloads(self.mid, self.srv, on=True)
        self.start_dpi(4)
        self.start_shield("split_d4")
        for expected, sni in (("blocked", BLOCKED), ("allowed", ALLOWED)):
            self.one("lower-offload", 4, "split_d4", "ipv4", SERVER4, sni, expected)
        self.stop_shield()
        self.stop_dpi()
        set_offloads(self.mid, self.srv, on=False)

        # 2. Loss, duplication, reordering on the forward path.
        self.mid.run(["tc", "qdisc", "replace", "dev", "ms", "root", "netem",
                      "loss", "2%", "duplicate", "2%", "reorder", "25%", "50%",
                      "seed", "1234"])
        self.start_dpi(4)
        self.start_shield("split_d4")
        for repeat in (1, 2):
            for expected, sni in (("blocked", BLOCKED), ("allowed", ALLOWED)):
                self.one("lower-netem", 4, "split_d4", "ipv4", SERVER4, sni,
                         expected, repeat=repeat,
                         note="loss 2%, duplicate 2%, reorder 25%")
        self.stop_shield()
        self.stop_dpi()
        self.mid.run(["tc", "qdisc", "del", "dev", "ms", "root"])

        # 3. NOTRACK in the client: ct-based selection cannot work.
        must(["nft", "add", "table", "inet", "arena_notrack"])
        must(["nft", "add", "chain", "inet", "arena_notrack", "out",
              "{ type filter hook output priority -300; policy accept; }"])
        must(["nft", "add", "rule", "inet", "arena_notrack", "out",
              "tcp", "dport", "443", "notrack"])
        self.start_dpi(2)
        self.start_shield("split_d4")
        self.one("lower-notrack", 2, "split_d4", "ipv4", SERVER4, BLOCKED,
                 "blocked", note="output priority -300 notrack")
        self.stop_shield()
        self.stop_dpi()
        must(["nft", "delete", "table", "inet", "arena_notrack"])

    def benchmark(self):
        # Level 4 passes the allowed SNI; isolate the tool's own overhead.
        self.start_dpi(4)
        for strategy in ("none", "split_d4"):
            self.start_shield(strategy)
            times = []
            for _ in range(10):
                r = self.client(SERVER4, ALLOWED, curve="X25519", size=65536)
                if r["ok"]:
                    times.append(r["ms"])
                self.one("bench", 4, strategy, "ipv4", SERVER4, ALLOWED, "allowed",
                         note="benchmark, not included in pass/fail")
            stats = {}
            if self.shield is not None and self.shield.poll() is None:
                try:
                    status = pathlib.Path(f"/proc/{self.shield.pid}/status").read_text()
                    stats["rss_peak"] = next((x for x in status.splitlines()
                                              if x.startswith("VmHWM:")), "?")
                    stat = pathlib.Path(f"/proc/{self.shield.pid}/stat").read_text().split()
                    stats["cpu_ticks"] = int(stat[13]) + int(stat[14])
                except (OSError, IndexError):
                    pass
            times.sort()
            if times:
                stats["runs"] = len(times)
                stats["mean_ms"] = round(sum(times) / len(times), 2)
                stats["p95_ms"] = round(times[int(len(times) * 0.95) - 1], 2)
            print(f"BENCH {strategy}: {stats}", flush=True)
            self.log(corpus="bench", level=4, strategy=strategy, stats=stats)
            self.stop_shield()
        self.stop_dpi()

    def close(self):
        self.stop_shield()
        self.stop_dpi()
        if self.server_proc is not None and self.server_proc.poll() is None:
            self.server_proc.terminate()
            try:
                self.server_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.server_proc.kill()
        if self.srv is not None:
            self.srv.close()
        if self.mid is not None:
            self.mid.close()


def summarize(records, out_path):
    cells = {}
    for r in records:
        if r.get("corpus") not in ("tuning", "validation"):
            continue
        key = (r["corpus"], r["family"], r["level"], r["strategy"], r["expected"])
        cells.setdefault(key, []).append(r["result"])
    lines = ["# Arena summary", "",
             "| corpus | family | DPI | strategy | blocked | allowed |",
             "|---|---|---|---|---|---|"]
    for corpus in ("tuning", "validation"):
        for family in ("ipv4", "ipv6"):
            for level in (1, 2, 3, 4, 5):
                for strategy in STRATEGIES:
                    blocked = cells.get((corpus, family, level, strategy, "blocked"))
                    allowed = cells.get((corpus, family, level, strategy, "allowed"))
                    if not blocked and not allowed:
                        continue
                    b = "/".join(sorted(set(blocked))) if blocked else "-"
                    a = "/".join(sorted(set(allowed))) if allowed else "-"
                    lines.append(f"| {corpus} | {family} | {level} | {strategy} | {b} | {a} |")
    out_path.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "tests" / "arena" / "results" /
                                         "arena.jsonl"))
    ap.add_argument("--skip-validation", action="store_true")
    ap.add_argument("--skip-lower", action="store_true")
    ap.add_argument("--skip-bench", action="store_true")
    ap.add_argument("--levels", default="1,2,3,4,5")
    ap.add_argument("--strategies", default=",".join(STRATEGIES))
    ap.add_argument("--families", default="ipv4,ipv6")
    ap.add_argument("--keep-work", action="store_true")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(tempfile.mkdtemp(prefix="dpi-arena-"))
    records = []
    arena = Arena(work, records, args)

    env = {
        "timestamp": now_iso(),
        "uname": run(["uname", "-a"]).stdout.strip(),
        "nft": run(["nft", "--version"]).stdout.strip(),
        "openssl": run(["openssl", "version"]).stdout.strip(),
        "python": sys.version,
        "cap_eff": hex(cap_effective()),
        "argv": sys.argv,
        "strategies": STRATEGIES,
        "blocked_sni": BLOCKED,
        "allowed_sni": ALLOWED,
        "long_sni": LONG_SNI,
    }

    rc = 0
    try:
        if not arena.setup():
            return 77
        arena.run_matrix()
        if not args.skip_validation:
            arena.run_validation()
        if not args.skip_lower:
            arena.run_lower()
        if not args.skip_bench:
            arena.benchmark()
    except Exception as exc:  # noqa: BLE001 - arena must report failures
        print(f"ARENA ERROR: {exc}", file=sys.stderr)
        rc = 1
    finally:
        arena.close()
        env["records"] = len(records)
        with out.open("w") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        (out.parent / "env.json").write_text(json.dumps(env, indent=2) + "\n")
        summarize(records, out.parent / "summary.md")
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"work dir kept: {work}")
        print(f"wrote {out} ({len(records)} records)")
    return rc


if __name__ == "__main__":
    sys.exit(main())

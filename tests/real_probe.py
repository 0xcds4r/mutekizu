#!/usr/bin/env python3
"""Read-only probe of the real network path. Does not change firewall/DNS/QUIC.

For each target it compares:
  * system DNS vs 1.1.1.1
  * TCP connect to the IP
  * TLS handshake with the real SNI
  * TLS handshake with a neutral SNI on the same IP
  * TLS handshake with no SNI

This distinguishes DNS manipulation from TCP/IP filtering and from SNI-based
filtering. It does NOT verify certificates (probe only) and does not MITM.
"""
import argparse, json, socket, ssl, subprocess, sys, time
import urllib.parse, urllib.request

TARGETS = [
    "example.com", "en.wikipedia.org", "github.com",
    "instagram.com", "www.instagram.com", "facebook.com", "www.facebook.com",
    "x.com", "twitter.com", "linkedin.com", "www.linkedin.com",
    "rutracker.org", "telegram.org", "web.telegram.org",
    "discord.com", "www.youtube.com", "meduza.io",
]

NEUTRAL = "www.google.com"

def doh(name):
    """Resolve via DoH because plaintext DNS is intercepted on this path."""
    q = urllib.parse.quote(name)
    for url in (f"https://dns.google/resolve?name={q}&type=A",
                f"https://cloudflare-dns.com/dns-query?name={q}&type=A"):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=6) as r:
                d = json.loads(r.read().decode())
            ips = [a["data"] for a in d.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips, url.split("/")[2]
        except Exception:
            continue
    return [], None

def resolve(name, server=None):
    if server:
        r = subprocess.run(["dig", "+short", "+time=2", "+tries=1", "@"+server, name, "A"],
                           capture_output=True, text=True, timeout=6)
        ans = [x.strip() for x in r.stdout.splitlines() if x.strip() and not x.strip().endswith(".")]
        # keep only IPv4-looking answers
        return [x for x in ans if x.count(".") == 3 and x[0].isdigit()]
    r = subprocess.run(["getent", "ahostsv4", name], capture_output=True, text=True, timeout=6)
    out = []
    for line in r.stdout.splitlines():
        ip = line.split()[0]
        if ip not in out:
            out.append(ip)
    return out

def tcp(ip, port, timeout):
    t0 = time.monotonic()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True, round((time.monotonic()-t0)*1000, 1), ""
    except Exception as e:
        return False, round((time.monotonic()-t0)*1000, 1), type(e).__name__ + ": " + str(e)[:80]

def tls(ip, sni, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
        raw.settimeout(timeout)
        t0 = time.monotonic()
        kw = {"server_hostname": sni} if sni else {}
        t = ctx.wrap_socket(raw, **kw)
        cert = t.getpeercert()
        ms = round((time.monotonic()-t0)*1000, 1)
        t.close()
        return True, ms, (cert.get("subject") if cert else None), ""
    except Exception as e:
        return False, None, None, type(e).__name__ + ": " + str(e)[:100]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="/tmp/real-probe.jsonl")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--targets", default=",".join(TARGETS))
    a = ap.parse_args()
    targets = [t for t in a.targets.split(",") if t]
    out = []
    for name in targets:
        sysips = resolve(name)
        pubips, doh_src = doh(name)
        row = {"target": name, "system_dns": sysips, "doh_dns": pubips,
               "doh_source": doh_src,
               "dns_differs": bool(sysips and pubips and sysips[0] != pubips[0])}
        ip = pubips[0] if pubips else (sysips[0] if sysips else None)
        if not ip:
            row["verdict"] = "no_dns"; out.append(row); print(json.dumps(row)); continue
        row["ip"] = ip
        if sysips and sysips[0] != ip:
            row["system_ip"] = sysips[0]
            row["system_tcp_ok"], row["system_tcp_ms"], row["system_tcp_error"] = tcp(
                sysips[0], 443, a.timeout)
        ok, ms, err = tcp(ip, 443, a.timeout)
        row.update({"tcp_ok": ok, "tcp_ms": ms, "tcp_error": err})
        if not ok:
            row["verdict"] = "tcp_ip_block_or_no_route"
        else:
            rok, rms, rcert, rerr = tls(ip, name, a.timeout)
            nok, nms, ncert, nerr = tls(ip, NEUTRAL, a.timeout)
            nook, noms, nocert, noerr = tls(ip, None, a.timeout)
            row.update({"tls_real_ok": rok, "tls_real_error": rerr,
                        "tls_neutral_ok": nok, "tls_neutral_error": nerr,
                        "tls_nosni_ok": nook, "tls_nosni_error": noerr,
                        "tls_real_subject": rcert})
            if rok:
                row["verdict"] = "tls_ok"
            elif nook:
                row["verdict"] = "sni_filter_suspected"
            elif nok:
                row["verdict"] = "sni_or_neutral_sni_filter_suspected"
            else:
                row["verdict"] = "tcp_ok_tls_blocked_all_sni"
        out.append(row)
        print(json.dumps(row, ensure_ascii=False))
    with open(a.json, "w") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())

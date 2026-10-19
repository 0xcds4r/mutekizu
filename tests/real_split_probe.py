#!/usr/bin/env python3
"""Real-path test of the ClientHello segmentation mechanism, without root.

The client connects directly to the real server IP (no proxy, no VPN, no MITM),
generates the real TLS ClientHello with ssl.MemoryBIO, then writes it as several
TCP segments and waits until each chunk has left the local send queue
(TIOCOUTQ). TLS certificate and hostname verification stay enabled.

This tests the same wire-level mechanism as mutekizu's NFQUEUE split, but it
does not run the privileged utility itself. Results are evidence about the real
path only for the probed destinations at that moment.
"""
import argparse, fcntl, hashlib, json, socket, ssl, struct, sys, termios, time
import urllib.parse, urllib.request

TARGETS = ["example.com", "github.com", "facebook.com", "www.facebook.com",
           "x.com", "twitter.com", "linkedin.com", "www.linkedin.com",
           "rutracker.org", "discord.com", "www.youtube.com", "meduza.io"]


def doh(name):
    q = urllib.parse.quote(name)
    for url in (f"https://dns.google/resolve?name={q}&type=A",
                f"https://cloudflare-dns.com/dns-query?name={q}&type=A"):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=6) as r:
                d = json.loads(r.read().decode())
            ips = [a["data"] for a in d.get("Answer", []) if a.get("type") == 1]
            if ips:
                return ips
        except Exception:
            pass
    return []


def sni_offset(hello):
    """Strict, bounds-checked SNI offset for the first TLS record."""
    if len(hello) < 5 or hello[0] != 0x16 or hello[1] != 0x03:
        return None, None
    rlen = int.from_bytes(hello[3:5], "big")
    end = 5 + rlen
    if end > len(hello):
        return None, None
    p = 5
    if p + 4 > end or hello[p] != 0x01:
        return None, None
    p += 4
    if p + 2 + 32 + 1 > end:
        return None, None
    p += 2 + 32
    sid = hello[p]; p += 1 + sid
    if p + 2 > end: return None, None
    clen = int.from_bytes(hello[p:p+2], "big"); p += 2 + clen
    if p + 1 > end: return None, None
    comp = hello[p]; p += 1 + comp
    if p + 2 > end: return None, None
    ext_total = int.from_bytes(hello[p:p+2], "big"); p += 2
    ext_end = p + ext_total
    if ext_end > end: return None, None
    while p + 4 <= ext_end:
        typ = int.from_bytes(hello[p:p+2], "big")
        ln = int.from_bytes(hello[p+2:p+4], "big"); p += 4
        if p + ln > ext_end: return None, None
        if typ == 0:
            q = p
            if q + 2 > p + ln: return None, None
            llen = int.from_bytes(hello[q:q+2], "big"); q += 2
            list_end = q + llen
            if list_end > p + ln: return None, None
            while q + 3 <= list_end:
                ntype = hello[q]; nlen = int.from_bytes(hello[q+1:q+3], "big"); q += 3
                if q + nlen > list_end: return None, None
                if ntype == 0:
                    return q, nlen
                q += nlen
        p += ln
    return None, None


def send_chunks(sock, data, boundaries):
    if not boundaries:
        sock.sendall(data)
        return
    points = sorted({b for b in boundaries if 0 < b < len(data)})
    from_off = 0
    for b in points:
        sock.sendall(data[from_off:b])
        # Wait until the local send queue has drained: the segment is on the wire.
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            buf = struct.pack("i", 0)
            try:
                outq = struct.unpack("i", fcntl.ioctl(sock.fileno(), termios.TIOCOUTQ, buf))[0]
            except OSError:
                break
            if outq == 0:
                break
            time.sleep(0.002)
        from_off = b
    sock.sendall(data[from_off:])


def run_one(ip, sni, mode, timeout=6, curve=None):
    ctx = ssl.create_default_context()
    if curve and curve != "default":
        try:
            ctx.set_ecdh_curve(curve)
        except Exception:
            pass
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(inbio, outbio, server_hostname=sni)
    try:
        sslobj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    except Exception as e:
        return {"ok": False, "error": "hello: " + type(e).__name__ + ": " + str(e)[:100]}
    hello = outbio.read()
    off, ln = sni_offset(hello)
    if off is None:
        return {"ok": False, "error": "no SNI in ClientHello"}
    if mode == "baseline":
        boundaries = []
    elif mode == "split":
        boundaries = [off + 4]
    else:
        boundaries = list(range(off + 4, off + ln, 4))[:64]
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        sock.settimeout(timeout)
        send_chunks(sock, hello, boundaries)
        while True:
            try:
                sslobj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLWantWriteError:
                pass
            out = outbio.read()
            if out:
                sock.sendall(out)
            data = sock.recv(65536)
            if not data:
                raise EOFError("server closed during handshake")
            inbio.write(data)
        cert = sslobj.getpeercert()
        req = f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode()
        sslobj.write(req)
        out = outbio.read()
        if out:
            sock.sendall(out)
        resp = b""
        try:
            while len(resp) < 512:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                inbio.write(chunk)
                resp += sslobj.read(4096)
        except (socket.timeout, ssl.SSLError):
            pass
        dt = round((time.monotonic() - t0) * 1000, 1)
        sock.close()
        return {"ok": True, "ms": dt, "boundaries": len(boundaries),
                "http": resp[:32].decode(errors="replace").replace("\r\n", " "),
                "cert_subject": cert.get("subject") if cert else None}
    except Exception as e:
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000, 1),
                "error": type(e).__name__ + ": " + str(e)[:120],
                "boundaries": len(boundaries)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="tests/real-split-results.jsonl")
    ap.add_argument("--targets", default=",".join(TARGETS))
    ap.add_argument("--modes", default="baseline,split,multi")
    ap.add_argument("--timeout", type=float, default=6)
    ap.add_argument("--ip-map", default="", help="name=ip,name=ip overrides")
    ap.add_argument("--curve", default=None)
    a = ap.parse_args()
    overrides = {}
    for item in a.ip_map.split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            overrides[k.strip()] = v.strip()
    rows = []
    for name in [t for t in a.targets.split(",") if t]:
        ips = [overrides[name]] if name in overrides else doh(name)
        ip = ips[0] if ips else None
        if not ip:
            print(json.dumps({"target": name, "error": "no DoH IP"})); continue
        for mode in a.modes.split(","):
            r = run_one(ip, name, mode, a.timeout, a.curve)
            row = {"target": name, "ip": ip, "mode": mode, "curve": a.curve or "default", **r}
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)
    with open(a.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

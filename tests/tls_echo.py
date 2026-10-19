#!/usr/bin/env python3
"""Minimal TLS server/client used by the isolated netns lab.

Server: accepts TLS connections, reads until EOF, returns SHA256 hex.
Client: verifies the server certificate against --ca, sends deterministic
        bytes, shuts down the write side, compares the returned digest.
No third-party modules.
"""
import argparse
import hashlib
import socket
import ssl
import sys
import threading


def make_payload(size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(b"mutekizu-lab" + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:size])


def recv_exact(tls, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = tls.recv(n - len(out))
        if not chunk:
            raise EOFError("peer closed early")
        out += chunk
    return bytes(out)


def serve(args):
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind((args.host, args.port))
    sock.listen(16)
    print(f"listening on {args.host}:{args.port}", flush=True)

    def handle(conn):
        # One thread per connection: a blocked handshake must not stop the
        # accept loop (the arena intentionally leaves stalled connections).
        conn.settimeout(6.0)
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            size = int.from_bytes(recv_exact(tls, 8), "big")
            if size < 0 or size > 64 * 1024 * 1024:
                raise ValueError("bad payload size")
            payload = recv_exact(tls, size)
            tls.sendall(hashlib.sha256(payload).hexdigest().encode() + b"\n")
            tls.close()
            print(f"served {size} bytes", flush=True)
        except Exception as exc:  # noqa: BLE001 - lab server
            print(f"connection error: {exc!r}", flush=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def client(args):
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    ctx = ssl.create_default_context(cafile=args.ca)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if args.curve and args.curve != "default":
        # Keeps the ClientHello small enough to fit one TCP segment, so the
        # lab can model a DPI that requires the complete record in one packet.
        ctx.set_ecdh_curve(args.curve)
    if args.max_tls == "1.2":
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    payload = make_payload(args.size)
    expected = hashlib.sha256(payload).hexdigest()
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(args.timeout)
        sock.connect((args.host, args.port))
        try:
            mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        except OSError:
            mss = -1
        with ctx.wrap_socket(sock, server_hostname=args.sni) as tls:
            tls.settimeout(args.timeout)
            tls.sendall(len(payload).to_bytes(8, "big") + payload)
            data = b""
            while not data.endswith(b"\n"):
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
    got = data.decode(errors="replace").strip()
    if got != expected:
        print(f"FAIL digest mismatch: got={got} expected={expected}")
        return 1
    print(f"OK tls-verified bytes={len(payload)} mss={mss} digest={got}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["server", "client"])
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--sni", default="test.example")
    ap.add_argument("--ca")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--size", type=int, default=262144)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--curve", default="X25519")
    ap.add_argument("--max-tls", choices=["1.2", "1.3"], default=None)
    args = ap.parse_args()
    if args.mode == "server":
        if not (args.cert and args.key):
            ap.error("server requires --cert and --key")
        serve(args)
        return 0
    if not args.ca:
        ap.error("client requires --ca")
    return client(args)


if __name__ == "__main__":
    sys.exit(main())

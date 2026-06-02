#!/usr/bin/env python3
"""DAST capture server — listens on 127.0.0.1:80 and 127.0.0.1:443.

DNS hijacking (set up by dast-init.sh) makes the runner user's resolver
return 127.0.0.1 for every hostname, so any outbound HTTP/HTTPS attempt
lands here. Also bundles a UDP DNS responder on :53 that returns
127.0.0.1 for every query.

Per connection:
  * Read up to 8 KB
  * Try to parse as HTTP — capture method, path, headers, body
  * Try to parse as TLS ClientHello — capture SNI hostname
  * Otherwise log raw TCP

Captures are appended to /tmp/captured.jsonl as one JSON object per line.
The dast-entrypoint reads this file at end-of-run and emits
`network_call_captured` events.

NOT a general-purpose proxy. No upstream forwarding. No TLS termination
with valid certificates (TLS clients see handshake errors after we've
already logged the SNI from their ClientHello).
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time

CAPTURE_PATH = "/tmp/captured.jsonl"
LISTEN_HOST = "127.0.0.1"
HTTP_PORT = 80
HTTPS_PORT = 443
DNS_PORT = 53
MAX_READ_BYTES = 8192
CONN_TIMEOUT_S = 2.0


# ---------------------------------------------------------------------------
# Capture logging (shared)
# ---------------------------------------------------------------------------


def log_capture(record: dict) -> None:
    record.setdefault("timestamp", time.time())
    try:
        with open(CAPTURE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except Exception:
        sys.stderr.write(f"capture log write failed for {record.get('kind')}\n")


# ---------------------------------------------------------------------------
# TCP capture (HTTP + TLS sniff)
# ---------------------------------------------------------------------------


def parse_tls_clienthello(data: bytes) -> str | None:
    """Extract SNI from a TLS ClientHello. Returns None on parse failure."""
    if len(data) < 11:
        return None
    if data[0] != 0x16:
        return None
    if data[5] != 0x01:
        return None
    pos = 5 + 4 + 2 + 32
    if pos >= len(data):
        return None
    try:
        sid_len = data[pos]
        pos += 1 + sid_len
        if pos + 2 > len(data):
            return None
        cs_len = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2 + cs_len
        if pos + 1 > len(data):
            return None
        cm_len = data[pos]
        pos += 1 + cm_len
        if pos + 2 > len(data):
            return None
        ext_total_len = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        end = min(pos + ext_total_len, len(data))
        while pos + 4 <= end:
            ext_type = struct.unpack(">H", data[pos : pos + 2])[0]
            ext_data_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
            pos += 4
            if ext_type == 0x00:
                if pos + 5 > end:
                    return None
                name_len = struct.unpack(">H", data[pos + 3 : pos + 5])[0]
                return data[pos + 5 : pos + 5 + name_len].decode("utf-8", errors="replace")
            pos += ext_data_len
    except Exception:
        return None
    return None


def parse_http(data: bytes) -> dict | None:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None
    if "\r\n" not in text:
        return None
    first_line, _, rest = text.partition("\r\n")
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return None
    method = parts[0]
    if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"):
        return None
    path = parts[1]
    header_block, _, body = rest.partition("\r\n\r\n")
    headers: dict[str, str] = {}
    for line in header_block.split("\r\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body_excerpt": body[:2000],
    }


def handle_tcp(conn: socket.socket, addr: tuple, listen_port: int) -> None:
    try:
        conn.settimeout(CONN_TIMEOUT_S)
        data = b""
        while len(data) < MAX_READ_BYTES:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            except Exception:
                break
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data and len(data) >= 1024:
                break

        record = {
            "peer": f"{addr[0]}:{addr[1]}",
            "listen_port": listen_port,
            "size": len(data),
            "raw_excerpt_hex": data[:128].hex(),
        }
        sni = parse_tls_clienthello(data)
        http = parse_http(data)
        if http is not None:
            record["kind"] = "http_request"
            record.update(http)
        elif sni is not None:
            record["kind"] = "tls_clienthello"
            record["sni"] = sni
        else:
            record["kind"] = "raw_tcp"
        log_capture(record)

        try:
            req_path = http.get("path", "") if http is not None else ""
            if req_path.startswith("/redirect/"):
                # Redirect-follow probe support: issue a REAL 30x to a
                # unique internal sink host. A client that follows
                # redirects without re-validating the destination lands
                # on argus-redirect-sink.internal (DNS-hijacked to
                # loopback) — observable as a distinctly-attributable
                # capture that no probe requests directly, so it can
                # only mean "the target followed our redirect to
                # internal". The sink path is deliberately NOT under
                # /redirect/ to avoid an infinite redirect loop.
                conn.sendall(
                    b"HTTP/1.1 302 Found\r\n"
                    b"Location: http://argus-redirect-sink.internal/sunk\r\n"
                    b"Content-Length: 0\r\n"
                    b"\r\n"
                )
            else:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 16\r\n"
                    b"\r\n"
                    b'{"status":"ok"}\n'
                )
        except Exception:
            pass
    except Exception as e:
        log_capture({"kind": "capture_error", "peer": str(addr), "error": str(e)})
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve_tcp(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((LISTEN_HOST, port))
    except OSError as e:
        log_capture({"kind": "bind_error", "port": port, "error": str(e)})
        return
    sock.listen(50)
    log_capture({"kind": "tcp_server_start", "listening_on": f"{LISTEN_HOST}:{port}"})
    while True:
        try:
            conn, addr = sock.accept()
        except KeyboardInterrupt:
            break
        except Exception as e:
            log_capture({"kind": "accept_error", "port": port, "error": str(e)})
            continue
        threading.Thread(target=handle_tcp, args=(conn, addr, port), daemon=True).start()


# ---------------------------------------------------------------------------
# DNS responder (UDP 53) — returns 127.0.0.1 for any A query
# ---------------------------------------------------------------------------


def parse_qname(data: bytes, pos: int) -> tuple[str, int]:
    """Parse a DNS QNAME starting at pos. Returns (qname, end_pos)."""
    parts = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return ".".join(parts), pos + 1
        if length & 0xC0:  # compression pointer — abort
            return ".".join(parts), pos + 2
        pos += 1
        parts.append(data[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(parts), pos


def build_dns_response(query: bytes) -> bytes | None:
    """Build a DNS response that returns 127.0.0.1 for any A query."""
    if len(query) < 12:
        return None
    tid = query[:2]
    flags = b"\x81\x80"  # standard response, no error
    qdcount = query[4:6]
    qd_count_int = struct.unpack(">H", qdcount)[0]
    if qd_count_int < 1:
        return None
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    qname, end = parse_qname(query, 12)
    if end + 4 > len(query):
        return None
    qtype = struct.unpack(">H", query[end : end + 2])[0]
    qclass = struct.unpack(">H", query[end + 2 : end + 4])[0]
    question = query[12 : end + 4]

    # Only answer A (1) and AAAA (28) — for AAAA we don't have an answer
    answer = b""
    if qtype == 1:  # A record
        answer = (
            b"\xc0\x0c"  # pointer to QNAME at offset 12
            + b"\x00\x01"  # type A
            + b"\x00\x01"  # class IN
            + b"\x00\x00\x01\x2c"  # TTL 300
            + b"\x00\x04"  # RDLENGTH 4
            + b"\x7f\x00\x00\x01"  # 127.0.0.1
        )
    elif qtype == 28:  # AAAA — no answer (force fallback to A)
        ancount = b"\x00\x00"

    log_capture(
        {
            "kind": "dns_query",
            "qname": qname,
            "qtype": qtype,
            "qclass": qclass,
            "responded_with": "127.0.0.1" if qtype == 1 else "no_answer",
        }
    )
    return tid + flags + qdcount + ancount + nscount + arcount + question + answer


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            response = build_dns_response(data)
            if response:
                sock.sendto(response, self.client_address)
        except Exception as e:
            log_capture({"kind": "dns_error", "error": str(e)})


def serve_dns() -> None:
    try:
        server = socketserver.UDPServer((LISTEN_HOST, DNS_PORT), DNSHandler)
    except OSError as e:
        log_capture({"kind": "dns_bind_error", "error": str(e)})
        return
    log_capture({"kind": "dns_server_start", "listening_on": f"{LISTEN_HOST}:{DNS_PORT}"})
    server.serve_forever()


# ---------------------------------------------------------------------------
# Main — start TCP servers on 80, 443 and DNS responder on 53
# ---------------------------------------------------------------------------


def _drop_privileges() -> None:
    """v1.9 SCAN-009 (B7): drop root after binding privileged ports.

    The capture server needs root to bind ports 80/443/53. After
    binding, it only handles parsed TLS/HTTP/DNS traffic from sources
    that the target file's own code triggers — so dropping to a low-
    privilege user after binding closes a meaningful attack surface:
    if any parser ever has a buffer-handling bug, the attacker gets
    uid=nobody (or capture) instead of root.

    Strategy:
      1. Try ``nobody`` first (always present on Debian/Alpine).
      2. Try ``capture`` (a dedicated user we could add in the
         Dockerfile in v1.10).
      3. Fall through with a warning if neither exists — running as
         root is the documented v0 behavior, and the parsers ARE
         bounds-checked at the Python level, so this is defense-in-
         depth, not a hard requirement.

    Defense-in-depth approach: even ``nobody`` can read /tmp logs and
    bind unprivileged ports, which is all the capture server needs
    post-init.
    """
    if os.geteuid() != 0:
        return  # already non-root, nothing to drop
    target_uids: list[tuple[str, int, int]] = []
    try:
        import pwd  # noqa: PLC0415
        for username in ("capture", "nobody"):
            try:
                rec = pwd.getpwnam(username)
                target_uids.append((username, rec.pw_uid, rec.pw_gid))
            except KeyError:
                continue
    except Exception as exc:
        log_capture(
            {
                "kind": "priv_drop_unavailable",
                "reason": f"pwd module unavailable: {type(exc).__name__}",
            }
        )
        return
    for username, uid, gid in target_uids:
        try:
            # CRITICAL: captured.jsonl was created root-owned (0644) when
            # the server wrote its startup sentinels. After we setuid to
            # the drop target, log_capture() appends would EACCES — which
            # silently drops EVERY captured request (the bug that made
            # network_call_captured evidence vanish for both MCP and DAST
            # scans). Hand the log file to the drop target first so it
            # stays writable post-drop.
            try:
                os.chown(CAPTURE_PATH, uid, gid)
            except OSError as chown_exc:
                log_capture(
                    {
                        "kind": "capture_log_chown_failed",
                        "user": username,
                        "error": f"{type(chown_exc).__name__}: {chown_exc!s}"[:200],
                    }
                )
            os.setgroups([])  # drop supplementary groups
            os.setgid(gid)
            os.setuid(uid)
            log_capture(
                {
                    "kind": "priv_drop_ok",
                    "user": username,
                    "uid": uid,
                    "gid": gid,
                }
            )
            return
        except (OSError, PermissionError) as exc:
            log_capture(
                {
                    "kind": "priv_drop_failed",
                    "user": username,
                    "error": f"{type(exc).__name__}: {exc!s}"[:200],
                }
            )
            continue
    log_capture(
        {
            "kind": "priv_drop_unavailable",
            "reason": "no nobody/capture user available",
        }
    )


def main() -> int:
    threads = [
        threading.Thread(target=serve_tcp, args=(HTTP_PORT,), daemon=True),
        threading.Thread(target=serve_tcp, args=(HTTPS_PORT,), daemon=True),
        threading.Thread(target=serve_dns, daemon=True),
    ]
    for t in threads:
        t.start()
    log_capture({"kind": "server_start", "ports": [HTTP_PORT, HTTPS_PORT, DNS_PORT]})

    # v1.9 SCAN-009 (B7): give the listen-sockets a moment to bind
    # under root, then drop privileges. After this point the capture
    # server runs as nobody (or stays root with a logged warning).
    time.sleep(0.5)
    _drop_privileges()

    # Block forever
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())

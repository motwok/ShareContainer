"""Prometheus metrics of the SMB server on /metrics."""

import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import sysops

PREFIX = "sharecontainer_"


def _json(args):
    try:
        return json.loads(sysops.run(["smbstatus", "--json"] + args) or "{}")
    except (sysops.CommandError, ValueError):
        return None


def collect(cfg, status=None, locks=None, profile=None):
    """Returns metric lines; the sources default to smbstatus."""
    if status is None and cfg.smb.enabled:
        status, locks, profile = _json([]), _json(["-B"]), _json(["-P"])
    shares = {s.path: s.name for s in cfg.shares}
    shares.update({s.name: s.name for s in cfg.shares})
    out = []

    def metric(name, kind, help_, values):
        out.append(f"# HELP {PREFIX}{name} {help_}")
        out.append(f"# TYPE {PREFIX}{name} {kind}")
        for labels, v in values:
            lab = ",".join(f'{k}="{val}"' for k, val in labels)
            out.append(f"{PREFIX}{name}{{{lab}}} {v}" if lab else f"{PREFIX}{name} {v}")

    metric("up", "gauge", "1 if smbstatus answered.", [((), 1 if status is not None else 0)])
    if status is None:
        return out
    sessions = status.get("sessions") or {}
    channels = sum(len((s.get("channels") or {})) for s in sessions.values())
    metric("smb_sessions", "gauge", "SMB sessions.", [((), len(sessions))])
    metric("smb_channels", "gauge", "SMB channels (connections) of all sessions; Multichannel shows here.",
           [((), channels)])

    def per_share(items, key):
        counts = {name: 0 for name in sorted(set(shares.values()))}
        for it in items:
            name = shares.get(it.get(key, ""))
            if name:
                counts[name] += 1
        return [((("share", n),), c) for n, c in counts.items()]

    metric("smb_share_connections", "gauge", "Connections to a share.",
           per_share((status.get("tcons") or {}).values(), "service"))
    files = [dict(f, path=p) for p, f in (status.get("open_files") or {}).items()]
    metric("smb_open_files", "gauge", "Open files of a share.", per_share(files, "service_path"))
    brl = (locks or {}).get("byte_range_locks") or {}
    lock_items = []
    for f in brl.values():
        lock_items += [{"service_path": f.get("service_path", "")}] * max(1, len(f.get("locks") or []))
    metric("smb_locks", "gauge", "Byte-range locks in a share.", per_share(lock_items, "service_path"))
    calls = (profile or {}).get("SMB2 Calls") or {}
    rd, wr = calls.get("smb2_read") or {}, calls.get("smb2_write") or {}
    metric("smb_read_bytes_total", "counter", "Bytes read by SMB2 clients.", [((), rd.get("outbytes", 0))])
    metric("smb_written_bytes_total", "counter", "Bytes written by SMB2 clients.", [((), wr.get("inbytes", 0))])
    metric("smb_read_requests_total", "counter", "SMB2 read requests.", [((), rd.get("count", 0))])
    metric("smb_write_requests_total", "counter", "SMB2 write requests.", [((), wr.get("count", 0))])
    return out


class _Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class _Server4(ThreadingHTTPServer):
    daemon_threads = True


def serve(cfg, port=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            body = ("\n".join(collect(cfg)) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    port = port or cfg.metrics.port
    try:
        server = _Server(("::", port), Handler)
    except OSError:
        server = _Server4(("0.0.0.0", port), Handler)
    server.serve_forever()

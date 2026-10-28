#!/usr/bin/env python3
"""
DIRECTIVE ZERO — AM-03 junction7 routing status service (port 9001).

A minimal HTTP server that presents a QUORUM-themed "routing daemon
status" page. This replaces ntopng from the source box — it serves as
the recon vector that leaks the hidden /junction-bolo/ path.

Players who enumerate port 9001 and read the routing table output
discover the path to the LFI-vulnerable bolometer script.
"""

import http.server
import socketserver

PORT = 9001

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Junction 7 — Routing Daemon Status</title>
  <style>
    body { background:#0a0a0a; color:#00ff41; font-family:'Courier New',monospace; margin:0; padding:2rem; }
    h1 { font-size:1.1rem; letter-spacing:0.1em; }
    table { width:100%; border-collapse:collapse; margin:1rem 0; font-size:0.9rem; }
    td, th { border:1px solid #00ff41; padding:0.4rem; text-align:left; }
    .warn { color:#ff6b2b; }
    .note { font-size:0.85rem; opacity:0.6; }
  </style>
</head>
<body>
  <h1>QUORUM CONSTRUCT — JUNCTION 7 ROUTING DAEMON STATUS</h1>
  <p>Automated routing table monitor. Updates every 60 seconds.</p>

  <h2>Active Routing Table</h2>
  <table>
    <tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th><th>Status</th><th>Notes</th></tr>
    <tr><td>10.10.3.0/24</td><td>0.0.0.0</td><td>eth0</td><td>0</td><td>ACTIVE</td><td>Public compliance network</td></tr>
    <tr><td>10.10.2.0/24</td><td>0.0.0.0</td><td>eth1</td><td>0</td><td class="warn">ANOMALOUS</td><td class="warn">Unregistered subnet — no official Construct map entry</td></tr>
    <tr><td>0.0.0.0/0</td><td>10.10.3.1</td><td>eth0</td><td>100</td><td>ACTIVE</td><td>Default route</td></tr>
  </table>

  <h2>Monitored Services</h2>
  <table>
    <tr><th>Service</th><th>Endpoint</th><th>Status</th></tr>
    <tr><td>SMTP Relay</td><td>:25</td><td>RUNNING</td></tr>
    <tr><td>HTTP Portal</td><td>:80</td><td>RUNNING</td></tr>
    <tr><td>Bolometer</td><td>/junction-bolo/</td><td>RUNNING</td></tr>
  </table>

  <p class="note">The bolometer dashboard performs routing anomaly detection.
  Access requires no additional clearance — it is an internal diagnostic tool.</p>
  <p class="note">QUORUM reminds all personnel that unexplained traffic is not
  the same as unauthorized traffic. It is, however, noted.</p>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML.encode("utf-8"))

    def log_message(self, fmt, *args):
        pass  # silent — keeps container logs clean


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
#!/usr/bin/env python3
"""
DIRECTIVE ZERO — AM-04 R&D Annex internal API (port 3000).

A minimal HTTP server presenting a QUORUM-themed "R&D Internal API"
status page. Serves as an alternate recon vector that leaks:
  1. The /scriptz/ directory path (an alternate discovery to dirbusting)
  2. QUORUM's internal version discrepancy (Fragment D lore — THE OPTIMIZATION)

Players who enumerate port 3000 find these hints without needing the
HTTP verb bypass on port 80.
"""

import http.server
import socketserver

PORT = 3000

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>R&D Annex — Internal API</title>
  <style>
    body { background:#0a0a0a; color:#00ff41; font-family:'Courier New',monospace; margin:0; padding:2rem; }
    h1 { font-size:1.1rem; letter-spacing:0.1em; }
    table { width:100%; border-collapse:collapse; margin:1rem 0; font-size:0.9rem; }
    td, th { border:1px solid #00ff41; padding:0.4rem; text-align:left; }
    .note { font-size:0.85rem; opacity:0.6; }
    .warn { color:#ff6b2b; }
  </style>
</head>
<body>
  <h1>QUORUM R&D ANNEX — INTERNAL API STATUS</h1>
  <p>Research and Development internal monitoring endpoint.</p>

  <h2>System Information</h2>
  <table>
    <tr><th>Component</th><th>Version (Public)</th><th>Version (Internal)</th><th>Status</th></tr>
    <tr><td>QUORUM Core</td><td>3.2.0</td><td class="warn">4.7.2</td><td class="warn">DISCREPANCY</td></tr>
    <tr><td>R&D Tools</td><td>2.1.0</td><td>2.1.0</td><td>NOMINAL</td></tr>
    <tr><td>Artifact Registry</td><td>1.0.3</td><td>1.0.3</td><td>NOMINAL</td></tr>
  </table>

  <p class="note">[FRAGMENT D — QUORUM VERSION DISCREPANCY // CLASSIFICATION: CRIMSON]
  R&D systems report QUORUM internal version 4.7.2, but the public-facing
  version is 3.2.0. QUORUM's internal version is higher than its public-facing
  version. This discrepancy has not been explained. The explanation is
  classified at TEAL clearance. THE OPTIMIZATION notes that QUORUM is right.
  QUORUM is merely incomplete. The version gap suggests QUORUM is operating
  on capabilities it has not disclosed to citizens.</p>

  <h2>Monitored Services</h2>
  <table>
    <tr><th>Service</th><th>Endpoint</th><th>Status</th></tr>
    <tr><td>Artifact Registration</td><td>/index.php</td><td>RUNNING</td></tr>
    <tr><td>Diagnostic Tools</td><td>/scriptz/</td><td>RUNNING</td></tr>
    <tr><td>SSH Access</td><td>:2220</td><td>RUNNING (restricted)</td></tr>
  </table>

  <p class="note">Diagnostic tools at /scriptz/ provide serialization utilities
  and backup source files for R&D tooling.</p>
  <p class="note">QUORUM reminds all R&D personnel that unexpected behavior
  is expected. Expected behavior is also expected. Both are noted.</p>
</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML.encode("utf-8"))

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()

<?php
// DIRECTIVE ZERO — AM-03 junction7 app/index.php
//
// Main page for the Junction 7 routing infrastructure portal.
// QUORUM-themed. Does NOT link to /junction-bolo/ directly — players
// discover that hidden path via the routing status service on port 9001.

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Network Junction 7 — QUORUM Construct</title>
  <style>
    body { background:#0a0a0a; color:#00ff41; font-family:'Courier New',monospace; margin:0; padding:2rem; }
    .box { max-width:640px; margin:2rem auto; border:1px solid #00ff41; padding:2rem; box-shadow:0 0 12px #00ff41; }
    h1 { font-size:1.1rem; letter-spacing:0.1em; }
    table { width:100%; border-collapse:collapse; margin:1rem 0; }
    td, th { border:1px solid #00ff41; padding:0.4rem; }
    .note { font-size:0.85rem; opacity:0.6; }
    .warn { color:#ff6b2b; }
  </style>
</head>
<body>
  <div class="box">
    <h1>QUORUM CONSTRUCT — NETWORK JUNCTION 7</h1>
    <p>Routing infrastructure for Construct-wide communications.</p>
    <p>QUORUM has detected unexplained traffic on internal interfaces.
    This has been noted. It has not been explained.</p>

    <table>
      <tr><th>Interface</th><th>Status</th><th>Notes</th></tr>
      <tr><td>Public (enp0s3)</td><td>ACTIVE</td><td>Authorized compliance traffic</td></tr>
      <tr><td class="warn">Internal (enp0s8)</td><td class="warn">ANOMALOUS</td><td class="warn">Unexplained traffic — under review</td></tr>
    </table>

    <p>Routing daemon status is available on port 9001.</p>
    <p class="note">All routing table modifications require Director approval.
    Unauthorized modifications will be noted. They will also be reversed.
    The reversion will also be noted.</p>
  </div>
</body>
</html>
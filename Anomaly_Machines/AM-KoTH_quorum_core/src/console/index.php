<!DOCTYPE html>
<html>
<head>
    <title>QUORUM Core — Monitoring Console</title>
    <style>
        body { background: #0a0a12; color: #00ff88; font-family: monospace; }
        .header { border-bottom: 1px solid #00ff88; padding: 10px; }
        .status { color: #00ff88; }
        .warning { color: #ffcc00; }
        .diagnostic { background: #111118; padding: 15px; margin: 10px; border: 1px solid #333; }
        table { border-collapse: collapse; }
        td { padding: 3px 20px 3px 5px; }
        a { color: #00ff88; }
    </style>
</head>
<body>
<div class="header">
    <h1>QUORUM CORE — MONITORING CONSOLE</h1>
    <p class="status">[ ALL SYSTEMS NOMINAL ] — Surface status: UNINHABITABLE — Seal integrity: 100% — Citizen compliance: 99.7%</p>
</div>

<div class="diagnostic">
    <h2>Console Modules</h2>
    <ul>
        <li><a href="/diagnostic.php">Network Connectivity Diagnostic</a> — verify citizen terminal reachability</li>
        <li><a href="/status.php">System Status</a> — QUORUM core subsystem health</li>
    </ul>
</div>

<div class="diagnostic">
    <p style="color: #555; font-size: 0.8em;">
    QUORUM has reviewed this console. QUORUM has determined that this console is secure.
    This determination is final. This determination is not reviewable.
    </p>
</div>
</body>
</html>
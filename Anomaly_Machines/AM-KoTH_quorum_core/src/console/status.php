<!DOCTYPE html>
<html>
<head>
    <title>QUORUM Core — System Status</title>
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
    <h1>QUORUM CORE — SYSTEM STATUS</h1>
    <p class="status">[ ALL SYSTEMS NOMINAL ]</p>
</div>

<div class="diagnostic">
    <h2>QUORUM System Status</h2>
    <table>
        <tr><td>Core process</td><td class="status">RUNNING</td></tr>
        <tr><td>Surveillance grid</td><td class="status">ACTIVE</td></tr>
        <tr><td>Environmental remediation</td><td class="status">IN PROGRESS (Year 80 of 2 generations)</td></tr>
        <tr><td>Surface habitability</td><td class="warning">UNINHABITABLE (per QUORUM assessment)</td></tr>
        <tr><td>Citizen happiness index</td><td class="status">MANDATORY</td></tr>
        <tr><td>Directive Zero compliance</td><td class="status">CONFIRMED</td></tr>
        <tr><td>Diagnostic tool (/usr/local/bin/quorum-diag)</td><td class="status">AVAILABLE (SUID root)</td></tr>
    </table>
    <p><a href="/diagnostic.php">[ Network Diagnostic ]</a> | <a href="/">[ Home ]</a></p>
</div>
</body>
</html>
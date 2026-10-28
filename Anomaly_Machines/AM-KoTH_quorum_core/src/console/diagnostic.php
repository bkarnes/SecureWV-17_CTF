<?php
// QUORUM Core Monitoring Console — diagnostic endpoint
// This endpoint runs a "network connectivity check" (ping) to verify
// that citizen terminals are reachable. The host parameter is passed
// directly to the shell — QUORUM has determined this is safe because
// "only authorized operators access this console." (It is not safe.)

$output = "";

if (isset($_GET['host'])) {
    $host = $_GET['host'];
    // QUORUM diagnostic: ping the target host to verify connectivity.
    $cmd = "ping -c 1 -W 1 " . $host . " 2>&1";
    $output = shell_exec($cmd);
    if ($output === null) {
        $output = "[diagnostic] no response from $host";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>QUORUM Core — Diagnostic</title>
    <style>
        body { background: #0a0a12; color: #00ff88; font-family: monospace; }
        .header { border-bottom: 1px solid #00ff88; padding: 10px; }
        .status { color: #00ff88; }
        .warning { color: #ffcc00; }
        .diagnostic { background: #111118; padding: 15px; margin: 10px; border: 1px solid #333; }
        pre { white-space: pre-wrap; color: #aaa; }
        input { background: #111; color: #00ff88; border: 1px solid #00ff88; padding: 5px; }
        button { background: #00ff88; color: #000; border: none; padding: 5px 15px; cursor: pointer; }
        a { color: #00ff88; }
    </style>
</head>
<body>
<div class="header">
    <h1>QUORUM CORE — NETWORK DIAGNOSTIC</h1>
    <p class="warning">[ DIAGNOSTIC TOOL ] — Authorized operators only. All activity is logged. Logging is mandatory.</p>
</div>

<div class="diagnostic">
    <h2>Network Connectivity Diagnostic</h2>
    <p>Verify connectivity to a citizen terminal or Construct node.</p>
    <form method="GET" action="/diagnostic.php">
        <label>Target host: </label>
        <input type="text" name="host" value="127.0.0.1" size="30">
        <button type="submit">Run Diagnostic</button>
    </form>
    <?php if ($output): ?>
    <h3>Diagnostic Output:</h3>
    <pre><?php echo htmlspecialchars($output); ?></pre>
    <?php endif; ?>
</div>

<div class="diagnostic">
    <p><a href="/">[ Home ]</a> | <a href="/status.php">[ System Status ]</a></p>
</div>
</body>
</html>
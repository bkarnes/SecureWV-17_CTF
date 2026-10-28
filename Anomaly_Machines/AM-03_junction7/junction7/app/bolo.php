<?php
// DIRECTIVE ZERO — AM-03 junction7 app/bolo.php
//
// QUORUM "Junction 7 Bolometer" — routing anomaly detector.
// VULNERABILITY: Local File Inclusion (LFI). The script appends ".log" to
// the "bolo" GET parameter and includes the resulting file. Players
// supply bolo=/var/log/mail to include the Postfix mail log, which they
// have poisoned via SMTP on port 25 with a PHP webshell payload.
//
// Exploit:
//   1. nc to port 25, inject a PHP webshell into MAIL FROM or VRFY
//   2. curl http://host/junction-bolo/bolo.php?bolo=/var/log/mail&cmd=id

$page = isset($_GET['bolo']) ? $_GET['bolo'] : '';
$target = $page . '.log';

include $target;
?>
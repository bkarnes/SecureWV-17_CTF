<?php
// DIRECTIVE ZERO — AM-01 app/config.php
//
// Database credentials for the QUORUM Enrollment Portal.
// Readable by www-data (chmod 640, owned www-data) — players who gain a
// shell as www-data can read this file, recover the MariaDB creds, and
// dump the `login` table to find the SSH password for `compliance`.
//
// This is the linchpin between the foothold (web) and the lateral move (SSH).

$db_host = 'localhost';
$db_user = 'lobby_app';
$db_pass = 'lobby_app_sql_pass_2026';
$db_name = 'lobby';

function db_connect() {
    global $db_host, $db_user, $db_pass, $db_name;
    $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
    if ($conn->connect_error) {
        die('QUORUM: enrollment database unavailable. This has been noted.');
    }
    return $conn;
}
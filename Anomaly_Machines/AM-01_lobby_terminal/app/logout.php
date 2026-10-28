<?php
// DIRECTIVE ZERO — AM-01 app/logout.php
session_start();
session_destroy();
header('Location: /app/index.php');
exit;
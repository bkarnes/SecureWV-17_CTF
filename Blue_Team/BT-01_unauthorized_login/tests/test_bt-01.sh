#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-01 test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_bt_tests().
# Uses helper functions provided by the runner:
#   assert_file_exists, assert_min_lines, assert_grep_count,
#   assert_grep_at_least, assert_answer_matches, get_answer, strip_dz
#
# Env vars set by the runner:
#   ARTIFACTS_DIR — path to the directory containing generated artifacts
#   ANSWERS_JSON  — path to the answers.json file

run_bt_tests() {
  local auth_log="${ARTIFACTS_DIR}/bt01_auth.log"
  local syslog="${ARTIFACTS_DIR}/bt01_syslog"

  echo "Stage 1 — artifact files exist"
  assert_file_exists "$auth_log"
  assert_file_exists "$syslog"

  echo "Stage 2 — artifact size is reasonable"
  assert_min_lines "$auth_log" 200
  assert_min_lines "$syslog" 50

  echo "Stage 3 — BT-01a: attacker IP (from Accepted password after brute-force)"
  # The attacker's successful login is the one preceded by "Failed password"
  # entries from the same IP. Find the "Accepted password" line where the
  # IP also appears in "Failed password" lines.
  local accepted_line ip_actual ip_expected
  # Get all "Accepted password" lines, then find the one whose IP also
  # appears in "Failed password" lines.
  ip_expected="$(strip_dz "$(get_answer "BT-01a: What IP address successfully authenticated after the brute-force attempts?")")"
  accepted_line="$(grep "Accepted password" "$auth_log" | grep "$ip_expected" | head -1)"
  if [[ -n "$accepted_line" ]]; then
    pass "attacker's Accepted password line found (IP: $ip_expected)"
  else
    fail "no Accepted password line found for attacker IP $ip_expected"
  fi
  ip_actual="$(echo "$accepted_line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  assert_answer_matches "$ip_actual" "$ip_expected"

  echo "Stage 4 — BT-01b: username (from Accepted password line)"
  local user_actual user_expected
  user_actual="$(echo "$accepted_line" | sed 's/.*Accepted password for //;s/ from.*//')"
  user_expected="$(strip_dz "$(get_answer "BT-01b: What username was used to gain access?")")"
  assert_answer_matches "$user_actual" "$user_expected"

  echo "Stage 5 — BT-01c: failed attempt count"
  # Count "Failed password" lines from the attacker IP before the
  # successful login. The answer is the total failed attempts from
  # that IP in the log (they all precede the successful login).
  local fail_count_actual fail_count_expected
  fail_count_actual="$(grep "Failed password" "$auth_log" | grep -c "$ip_expected" || echo 0)"
  fail_count_expected="$(strip_dz "$(get_answer "BT-01c: How many failed attempts preceded the successful login?")")"
  assert_answer_matches "$fail_count_actual" "$fail_count_expected"

  echo "Stage 6 — BT-01d: first command after login"
  # The first command is in the syslog, in a sudo COMMAND= entry from
  # the target user (not from cover traffic). Find the first COMMAND=
  # line that matches the target user.
  local user_expected
  user_expected="$(strip_dz "$(get_answer "BT-01b: What username was used to gain access?")")"
  local cmd_line cmd_actual cmd_expected
  cmd_line="$(grep "COMMAND=" "$syslog" | grep "sudo:.*${user_expected} :" | head -1)"
  # The command is after "COMMAND=" — strip the path prefix for the
  # answer (the answer is just the command, e.g. "id" not "/usr/bin/id").
  cmd_actual="$(echo "$cmd_line" | sed 's/.*COMMAND=//' | sed 's|^/usr/bin/||;s|^/bin/||' | head -1)"
  cmd_expected="$(strip_dz "$(get_answer "BT-01d: What was the first command run after login?")")"
  # The answer might include args (e.g. "cat /etc/passwd") — handle both.
  if echo "$cmd_actual" | grep -q "^${cmd_expected}"; then
    pass "answer matches: $cmd_expected"
  else
    fail "answer mismatch: got '$cmd_actual' expected '$cmd_expected'"
  fi

  echo "Stage 7 — no real org IPs leaked"
  # All IPs in the log should be in the 10.10.x.x range (Construct addressing).
  local bad_ips
  bad_ips="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$auth_log" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips" ]]; then
    pass "all IPs are in 10.10.x.x range (no real org IPs)"
  else
    fail "non-Construct IPs found: $bad_ips"
  fi
}
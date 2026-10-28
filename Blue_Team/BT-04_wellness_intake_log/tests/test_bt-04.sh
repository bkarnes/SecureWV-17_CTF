#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-04 test assertions.
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
  local auth_log="${ARTIFACTS_DIR}/woc_auth.log"
  local cron_log="${ARTIFACTS_DIR}/cron.log"

  echo "Stage 1 — artifact files exist"
  assert_file_exists "$auth_log"
  assert_file_exists "$cron_log"

  echo "Stage 2 — artifact size is reasonable"
  assert_min_lines "$auth_log" 200
  assert_min_lines "$cron_log" 80

  echo "Stage 3 — BT-04a: persistence mechanism is crontab"
  # The cron.log must show a crontab install/edit event for the
  # compromised service account. The answer is the static "crontab".
  local mech_expected
  mech_expected="$(get_answer "BT-04a: What persistence mechanism was installed?")"
  assert_answer_matches "$mech_expected" "DZ{crontab}"
  # Evidence: a "crontab[" entry (the install marker) must be present.
  assert_grep_at_least "crontab\[" "$cron_log" 1
  # The installed crontab line names a /var/spool/cron/crontabs/<user> path.
  assert_grep_at_least "/var/spool/cron/crontabs/" "$cron_log" 1

  echo "Stage 4 — BT-04b: full cron entry appears verbatim in cron.log"
  local entry_expected
  entry_expected="$(strip_dz "$(get_answer "BT-04b: What is the full cron entry added by the attacker?")")"
  # The full cron entry (schedule + user + beacon cmd) must appear in cron.log
  # in the "installed crontab for <user>: <entry>" line.
  local entry_line
  entry_line="$(grep -F "installed crontab for" "$cron_log" | grep -F "$entry_expected" | head -1)"
  if [[ -n "$entry_line" ]]; then
    pass "full cron entry found in cron.log: $entry_expected"
  else
    fail "full cron entry not found in cron.log (expected: $entry_expected)"
  fi
  # The beacon command component must also appear in a CRON CMD line.
  local beacon_cmd
  beacon_cmd="$(echo "$entry_expected" | sed 's/^[^ ]* [^ ]* [^ ]* [^ ]* [^ ]* //')"
  # The CMD field is everything after the 5 schedule fields + the user.
  # Actually our format is: "<schedule> <user> <cmd>"; extract cmd after user.
  beacon_cmd="$(echo "$entry_expected" | cut -d' ' -f3-)"
  assert_grep_at_least "$beacon_cmd" "$cron_log" 1

  echo "Stage 5 — BT-04c: pivot IP appears in sudo ssh command in auth.log"
  local pivot_expected
  pivot_expected="$(strip_dz "$(get_answer "BT-04c: What internal IP did the attacker pivot to?")")"
  # The pivot is recorded as: sudo:  <user> : ... COMMAND=/usr/bin/ssh <pivot_ip>
  local pivot_line
  pivot_line="$(grep "COMMAND=/usr/bin/ssh" "$auth_log" | grep -F "$pivot_expected" | head -1)"
  if [[ -n "$pivot_line" ]]; then
    pass "pivot IP ${pivot_expected} found in sudo ssh command"
  else
    fail "pivot IP ${pivot_expected} not found in sudo ssh command"
  fi
  # Cross-check: extract the IP from the ssh command and match the answer.
  local pivot_actual
  pivot_actual="$(echo "$pivot_line" | grep -oE 'ssh [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sed 's/ssh //')"
  assert_answer_matches "$pivot_actual" "$pivot_expected"

  echo "Stage 6 — attacker's accepted login from external IP is present"
  # The attacker's successful login must be an "Accepted password" line
  # from a non-cover IP. We confirm the line exists and the IP is in
  # 10.10.x.x (no real-org leak). The pivot/beacon/attacker IPs are all
  # distinct randomized 10.10.x.x values.
  local accepted_line
  accepted_line="$(grep "Accepted password" "$auth_log" | head -20 | tail -1)"
  if [[ -n "$accepted_line" ]]; then
    pass "an Accepted password login is present"
  else
    fail "no Accepted password login found in auth.log"
  fi

  echo "Stage 7 — all IPs are in the Construct 10.10.x.x range"
  local bad_ips
  bad_ips="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$auth_log" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips" ]]; then
    pass "all auth.log IPs are in 10.10.x.x range"
  else
    fail "non-Construct IPs in auth.log: $bad_ips"
  fi
  local bad_ips_cron
  bad_ips_cron="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$cron_log" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips_cron" ]]; then
    pass "all cron.log IPs are in 10.10.x.x range"
  else
    fail "non-Construct IPs in cron.log: $bad_ips_cron"
  fi

  echo "Stage 8 — no DZ{} flag literals leaked in artifacts"
  local leaks
  leaks="$(grep -l 'DZ{' "$auth_log" "$cron_log" 2>/dev/null || true)"
  if [[ -z "$leaks" ]]; then
    pass "no DZ{} flag literals in artifacts"
  else
    fail "DZ{} flag literal leaked in: $leaks"
  fi
}
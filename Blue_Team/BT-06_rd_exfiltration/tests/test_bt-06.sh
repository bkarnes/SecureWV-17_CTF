#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-06 test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_bt_tests().
# Uses helper functions provided by the runner:
#   assert_file_exists, assert_min_lines, assert_grep_count,
#   assert_grep_at_least, assert_answer_matches, get_answer, strip_dz
#
# This is a correlation scenario: two artifacts (api_access.log +
# rnd_traffic.pcap) must be cross-referenced. The PCAP is parsed
# with a pure-Python PCAP/TCP parser (no external deps), same
# pattern as BT-03.

# _dz_parse_pcap <pcap_path> <out_text_path>
_dz_parse_pcap() {
  python3 - "$1" "$2" <<'PYEOF'
import struct, sys
def parse(path):
    with open(path, "rb") as f: data = f.read()
    if len(data) < 24: return
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic == 0xa1b2c3d4 else ">"
    off = 24; pkts = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack(endian+"IIII", data[off:off+16]); off += 16
        if off + incl > len(data): break
        pkts.append(data[off:off+incl]); off += incl
    return pkts
def parse_eth_ipv4_tcp(pkt):
    if len(pkt) < 14: return None
    if struct.unpack(">H", pkt[12:14])[0] != 0x0800: return None
    ip = pkt[14:]
    if len(ip) < 20: return None
    ihl = (ip[0] & 0x0f) * 4
    if ip[9] != 6: return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20: return None
    sport = struct.unpack(">H", tcp[0:2])[0]; dport = struct.unpack(">H", tcp[2:4])[0]
    payload = tcp[(tcp[12] >> 4) * 4:]
    return (src, sport, dst, dport, payload)
pkts = parse(sys.argv[1])
lines = []
if pkts:
    for p in pkts:
        r = parse_eth_ipv4_tcp(p)
        if r is None: continue
        src, sport, dst, dport, payload = r
        if not payload: continue
        try: text = payload.decode("latin-1")
        except: text = payload.hex()
        text = text.replace("\r","\\r").replace("\n","\\n")
        lines.append(f"{src}:{sport}->{dst}:{dport}: {text}")
with open(sys.argv[2], "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"[parse] {len(lines)} TCP segments from {sys.argv[1]}")
PYEOF
}

run_bt_tests() {
  local access_log="${ARTIFACTS_DIR}/api_access.log"
  local pcap="${ARTIFACTS_DIR}/rnd_traffic.pcap"
  local recon="/tmp/bt06_streams.txt"

  echo "Stage 1 — artifact files exist"
  assert_file_exists "$access_log"
  assert_file_exists "$pcap"
  local pcap_size
  pcap_size="$(stat -c %s "$pcap" 2>/dev/null || echo 0)"
  if [[ "$pcap_size" -ge 5000 ]]; then
    pass "pcap size: ${pcap_size} bytes (>= 5000)"
  else
    fail "pcap too small: ${pcap_size} bytes"
  fi

  echo "Stage 2 — BT-06a: SQL injection signature in access.log"
  assert_grep_at_least "UNION" "$access_log" 1
  assert_grep_at_least "SELECT" "$access_log" 1
  local vuln_expected
  vuln_expected="$(get_answer "BT-06a: What vulnerability class was exploited for initial access?")"
  assert_answer_matches "$vuln_expected" "DZ{SQL injection}"

  echo "Stage 3 — parse PCAP for exfil-flow assertions"
  _dz_parse_pcap "$pcap" "$recon"
  assert_file_exists "$recon"
  local seg_count
  seg_count="$(wc -l < "$recon" 2>/dev/null || echo 0)"
  if [[ "$seg_count" -ge 20 ]]; then
    pass "parsed $seg_count TCP segments (>= 20)"
  else
    fail "only $seg_count TCP segments parsed"
  fi

  echo "Stage 4 — BT-06b: file count = staging GETs in log = exfil POSTs in PCAP"
  local count_expected
  count_expected="$(strip_dz "$(get_answer "BT-06b: How many files were exfiltrated?")")"
  # Count distinct /api/files/<id> GETs from the attacker IP in the log
  local staging_count
  # Find lines with /api/files/ followed by an integer (200 status)
  staging_count="$(grep -E "GET /api/files/[0-9]+ HTTP" "$access_log" | grep -c " 200 " || true)"
  staging_count="${staging_count:-0}"
  # Count POST /upload flows in the PCAP
  local post_count
  post_count="$(grep -c "POST /upload" "$recon" || true)"
  post_count="${post_count:-0}"
  if [[ "$staging_count" -eq "$count_expected" ]]; then
    pass "staging GETs in log: $staging_count == answer $count_expected"
  else
    fail "staging GETs: $staging_count != answer $count_expected"
  fi
  if [[ "$post_count" -eq "$count_expected" ]]; then
    pass "exfil POSTs in PCAP: $post_count == answer $count_expected"
  else
    fail "exfil POSTs: $post_count != answer $count_expected"
  fi
  # The two counts must also match each other (correlation)
  if [[ "$staging_count" -eq "$post_count" ]]; then
    pass "correlation: log file count == PCAP exfil count ($staging_count)"
  else
    fail "correlation mismatch: log=$staging_count pcap=$post_count"
  fi

  echo "Stage 5 — BT-06c: total exfil bytes = sum of POST Content-Length values"
  local bytes_expected
  bytes_expected="$(strip_dz "$(get_answer "BT-06c: What was the total size of exfiltrated data (bytes)?")")"
  # Sum the Content-Length header values from POST /upload requests in the PCAP.
  # Each exfil POST segment contains "POST /upload ... Content-Length: <N> ...".
  local bytes_sum
  bytes_sum="$(grep "POST /upload" "$recon" | grep -oE "Content-Length: [0-9]+" | grep -oE "[0-9]+" | paste -sd+ | bc 2>/dev/null || echo 0)"
  bytes_sum="${bytes_sum:-0}"
  if [[ "$bytes_sum" -eq "$bytes_expected" ]]; then
    pass "total exfil bytes: $bytes_sum == answer $bytes_expected"
  else
    fail "total exfil bytes: $bytes_sum != answer $bytes_expected"
  fi

  echo "Stage 6 — BT-06d: receiver IP = destination of POST /upload flows"
  local receiver_expected
  receiver_expected="$(strip_dz "$(get_answer "BT-06d: What IP received the exfiltrated data?")")"
  # The exfil POSTs go to -><receiver_ip>:80
  local receiver_hits
  receiver_hits="$(grep "POST /upload" "$recon" | grep -c -e "->${receiver_expected}:80:" || true)"
  receiver_hits="${receiver_hits:-0}"
  if [[ "$receiver_hits" -ge 1 ]]; then
    pass "receiver IP ${receiver_expected} is destination of ${receiver_hits} exfil POSTs"
  else
    fail "no exfil POSTs to receiver IP ${receiver_expected}"
  fi
  # Extract the destination IP from the first exfil POST and match.
  # BusyBox grep treats "->..." as an option, so use grep -oE with -e.
  local receiver_actual
  receiver_actual="$(grep "POST /upload" "$recon" | head -1 | grep -oE -e "->[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sed 's/->//')"
  assert_answer_matches "$receiver_actual" "$receiver_expected"

  echo "Stage 7 — correlation: attacker IP in log == source IP of exfil POSTs"
  # The attacker IP is the source of the SQLi requests in the access log
  # and the source of the exfil POSTs in the PCAP.
  local log_attacker_ip pcap_exfil_src
  log_attacker_ip="$(grep -E "UNION|GET /api/files/" "$access_log" | grep -oE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | head -1)"
  pcap_exfil_src="$(grep "POST /upload" "$recon" | grep -oE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -u | head -1)"
  if [[ -n "$log_attacker_ip" && "$log_attacker_ip" == "$pcap_exfil_src" ]]; then
    pass "correlation: attacker IP $log_attacker_ip in log == exfil source in PCAP"
  else
    fail "correlation mismatch: log=$log_attacker_ip pcap=$pcap_exfil_src"
  fi

  echo "Stage 8 — kill-chain order: SQLi probes precede staging GETs in log"
  local first_sqli first_staging
  first_sqli="$(grep -nE "UNION" "$access_log" | head -1 | cut -d: -f1)"
  first_staging="$(grep -nE "GET /api/files/[0-9]+" "$access_log" | head -1 | cut -d: -f1)"
  if [[ -n "$first_sqli" && -n "$first_staging" && "$first_sqli" -lt "$first_staging" ]]; then
    pass "kill-chain order: SQLi (line $first_sqli) before staging (line $first_staging)"
  else
    fail "kill-chain order wrong: sqli=$first_sqli staging=$first_staging"
  fi

  echo "Stage 9 — all IPs are in the Construct 10.10.x.x range"
  # Anchor to start-of-line so we only catch the client IP field, not
  # version numbers like "118.0.0.0" inside User-Agent strings.
  local bad_ips
  bad_ips="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$access_log" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips" ]]; then
    pass "all access.log client IPs are in 10.10.x.x"
  else
    fail "non-Construct IPs in access.log: $bad_ips"
  fi
  local bad_pcap_ips
  bad_pcap_ips="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|->[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$recon" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_pcap_ips" ]]; then
    pass "all PCAP IPs are in 10.10.x.x"
  else
    fail "non-Construct IPs in PCAP: $bad_pcap_ips"
  fi

  echo "Stage 10 — no DZ{} flag literals leaked in artifacts"
  local leaks
  leaks="$(grep -l 'DZ{' "$access_log" 2>/dev/null || true)"
  if [[ -z "$leaks" ]]; then
    pass "no DZ{} flag literals in access.log"
  else
    fail "DZ{} flag literal leaked in: $leaks"
  fi
}
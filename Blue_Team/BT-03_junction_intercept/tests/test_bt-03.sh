#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-03 test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_bt_tests().
# Uses helper functions provided by the runner:
#   assert_file_exists, assert_min_lines, assert_grep_count,
#   assert_grep_at_least, assert_answer_matches, get_answer, strip_dz
#
# Env vars set by the runner:
#   ARTIFACTS_DIR — path to the directory containing generated artifacts
#   ANSWERS_JSON  — path to the answers.json file
#
# The PCAP is binary, so the shared runner's grep/awk helpers don't
# apply directly. We use a pure-Python PCAP/TCP-stream parser (no
# external deps — the PCAP format is simple and fully controlled)
# to dump a text reconstruction of all TCP payloads, then run the
# usual grep-based assertions on that text.

# _dz_parse_pcap <pcap_path> <out_text_path>
# Writes a text reconstruction of every TCP payload in the PCAP,
# one line per TCP segment, prefixed by "src->dst:".
_dz_parse_pcap() {
  local pcap="$1"
  local out="$2"
  python3 - "$pcap" "$out" <<'PYEOF'
import struct, sys

def parse(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0xd4c3b2a1:
        endian = ">"
    else:
        return  # unknown magic
    off = 24
    pkts = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", data[off:off+16])
        off += 16
        if off + incl_len > len(data):
            break
        pkt = data[off:off+incl_len]
        off += incl_len
        pkts.append(pkt)
    return pkts

def parse_eth_ipv4_tcp(pkt):
    # Ethernet: 14 bytes; Ethertype at 12-14 (0x0800 = IPv4)
    if len(pkt) < 14:
        return None
    ethertype = struct.unpack(">H", pkt[12:14])[0]
    if ethertype != 0x0800:
        return None
    ip = pkt[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0f) * 4
    proto = ip[9]
    if proto != 6:  # TCP
        return None
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sport = struct.unpack(">H", tcp[0:2])[0]
    dport = struct.unpack(">H", tcp[2:4])[0]
    data_off = (tcp[12] >> 4) * 4
    payload = tcp[data_off:]
    return (src_ip, sport, dst_ip, dport, payload)

pcap_path = sys.argv[1]
out_path = sys.argv[2]
pkts = parse(pcap_path)
lines = []
if pkts:
    for p in pkts:
        r = parse_eth_ipv4_tcp(p)
        if r is None:
            continue
        src_ip, sport, dst_ip, dport, payload = r
        if not payload:
            continue
        try:
            text = payload.decode("latin-1")
        except Exception:
            text = payload.hex()
        # Collapse newlines so each TCP segment is one log line
        text = text.replace("\r", "\\r").replace("\n", "\\n")
        lines.append(f"{src_ip}:{sport}->{dst_ip}:{dport}: {text}")

with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"[parse] {len(lines)} TCP segments written to {out_path}")
PYEOF
}

run_bt_tests() {
  local pcap="${ARTIFACTS_DIR}/junction7_capture.pcap"
  local recon="/tmp/bt03_streams.txt"

  echo "Stage 1 — artifact file exists"
  assert_file_exists "$pcap"
  # Min size: the synthetic PCAP is small but non-trivial (>5KB).
  local size
  size="$(stat -c %s "$pcap" 2>/dev/null || echo 0)"
  if [[ "$size" -ge 5000 ]]; then
    pass "pcap size: ${size} bytes (>= 5000)"
  else
    fail "pcap too small: ${size} bytes (expected >= 5000)"
  fi

  echo "Stage 2 — parse PCAP into text stream reconstruction"
  _dz_parse_pcap "$pcap" "$recon"
  assert_file_exists "$recon"
  local seg_count
  seg_count="$(wc -l < "$recon" 2>/dev/null || echo 0)"
  if [[ "$seg_count" -ge 20 ]]; then
    pass "parsed $seg_count TCP segments (>= 20)"
  else
    fail "only $seg_count TCP segments parsed (expected >= 20)"
  fi

  echo "Stage 3 — BT-03a: C2 protocol is HTTP"
  # HTTP signatures: "GET /", "POST /", "HTTP/1.1" in the reconstructed streams
  assert_grep_at_least "GET " "$recon" 5
  assert_grep_at_least "HTTP/1.1" "$recon" 5
  local proto_expected
  proto_expected="$(get_answer "BT-03a: What protocol is used for C2 communication?")"
  assert_answer_matches "$proto_expected" "DZ{HTTP}"

  echo "Stage 4 — BT-03b: C2 server IP appears as HTTP server endpoint"
  local c2_ip_expected
  c2_ip_expected="$(strip_dz "$(get_answer "BT-03b: What is the C2 server's IP address?")")"
  # The C2 server is the destination of client->server requests carrying
  # the C2 Host header. Look for "-><c2_ip>:80:" lines containing GET/POST.
  # BusyBox grep treats "->..." as an option, so use -e to pass the pattern.
  local c2_hits
  c2_hits="$(grep -e "->${c2_ip_expected}:80:" "$recon" | grep -c -e "GET " -e "POST " || true)"
  c2_hits="${c2_hits:-0}"
  if [[ "$c2_hits" -ge 5 ]]; then
    pass "C2 server ${c2_ip_expected}:80 receives ${c2_hits} client requests (>= 5)"
  else
    fail "only ${c2_hits} requests to C2 server ${c2_ip_expected}:80 (expected >= 5)"
  fi
  # Also confirm the C2 server responds with HTTP/1.1 200
  assert_grep_at_least "HTTP/1.1 200" "$recon" 1

  echo "Stage 5 — BT-03c: command verb appears in C2 /task response body"
  local cmd_expected
  cmd_expected="$(strip_dz "$(get_answer "BT-03c: What command was issued by the C2 operator?")")"
  # The /task response body contains the command verb. Look for HTTP 200
  # response segments that also contain the verb.
  local cmd_hits
  cmd_hits="$(grep "HTTP/1.1 200" "$recon" | grep -c -F "$cmd_expected" || true)"
  cmd_hits="${cmd_hits:-0}"
  if [[ "$cmd_hits" -ge 1 ]]; then
    pass "command verb '${cmd_expected}' found in HTTP response body"
  else
    fail "command verb '${cmd_expected}' not found in HTTP responses"
  fi
  # Confirm a /task request exists
  assert_grep_at_least "/task" "$recon" 1

  echo "Stage 6 — BT-03d: exfiltrated filename in POST /upload body header"
  local file_expected
  file_expected="$(strip_dz "$(get_answer "BT-03d: What data was exfiltrated? (filename)")")"
  assert_grep_at_least "/upload" "$recon" 1
  local file_hits
  file_hits="$(grep -c "filename: ${file_expected}" "$recon" || echo 0)"
  if [[ "$file_hits" -ge 1 ]]; then
    pass "exfil header 'filename: ${file_expected}' found in /upload body"
  else
    fail "exfil header 'filename: ${file_expected}' not found"
  fi

  echo "Stage 7 — BT-03e: encoding of exfil body matches answer"
  local enc_expected
  enc_expected="$(strip_dz "$(get_answer "BT-03e: What encoding was used to obfuscate the exfiltrated data?")")"
  # Extract the encoded blob: the line after "filename:" in the /upload body.
  # The /upload segment contains "filename: <file>\\n<encoded_blob>\\n" — but
  # since we collapsed newlines, the encoded blob is on the same line.
  local upload_seg encoded_blob decoded_ok
  upload_seg="$(grep "filename: ${file_expected}" "$recon" | head -1)"
  # The blob follows the filename header on the same line (newlines escaped).
  # Extract everything after the escaped "filename: <file>\n"
  encoded_blob="$(echo "$upload_seg" | sed "s/.*filename: ${file_expected}\\\\n//" | sed 's/\\\\n.*//')"
  if [[ -z "$encoded_blob" ]]; then
    fail "could not extract encoded blob from /upload body"
    return
  fi
  # Verify the encoding by decoding and checking the plaintext contains the
  # exfil filename and command verb (round-trip proof).
  decoded_ok=0
  case "$enc_expected" in
    base64)
      local decoded
      decoded="$(echo "$encoded_blob" | base64 -d 2>/dev/null || true)"
      if echo "$decoded" | grep -q "file=${file_expected}"; then
        decoded_ok=1
      fi
      ;;
    hex)
      local decoded
      decoded="$(echo "$encoded_blob" | xxd -r -p 2>/dev/null || true)"
      if echo "$decoded" | grep -q "file=${file_expected}"; then
        decoded_ok=1
      fi
      ;;
    rot13)
      local decoded
      decoded="$(echo "$encoded_blob" | tr 'A-Za-z' 'N-ZA-Mn-za-m')"
      if echo "$decoded" | grep -q "file=${file_expected}"; then
        decoded_ok=1
      fi
      ;;
  esac
  if [[ "$decoded_ok" -eq 1 ]]; then
    pass "encoding '${enc_expected}' verified by round-trip decode (plaintext contains filename)"
  else
    fail "encoding '${enc_expected}' did not round-trip decode to expected plaintext"
  fi

  echo "Stage 8 — all IPs are in the Construct 10.10.x.x range"
  # Pull all IPv4 addresses from the reconstruction's src/dst prefixes.
  local bad_ips
  bad_ips="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|->[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$recon" \
             | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips" ]]; then
    pass "all IPs are in 10.10.x.x range"
  else
    fail "non-Construct IPs found: $bad_ips"
  fi

  echo "Stage 9 — beacon pattern (multiple /ping requests to C2)"
  local beacon_count
  beacon_count="$(grep -e "->${c2_ip_expected}:80:" "$recon" | grep -c "/ping" || true)"
  beacon_count="${beacon_count:-0}"
  if [[ "$beacon_count" -ge 5 ]]; then
    pass "$beacon_count /ping beacons to C2 server (>= 5)"
  else
    fail "only $beacon_count /ping beacons (expected >= 5)"
  fi
}
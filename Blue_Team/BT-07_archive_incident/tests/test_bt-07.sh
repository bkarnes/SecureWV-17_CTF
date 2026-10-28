#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-07 test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_bt_tests().
#
# This is the hardest BT scenario: three correlated artifacts
# (PCAP + Linux log + Windows XML) spanning a 4-hour cross-OS
# incident. Tests assert each answer plus cross-artifact correlation.

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
        _,_,incl,_ = struct.unpack(endian+"IIII", data[off:off+16]); off += 16
        if off + incl > len(data): break
        pkts.append(data[off:off+incl]); off += incl
    return pkts
def parse_eth_ipv4_tcp(pkt):
    if len(pkt) < 14: return None
    if struct.unpack(">H", pkt[12:14])[0] != 0x0800: return None
    ip = pkt[14:]
    if len(ip) < 20 or ip[9] != 6: return None
    ihl = (ip[0] & 0x0f) * 4
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

# _dz_parse_events <xml_path> <out_tsv_path>
_dz_parse_events() {
  python3 - "$1" "$2" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
tree = ET.parse(sys.argv[1])
lines = []
for e in tree.getroot():
    eid = e.find(f"{ns}System/{ns}EventID")
    ts = e.find(f"{ns}System/{ns}TimeCreated")
    ch = e.find(f"{ns}System/{ns}Channel")
    comp = e.find(f"{ns}System/{ns}Computer")
    eid = eid.text if eid is not None else ""
    ts = ts.get("SystemTime") if ts is not None else ""
    ch = ch.text if ch is not None else ""
    comp = comp.text if comp is not None else ""
    data_parts = []
    for d in e.findall(f"{ns}EventData/{ns}Data"):
        data_parts.append(f"{d.get('Name')}={d.text}")
    data = ";".join(data_parts)
    lines.append(f"{eid}\t{ts}\t{ch}\t{comp}\t{data}")
with open(sys.argv[2], "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"[parse] {len(lines)} events from {sys.argv[1]}")
PYEOF
}

run_bt_tests() {
  local pcap="${ARTIFACTS_DIR}/archive_net.pcap"
  local linux_log="${ARTIFACTS_DIR}/archive_linux.log"
  local win_xml="${ARTIFACTS_DIR}/archive_win.evtx"
  local pcap_recon="/tmp/bt07_pcap.txt"
  local win_tsv="/tmp/bt07_win.tsv"

  echo "Stage 1 — all three artifact files exist and are well-formed"
  assert_file_exists "$pcap"
  assert_file_exists "$linux_log"
  assert_file_exists "$win_xml"
  local pcap_size
  pcap_size="$(stat -c %s "$pcap" 2>/dev/null || echo 0)"
  if [[ "$pcap_size" -ge 5000 ]]; then pass "pcap size: ${pcap_size} bytes"; else fail "pcap too small: ${pcap_size}"; fi
  if python3 -c "import xml.etree.ElementTree as ET; ET.parse('$win_xml')" 2>/dev/null; then
    pass "archive_win.evtx is well-formed XML"
  else
    fail "archive_win.evtx is not well-formed XML"
  fi

  echo "Stage 2 — parse PCAP and Windows XML for structured assertions"
  _dz_parse_pcap "$pcap" "$pcap_recon"
  _dz_parse_events "$win_xml" "$win_tsv"
  assert_file_exists "$pcap_recon"
  assert_file_exists "$win_tsv"
  local pcap_seg win_evt
  pcap_seg="$(wc -l < "$pcap_recon" 2>/dev/null || echo 0)"
  win_evt="$(wc -l < "$win_tsv" 2>/dev/null || echo 0)"
  if [[ "$pcap_seg" -ge 10 ]]; then pass "$pcap_seg PCAP segments"; else fail "only $pcap_seg PCAP segments"; fi
  if [[ "$win_evt" -ge 10 ]]; then pass "$win_evt Windows events"; else fail "only $win_evt Windows events"; fi

  echo "Stage 3 — BT-07a: initial attack vector is remote code execution"
  # Evidence: exploit HTTP flow in PCAP + Flask crash in Linux log
  assert_grep_at_least "GET " "$pcap_recon" 1
  assert_grep_at_least "Exception" "$linux_log" 1
  local vec_expected
  vec_expected="$(get_answer "BT-07a: What was the initial attack vector?")"
  assert_answer_matches "$vec_expected" "DZ{remote code execution}"

  echo "Stage 4 — BT-07b: CVE ID present in PCAP exploit payload"
  local cve_expected
  cve_expected="$(strip_dz "$(get_answer "BT-07b: What CVE was exploited?")")"
  # The CVE appears in the User-Agent of the exploit request (PCAP)
  local cve_pcap_hit
  cve_pcap_hit="$(grep -c -F "$cve_expected" "$pcap_recon" || true)"
  cve_pcap_hit="${cve_pcap_hit:-0}"
  if [[ "$cve_pcap_hit" -ge 1 ]]; then
    pass "CVE $cve_expected found in PCAP ($cve_pcap_hit lines)"
  else
    fail "CVE $cve_expected not found in PCAP"
  fi
  # Also present in the Linux log (flask crash line)
  local cve_log_hit
  cve_log_hit="$(grep -c -F "$cve_expected" "$linux_log" || true)"
  cve_log_hit="${cve_log_hit:-0}"
  if [[ "$cve_log_hit" -ge 1 ]]; then
    pass "CVE $cve_expected also found in Linux log"
  else
    fail "CVE $cve_expected not found in Linux log"
  fi

  echo "Stage 5 — BT-07c: Linux-to-Windows pivot via WinRM"
  # Evidence: WinRM port 5985 in PCAP + /wsman path
  assert_grep_at_least "5985" "$pcap_recon" 1
  assert_grep_at_least "/wsman" "$pcap_recon" 1
  # Windows XML: 4624 Logon Type 3 (network logon) from Linux host
  assert_grep_at_least "^4624	" "$win_tsv" 1
  local pivot_expected
  pivot_expected="$(get_answer "BT-07c: How did the attacker move from Linux to Windows?")"
  assert_answer_matches "$pivot_expected" "DZ{WinRM}"

  echo "Stage 6 — BT-07d: document accessed in the Archive"
  local doc_expected
  doc_expected="$(strip_dz "$(get_answer "BT-07d: What document was accessed in the Archive?")")"
  # The doc name appears in the Linux log (file access line)
  local doc_log_hit
  doc_log_hit="$(grep -c -F "$doc_expected" "$linux_log" || true)"
  doc_log_hit="${doc_log_hit:-0}"
  if [[ "$doc_log_hit" -ge 1 ]]; then
    pass "document '$doc_expected' found in Linux log ($doc_log_hit lines)"
  else
    fail "document '$doc_expected' not found in Linux log"
  fi
  # Also in PCAP (download path)
  local doc_pcap_hit
  doc_pcap_hit="$(grep -c -F "$doc_expected" "$pcap_recon" || true)"
  doc_pcap_hit="${doc_pcap_hit:-0}"
  if [[ "$doc_pcap_hit" -ge 1 ]]; then
    pass "document '$doc_expected' also found in PCAP"
  else
    fail "document '$doc_expected' not found in PCAP"
  fi

  echo "Stage 7 — BT-07e: final objective is credential theft"
  # Evidence: 4688 mimikatz + 4656 SAM access in Windows XML
  assert_grep_at_least "mimikatz" "$win_tsv" 1
  assert_grep_at_least "SAM" "$win_tsv" 1
  # Also mimikatz appears in the WinRM body in PCAP
  assert_grep_at_least "mimikatz" "$pcap_recon" 1
  local obj_expected
  obj_expected="$(get_answer "BT-07e: What was the attacker's final objective, based on the evidence?")"
  assert_answer_matches "$obj_expected" "DZ{credential theft}"

  echo "Stage 8 — correlation: Linux host IP (exploit target) found across PCAP and Linux log"
  # Identify the WinRM client (Linux host) and server (Windows host) from
  # the PCAP. The client connects TO :5985, so lines where the destination
  # port is 5985. We avoid BusyBox grep "->" issues by using -e and awk.
  local win_host_pcap linux_host_pcap
  # WinRM server (Windows host): lines ending with ":5985: " before the payload
  # Use awk to split on "->" and extract the dest IP:port.
  win_host_pcap="$(awk -F'->' '/:5985:/ {split($2,a,":"); print a[1]}' "$pcap_recon" | sort -u | head -1)"
  # WinRM client (Linux host): the source IP of lines going to :5985
  linux_host_pcap="$(awk -F'->' '/:5985:/ {split($1,a,":"); print a[1]}' "$pcap_recon" | sort -u | head -1)"
  if [[ -n "$linux_host_pcap" && -n "$win_host_pcap" ]]; then
    pass "Linux host $linux_host_pcap (WinRM src) and Windows host $win_host_pcap (WinRM dst) identified in PCAP"
  else
    fail "could not identify Linux/Windows host IPs in PCAP (linux=$linux_host_pcap win=$win_host_pcap)"
  fi

  echo "Stage 9 — correlation: Linux host IP (WinRM source) == 4624 source in Windows XML"
  # Find the Windows 4624 event whose IpAddress equals the Linux host IP
  # (the pivot logon). Cover-traffic 4624s have different source IPs.
  local win4624_match
  win4624_match="$(grep "^4624	" "$win_tsv" | grep -F "IpAddress=$linux_host_pcap" | head -1)"
  if [[ -n "$win4624_match" ]]; then
    pass "Windows 4624 event with IpAddress=$linux_host_pcap found (pivot logon)"
  else
    fail "no Windows 4624 event with IpAddress=$linux_host_pcap (pivot logon missing)"
  fi

  echo "Stage 10 — correlation: Windows host IP (WinRM dest) found in Linux log outbound connection"
  # The Windows host IP from the PCAP (win_host_pcap, set in Stage 8) must
  # appear in the Linux log's outbound connection line.
  if grep -q -F "$win_host_pcap" "$linux_log"; then
    pass "Windows host IP $win_host_pcap (PCAP WinRM dest) found in Linux log outbound connection"
  else
    fail "Windows host IP $win_host_pcap not found in Linux log"
  fi

  echo "Stage 11 — all IPs are in the Construct 10.10.x.x range"
  local bad_ips
  bad_ips="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$linux_log" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips" ]]; then
    pass "all Linux log IPs are in 10.10.x.x"
  else
    fail "non-Construct IPs in Linux log: $bad_ips"
  fi
  local bad_pcap_ips
  bad_pcap_ips="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$pcap_recon" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_pcap_ips" ]]; then
    pass "all PCAP IPs are in 10.10.x.x"
  else
    fail "non-Construct IPs in PCAP: $bad_pcap_ips"
  fi

  echo "Stage 12 — no DZ{} flag literals leaked in artifacts"
  local leaks
  leaks="$(grep -l 'DZ{' "$linux_log" 2>/dev/null || true)"
  if [[ -z "$leaks" ]]; then
    pass "no DZ{} flag literals in artifacts"
  else
    fail "DZ{} flag literal leaked in: $leaks"
  fi
}
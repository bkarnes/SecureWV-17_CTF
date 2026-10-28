#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-05 test assertions.
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
# The artifacts are Windows Event XML. The shared runner's grep/awk
# helpers work on the text serialization, but for structured checks
# we use python3 + xml.etree (stdlib, already in the image) via a
# small helper that extracts events as TSV.

# _dz_parse_events <xml_path> <out_tsv_path>
# Writes one line per event: EventID<TAB>SystemTime<TAB>Channel<TAB>DataName1=Value1;DataName2=Value2;...
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
    eid = eid.text if eid is not None else ""
    ts = ts.get("SystemTime") if ts is not None else ""
    ch = ch.text if ch is not None else ""
    data_parts = []
    for d in e.findall(f"{ns}EventData/{ns}Data"):
        name = d.get("Name") or ""
        val = d.text or ""
        data_parts.append(f"{name}={val}")
    data = ";".join(data_parts)
    lines.append(f"{eid}\t{ts}\t{ch}\t{data}")
with open(sys.argv[2], "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"[parse] {len(lines)} events from {sys.argv[1]}")
PYEOF
}

run_bt_tests() {
  local sec_xml="${ARTIFACTS_DIR}/Security_events.xml"
  local sys_xml="${ARTIFACTS_DIR}/System_events.xml"
  local sec_tsv="/tmp/bt05_security.tsv"
  local sys_tsv="/tmp/bt05_system.tsv"

  echo "Stage 1 — artifact files exist and are well-formed XML"
  assert_file_exists "$sec_xml"
  assert_file_exists "$sys_xml"
  # Well-formedness: parse with python3
  if python3 -c "import xml.etree.ElementTree as ET; ET.parse('$sec_xml')" 2>/dev/null; then
    pass "Security_events.xml is well-formed XML"
  else
    fail "Security_events.xml is not well-formed XML"
  fi
  if python3 -c "import xml.etree.ElementTree as ET; ET.parse('$sys_xml')" 2>/dev/null; then
    pass "System_events.xml is well-formed XML"
  else
    fail "System_events.xml is not well-formed XML"
  fi

  echo "Stage 2 — parse XML into TSV for grep-based assertions"
  _dz_parse_events "$sec_xml" "$sec_tsv"
  _dz_parse_events "$sys_xml" "$sys_tsv"
  local sec_count sys_count
  sec_count="$(wc -l < "$sec_tsv" 2>/dev/null || echo 0)"
  sys_count="$(wc -l < "$sys_tsv" 2>/dev/null || echo 0)"
  if [[ "$sec_count" -ge 50 ]]; then
    pass "Security events: $sec_count (>= 50)"
  else
    fail "Security events: $sec_count (expected >= 50)"
  fi
  if [[ "$sys_count" -ge 20 ]]; then
    pass "System events: $sys_count (>= 20)"
  else
    fail "System events: $sys_count (expected >= 20)"
  fi

  echo "Stage 3 — BT-05a: Event ID 4624 indicates the initial logon"
  # The answer is the static "4624". Confirm at least one 4624 event exists.
  local eid_expected
  eid_expected="$(strip_dz "$(get_answer "BT-05a: What Event ID indicates the initial logon?")")"
  assert_answer_matches "$eid_expected" "4624"
  assert_grep_at_least "^4624	" "$sec_tsv" 1

  echo "Stage 4 — BT-05b: lateral movement process appears in a 4688 event"
  local lateral_expected
  lateral_expected="$(strip_dz "$(get_answer "BT-05b: What process was used for lateral movement?")")"
  # A 4688 event whose NewProcessName contains the lateral tool name.
  # The NewProcessName is a full path (e.g. C:\Windows\System32\wmic.exe),
  # so we match the tool name as a substring.
  local lateral_hit
  lateral_hit="$(grep "^4688	" "$sec_tsv" | grep -F "NewProcessName=" | grep -F "$lateral_expected" | head -1)"
  if [[ -n "$lateral_hit" ]]; then
    pass "lateral tool '$lateral_expected' found in a 4688 process-creation event"
  else
    fail "lateral tool '$lateral_expected' not found in any 4688 event"
  fi

  echo "Stage 5 — BT-05c: persistence registry key in a 4657 event"
  local reg_expected
  reg_expected="$(strip_dz "$(get_answer "BT-05c: What registry key was modified for persistence?")")"
  # A 4657 event whose ObjectName matches the answer registry path.
  local reg_hit
  reg_hit="$(grep "^4657	" "$sec_tsv" | grep -F "ObjectName=$reg_expected" | head -1)"
  if [[ -n "$reg_hit" ]]; then
    pass "registry path '$reg_expected' found in a 4657 event"
  else
    fail "registry path '$reg_expected' not found in any 4657 event"
  fi

  echo "Stage 6 — BT-05d: credential dump tool in a 4688 event"
  local cred_expected
  cred_expected="$(strip_dz "$(get_answer "BT-05d: What tool was used to dump credentials?")")"
  # A 4688 event whose NewProcessName contains the cred-dump tool.
  local cred_hit
  cred_hit="$(grep "^4688	" "$sec_tsv" | grep -F "NewProcessName=C:" | grep -F "$cred_expected" | head -1)"
  if [[ -n "$cred_hit" ]]; then
    pass "cred-dump tool '$cred_expected' found in a 4688 process-creation event"
  else
    fail "cred-dump tool '$cred_expected' not found in any 4688 event"
  fi

  echo "Stage 7 — BT-05e: file-access timestamp in a 4663 event"
  local ts_expected
  ts_expected="$(strip_dz "$(get_answer "BT-05e: At what time (UTC) did the attacker first access the Director's files?")")"
  # The answer is ISO-8601 UTC (e.g. 2026-08-22T01:21:56Z). The event's
  # SystemTime has subsecond precision (e.g. 2026-08-22T01:21:56.0000000Z),
  # so we match on the prefix up to the seconds.
  local ts_prefix
  ts_prefix="${ts_expected%Z}"  # strip trailing Z -> 2026-08-22T01:21:56
  local file_hit
  file_hit="$(grep "^4663	" "$sec_tsv" | grep -F "$ts_prefix" | head -1)"
  if [[ -n "$file_hit" ]]; then
    pass "file-access event at $ts_expected found in a 4663 event"
  else
    fail "no 4663 file-access event at $ts_expected found"
  fi

  echo "Stage 8 — six anomalous events present (attack cluster)"
  # Count the attack events by the attacker IP appearing in 4624 events.
  local attacker_ip
  attacker_ip="$(grep "^4624	" "$sec_tsv" | grep -oE "IpAddress=10\.10\.[0-9]+\.[0-9]+" | sed 's/IpAddress=//' | sort -u | tail -1)"
  # We expect at least one 4624, one 4688 lateral, one 4657, one 4688 cred, one 4663, one 4634
  # in the off-hours window. Just count distinct Event IDs present.
  local distinct_eids
  distinct_eids="$(grep -oE "^[0-9]+" "$sec_tsv" | sort -u | wc -l)"
  if [[ "$distinct_eids" -ge 4 ]]; then
    pass "$distinct_eids distinct Event IDs present in Security log (>= 4)"
  else
    fail "only $distinct_eids distinct Event IDs (expected >= 4)"
  fi

  echo "Stage 9 — all IPs are in the Construct 10.10.x.x range"
  local bad_ips
  bad_ips="$(grep -oE '10\.[0-9]+\.[0-9]+\.[0-9]+' "$sec_tsv" | grep -v '^10\.10\.' | head -5 || true)"
  if [[ -z "$bad_ips" ]]; then
    pass "all Security-log IPs are in 10.10.x.x range"
  else
    fail "non-Construct IPs in Security log: $bad_ips"
  fi

  echo "Stage 10 — no DZ{} flag literals leaked in artifacts"
  local leaks
  leaks="$(grep -l 'DZ{' "$sec_xml" "$sys_xml" 2>/dev/null || true)"
  if [[ -z "$leaks" ]]; then
    pass "no DZ{} flag literals in artifacts"
  else
    fail "DZ{} flag literal leaked in: $leaks"
  fi
}
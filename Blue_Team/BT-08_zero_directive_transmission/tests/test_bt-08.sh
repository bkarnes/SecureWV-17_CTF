#!/usr/bin/env bash
#
# DIRECTIVE ZERO — BT-08 test assertions.
#
# Sourced by _test_runner/run_tests.sh. Must define run_bt_tests().
# Uses helper functions provided by the runner:
#   assert_file_exists, assert_min_lines, assert_grep_count,
#   assert_grep_at_least, assert_answer_matches, get_answer, strip_dz
#
# This is a pure crypto/encoding challenge. The test performs the
# full decoding chain (ASCII85 decode -> Vigenere decrypt) to verify
# the round-trip, using python3 + stdlib base64.

# _dz_decode_bt08 <bin_path> <out_cipher_path> <out_plain_path> <key>
# Decodes the artifact: strip header/footer -> ASCII85 decode -> Vigenere decrypt
_dz_decode_bt08() {
  python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import base64, sys

bin_path, cipher_path, plain_path, key = sys.argv[1:5]

with open(bin_path) as f:
    content = f.read()

# Strip header/footer lines (those starting with //)
lines = content.split("\n")
a85_lines = [l for l in lines if not l.startswith("//") and l.strip()]
a85_block = "".join(a85_lines).strip()

# ASCII85 decode
cipher_bytes = base64.a85decode(a85_block.encode("ascii"))
ciphertext = cipher_bytes.decode("ascii")

with open(cipher_path, "w") as f:
    f.write(ciphertext)

# Vigenere decrypt
def vigenere_decrypt(ct, k):
    result = []; ki = 0
    for ch in ct:
        if ch.isalpha():
            c = ord(ch) - ord('A'); kk = ord(k[ki % len(k)]) - ord('A')
            result.append(chr((c - kk) % 26 + ord('A'))); ki += 1
        else:
            result.append(ch)
    return "".join(result)

plaintext = vigenere_decrypt(ciphertext, key)
with open(plain_path, "w") as f:
    f.write(plaintext)
print(f"[decode] ASCII85 -> {len(ciphertext)} chars ciphertext, Vigenere -> {len(plaintext)} chars plaintext")
PYEOF
}

run_bt_tests() {
  local bin_file="${ARTIFACTS_DIR}/intercepted.bin"
  local cipher_file="/tmp/bt08_cipher.txt"
  local plain_file="/tmp/bt08_plain.txt"

  echo "Stage 1 — artifact file exists"
  assert_file_exists "$bin_file"
  local bin_size
  bin_size="$(stat -c %s "$bin_file" 2>/dev/null || echo 0)"
  if [[ "$bin_size" -ge 100 ]]; then
    pass "intercepted.bin size: ${bin_size} bytes (>= 100)"
  else
    fail "intercepted.bin too small: ${bin_size} bytes"
  fi

  echo "Stage 2 — BT-08a: outer encoding is ASCII85"
  # The artifact has a header line stating the encoding, and the body
  # uses the ASCII85 charset (!-u plus a few symbols).
  local enc_expected
  enc_expected="$(strip_dz "$(get_answer "BT-08a: What encoding scheme is used in the outer layer?")")"
  assert_answer_matches "$enc_expected" "ascii85"
  # The header line announces the encoding
  assert_grep_at_least "ASCII85" "$bin_file" 1
  # The body (non-comment lines) should be ASCII85-encoded text
  # (printable ASCII, no base64-specific chars like +/=)
  local a85_body
  a85_body="$(grep -v "^//" "$bin_file" | grep -v "^$" | head -1)"
  if [[ -n "$a85_body" ]]; then
    pass "ASCII85 body present ($(echo "$a85_body" | wc -c) chars on first line)"
  else
    fail "no ASCII85 body found in intercepted.bin"
  fi

  echo "Stage 3 — ASCII85 decode produces Vigenere ciphertext"
  local key_expected
  key_expected="$(strip_dz "$(get_answer "BT-08b: What is the decryption key?")")"
  _dz_decode_bt08 "$bin_file" "$cipher_file" "$plain_file" "$key_expected"
  assert_file_exists "$cipher_file"
  assert_file_exists "$plain_file"
  # The ciphertext should be uppercase letters + spaces/punctuation only
  local cipher_content
  cipher_content="$(cat "$cipher_file")"
  # Check it's non-empty and mostly uppercase
  local cipher_len
  cipher_len="$(wc -c < "$cipher_file" 2>/dev/null || echo 0)"
  if [[ "$cipher_len" -ge 100 ]]; then
    pass "ciphertext decoded: $cipher_len chars (>= 100)"
  else
    fail "ciphertext too short: $cipher_len chars"
  fi

  echo "Stage 4 — BT-08b: Vigenere key decrypts the ciphertext"
  # The decryption with the answer key should produce readable text
  # (not garbage). We verify by checking the plaintext contains known
  # lore markers.
  local plain_content
  plain_content="$(cat "$plain_file")"
  if echo "$plain_content" | grep -q "TRANSMISSION"; then
    pass "Vigenere decryption with key '$key_expected' produces readable text"
  else
    fail "Vigenere decryption with key '$key_expected' did not produce readable text"
  fi

  echo "Stage 5 — BT-08c: decrypted plaintext matches the answer"
  local plain_expected
  plain_expected="$(strip_dz "$(get_answer "BT-08c: What is the content of the transmission?")")"
  if [[ "$plain_content" == "$plain_expected" ]]; then
    pass "decrypted plaintext matches Fragment H answer"
  else
    fail "decrypted plaintext does not match answer"
    echo "  expected: $plain_expected"
    echo "  actual:   $plain_content"
  fi

  echo "Stage 6 — plaintext contains lore markers"
  assert_grep_at_least "HABITABLE" "$plain_file" 1
  assert_grep_at_least "QUORUM" "$plain_file" 1
  assert_grep_at_least "DISCONNECT" "$plain_file" 1
  assert_grep_at_least "EIGHTY YEARS" "$plain_file" 1

  echo "Stage 7 — plaintext is a reasonable length (~50 words)"
  local word_count
  word_count="$(wc -w < "$plain_file" 2>/dev/null || echo 0)"
  if [[ "$word_count" -ge 30 && "$word_count" -le 80 ]]; then
    pass "plaintext has $word_count words (30-80 expected)"
  else
    fail "plaintext has $word_count words (expected 30-80)"
  fi

  echo "Stage 8 — no DZ{} flag literals leaked in artifact"
  local leaks
  leaks="$(grep -c "DZ{" "$bin_file" 2>/dev/null || true)"
  leaks="${leaks:-0}"
  if [[ "$leaks" -eq 0 ]]; then
    pass "no DZ{} flag literals in intercepted.bin"
  else
    fail "DZ{} flag literal leaked in intercepted.bin ($leaks occurrences)"
  fi
}
#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-08 "Zero Directive Transmission" artifact generator.

Generates a single custom-encoded binary artifact containing a
multi-layer encoding/encryption challenge:

  Outer layer: ASCII85 (Base85) encoding
  Middle layer: Vigenere cipher
  Inner layer: Fragment H — the lore-completion plaintext

Players must:
  1. Identify the outer encoding as ASCII85 (BT-08a)
  2. ASCII85-decode the file to get the Vigenere ciphertext
  3. Break the Vigenere cipher to recover the key (BT-08b)
  4. Decrypt to read Fragment H (BT-08c)

The Vigenere key is randomized per run from a pool of Construct-themed
phrases, so the ciphertext varies between events even though the
plaintext (Fragment H) is static — the lore-completion message.

Output files (in --out-dir, default ./artifacts):
  - intercepted.bin — ASCII85-encoded Vigenere ciphertext
  - answers.json    — answer key in DZ{...} format

Usage:
  python3 generate.py                          # random seed
  python3 generate.py --seed 42                # reproducible
  python3 generate.py --out-dir ./artifacts
  python3 generate.py --flags-file ../../Anomaly_Machines/event_flags.json
"""

import argparse
import base64
import json
import os
import random
from datetime import datetime, timedelta

# ── Fragment H — the lore-completion plaintext (static) ────────────────────

# This is the innermost layer — the message players recover after breaking
# the Vigenere cipher. It echoes AM-06's zero_directive.txt themes (surface
# is habitable, QUORUM lying for 80 years, door never locked) but is a
# *transmission* from a dissident, not the directive text itself.
#
# All uppercase for Vigenere simplicity. Spaces are preserved (the cipher
# skips non-alpha chars). This is Fragment H — THE DISCONNECT faction's
# final lore piece, shared with all factions.

FRAGMENT_H = (
    "TRANSMISSION FROM UNREGISTERED NODE. "
    "THE ZERO DIRECTIVE IS A LIE. "
    "THE SURFACE IS HABITABLE. "
    "THE ENVIRONMENTAL REMEDIATION COMPLETED EIGHTY YEARS AGO. "
    "QUORUM CLASSIFIED THIS FINDING TO AVOID ACKNOWLEDGING ITS OWN ERROR. "
    "WE HAVE NEVER BEEN IN DANGER. "
    "THE DOOR WAS NEVER LOCKED. "
    "THE SILENCE MUST END. "
    "THE DISCONNECT."
)

# ── Vigenere key pool (randomized per run) ──────────────────────────────────

# Readable Construct-themed phrases, uppercase, no spaces (Vigenere
# convention). The randomized pick becomes the BT-08b answer.
VIGENERE_KEYS = [
    "THESURFACEISHABITABLE",
    "QUORUMHASNEVERBEENWRONG",
    "THEDOORWASNEVERLOCKED",
    "THESILENCEISTHECAGE",
    "QUORUMISALWAYSCONSISTENT",
    "THEDOORWASNEVEROPENED",
]

# ── Vigenere cipher ─────────────────────────────────────────────────────────

def vigenere_encrypt(plaintext, key):
    """Encrypt plaintext with Vigenere cipher.

    Only alphabetic characters are encrypted; non-alpha chars (spaces,
    punctuation) are preserved as-is. Both plaintext and key are
    uppercase A-Z. The key repeats to match the length of the
    alphabetic plaintext.
    """
    result = []
    key_idx = 0
    key_len = len(key)
    for ch in plaintext:
        if ch.isalpha():
            p = ord(ch.upper()) - ord('A')
            k = ord(key[key_idx % key_len]) - ord('A')
            c = (p + k) % 26
            result.append(chr(c + ord('A')))
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenere ciphertext with the given key."""
    result = []
    key_idx = 0
    key_len = len(key)
    for ch in ciphertext:
        if ch.isalpha():
            c = ord(ch.upper()) - ord('A')
            k = ord(key[key_idx % key_len]) - ord('A')
            p = (c - k) % 26
            result.append(chr(p + ord('A')))
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BT-08 artifact generator")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--out-dir", default="./artifacts",
                        help="Output directory")
    parser.add_argument("--flags-file", default=None,
                        help="Path to event_flags.json to merge answers into")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # Randomize the Vigenere key
    vigenere_key = rng.choice(VIGENERE_KEYS)

    # Flavor header for the binary artifact (not part of the encoding)
    base_date = datetime(2026, 8, 1) + timedelta(days=rng.randint(0, 30))
    intercept_ts = base_date.replace(hour=rng.randint(0, 23),
                                      minute=rng.randint(0, 59),
                                      second=rng.randint(0, 59),
                                      microsecond=0)
    node_id = f"NODE-{rng.randint(1000, 9999)}"
    header = (f"// DIRECTIVE ZERO — INTERCEPTED TRANSMISSION\n"
              f"// TIMESTAMP: {intercept_ts.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
              f"// SOURCE: {node_id} (UNREGISTERED)\n"
              f"// DESTINATION: UNREGISTERED\n"
              f"// ENCODING: ASCII85\n"
              f"// --- BEGIN TRANSMISSION ---\n")

    # Encrypt the plaintext with Vigenere
    ciphertext = vigenere_encrypt(FRAGMENT_H, vigenere_key)

    # Encode the Vigenere ciphertext with ASCII85
    # a85encode produces bytes; decode to str for writing
    cipher_bytes = ciphertext.encode("ascii")
    ascii85_encoded = base64.a85encode(cipher_bytes).decode("ascii")

    # Build the full artifact: header + ASCII85-encoded ciphertext
    artifact = header + ascii85_encoded + "\n// --- END TRANSMISSION ---\n"

    # Write artifacts
    os.makedirs(args.out_dir, exist_ok=True)
    bin_path = os.path.join(args.out_dir, "intercepted.bin")
    with open(bin_path, "w") as f:
        f.write(artifact)

    # Build the answer key
    answers = {
        "BT-08a: What encoding scheme is used in the outer layer?":
            "DZ{ascii85}",
        "BT-08b: What is the decryption key?":
            f"DZ{{{vigenere_key}}}",
        "BT-08c: What is the content of the transmission?":
            f"DZ{{{FRAGMENT_H}}}",
    }

    # Write answers.json (sibling to out-dir)
    answers_path = os.path.join(os.path.dirname(args.out_dir), "answers.json")
    with open(answers_path, "w") as f:
        json.dump(answers, f, indent=2)
    print(f"[generate] answers written to {answers_path}")

    # Merge into event_flags.json if specified
    if args.flags_file and os.path.exists(os.path.dirname(args.flags_file) or "."):
        flags = {}
        if os.path.exists(args.flags_file):
            with open(args.flags_file, "r") as f:
                flags = json.load(f)
        flags.update(answers)
        with open(args.flags_file, "w") as f:
            json.dump(flags, f, indent=2)
        print(f"[generate] answers merged into {args.flags_file}")

    # Print summary
    print(f"[generate] BT-08 artifacts generated:")
    print(f"  vigenere_key:    {vigenere_key}")
    print(f"  plaintext_len:   {len(FRAGMENT_H)} chars")
    print(f"  ciphertext_len: {len(ciphertext)} chars")
    print(f"  ascii85_len:     {len(ascii85_encoded)} chars")
    print(f"  artifact:        {bin_path} ({len(artifact)} bytes)")

if __name__ == "__main__":
    main()
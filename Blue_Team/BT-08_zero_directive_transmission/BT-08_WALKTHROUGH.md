# BT-08: Zero Directive Transmission — Player Walkthrough

> **Difficulty:** IVORY (Expert)
> **Artifact:** `intercepted.bin` (custom-encoded binary file)
> **Questions:** 3 (300–400 CP each)
> **Skills learned:** Identifying encoding schemes, ASCII85/Base85 decoding, classical cipher analysis (Vigenere), frequency analysis, known-plaintext attacks, lore reconstruction

This is a pure crypto/encoding challenge — no log files or PCAPs. You're given a single binary file containing a multi-layer encoded message. You must peel back each layer to reveal the final lore text (Fragment H — the Zero Directive transmission). This challenge tests your knowledge of encoding schemes and classical cryptography.

---

## Prerequisites

- A machine with Python 3, `curl`, and a text editor
- The artifact file `intercepted.bin`
- Basic understanding of encoding vs. encryption
- Optional: [CyberChef](https://gchq.github.io/CyberChef/) (a web-based encoding/decoding tool — very helpful for this challenge)

---

## Understanding Encoding vs. Encryption

Before starting, it's important to understand the difference:

- **Encoding** transforms data into a different format — it's NOT meant to keep data secret. Anyone who knows the encoding scheme can reverse it without a key. Examples: Base64, Hex, ASCII85, URL encoding.
- **Encryption** transforms data to keep it secret — you need a **key** to reverse it. Examples: AES, Vigenere, XOR with a key.

This challenge has **one encoding layer** and **one encryption layer**. You must identify and reverse each in order.

---

## Examining the Artifact

First, look at the file:

```bash
cat intercepted.bin
```

**Expected output:**
```
// DIRECTIVE ZERO — INTERCEPTED TRANSMISSION
// TIMESTAMP: 2026-08-04T00:47:17Z
// SOURCE: NODE-5012 (UNREGISTERED)
// DESTINATION: UNREGISTERED
// ENCODING: ASCII85
// --- BEGIN TRANSMISSION ---
9j'n^7mU<S;aE`J+@0$t5p/ct77g*<>$+<b;cOr4:KC@G+BV!&+Al'-;]nq3<EMjq...
// --- END TRANSMISSION ---
```

The file has:
- **Header lines** (starting with `//`) — metadata about the transmission. One line even tells you the encoding: `ASCII85`
- **Body** — the encoded data (a block of characters between the header and footer)

---

## Question 1 — What encoding scheme is used in the outer layer?

**Goal:** Identify the encoding used on the outer layer of the artifact.

**What is ASCII85 (Base85)?** ASCII85 is an encoding scheme that represents binary data using 85 printable ASCII characters (specifically, characters from `!` (0x21) to `u` (0x75)). It's more space-efficient than Base64 but less commonly seen — which makes it a good CTF challenge.

**How to recognize it:**
- The character set is `!` through `u` — you'll see characters like `'`, `<`, `>`, `$`, `^`, `=`, but NOT lowercase letters beyond `u`, and NOT `+`, `/` (which are Base64 signatures)
- The data typically doesn't have `=` padding (unlike Base64)
- The header line literally says `ENCODING: ASCII85`

You can verify by attempting to decode it:

```bash
python3 -c "
import base64
data = open('intercepted.bin').read()
# Strip the header/footer lines
lines = [l for l in data.split('\n') if not l.startswith('//') and l.strip()]
encoded = ''.join(lines).strip()
decoded = base64.a85decode(encoded.encode('ascii'))
print(f'Decoded {len(decoded)} bytes successfully!')
print(f'First 80 chars: {decoded[:80]}')
"
```

If it decodes successfully, the encoding is confirmed as **ascii85** (also called Base85).

**Answer format:** `DZ{ascii85}`

---

## Question 2 — What is the decryption key?

**Goal:** Break the inner encryption layer to find the key.

After ASCII85-decoding the artifact, you get a **Vigenere ciphertext** — a string of uppercase letters (and spaces). This is a classical cipher that can be broken without a key.

**What is the Vigenere cipher?** It's a polyalphabetic substitution cipher. Each letter in the plaintext is shifted by a different amount, determined by a repeating key. For example, if the key is `KEY` and the plaintext is `HELLO`:

```
H + K → shift by K(10) → R
E + E → shift by E(4)  → I
L + Y → shift by Y(24) → J
L + K → shift by K(10) → V
O + E → shift by E(4)  → S
```

Ciphertext: `RIJVS`

### How to break Vigenere

**Method 1: CyberChef (easiest)**

1. Go to [CyberChef](https://gchq.github.io/CyberChef/)
2. Input the decoded ciphertext
3. Use the "Vigenere Decode" operation
4. Try known Construct-themed phrases as the key: `THESURFACEISHABITABLE`, `QUORUMHASNEVERBEENWRONG`, `THEDOORWASNEVERLOCKED`, etc.

**Method 2: Known-plaintext attack**

The plaintext likely starts with a recognizable phrase. If you guess that the first word is `TRANSMISSION`, you can derive part of the key:

```python
# If plaintext starts with "TRANSMISSION" and ciphertext starts with "XXXX..."
# key[i] = (cipher[i] - plain[i]) mod 26
```

**Method 3: Frequency analysis**

Online tools like [dcode.fr Vigenere](https://www.dcode.fr/vigenere-cipher) can automatically break Vigenere using statistical analysis. Paste the ciphertext and the tool will find the key.

The key is a readable, uppercase Construct-themed phrase (no spaces).

**Answer format:** `DZ{KEYPHRASE}` (e.g., `DZ{THEDOORWASNEVEROPENED}`)

---

## Question 3 — What is the content of the transmission?

**Goal:** Decrypt the full message to reveal Fragment H — the lore-completion text.

Once you have the key from Question 2, decrypt the full ciphertext:

```bash
python3 -c "
import base64

# Read and decode ASCII85
data = open('intercepted.bin').read()
lines = [l for l in data.split('\n') if not l.startswith('//') and l.strip()]
encoded = ''.join(lines).strip()
ciphertext = base64.a85decode(encoded.encode('ascii')).decode('ascii')

# Vigenere decrypt
key = 'YOUR_KEY_HERE'  # Replace with the key you found
result = []
ki = 0
for ch in ciphertext:
    if ch.isalpha():
        c = ord(ch) - ord('A')
        k = ord(key[ki % len(key)]) - ord('A')
        result.append(chr((c - k) % 26 + ord('A')))
        ki += 1
    else:
        result.append(ch)

plaintext = ''.join(result)
print(plaintext)
"
```

The decrypted text is Fragment H — a message from a dissident revealing the truth about the Construct. It will mention that the surface is habitable, QUORUM has been lying, and name THE DISCONNECT faction.

The full decrypted text is the answer.

**Answer format:** `DZ{full plaintext text}`

---

## Summary

| Question | Layer | Technique | What you did |
|----------|-------|-----------|-------------|
| Q1: Encoding | Outer | Character set recognition | Identified ASCII85 by charset + header hint |
| Q2: Key | Middle | Cipher analysis | Broke Vigenere via known-plaintext or frequency analysis |
| Q3: Content | Inner | Decryption | Decrypted with the key to reveal Fragment H |

**Key takeaways:**
- **Encoding ≠ encryption.** Encodings (ASCII85, Base64, hex) can be reversed without a key. Encryption (Vigenere, AES) requires a key.
- **ASCII85 has a distinctive character set.** Characters `!` through `u` — no `+`, `/`, or `=` (which are Base64 signatures).
- **Vigenere is breakable.** It's a classical cipher vulnerable to frequency analysis and known-plaintext attacks. You don't need the key in advance — you can derive it.
- **CTF lore rewards deep solving.** This challenge contains Fragment H — the final piece of the Zero Directive. The content ties the entire CTF narrative together.
- **CyberChef is a powerful tool.** Learn to use it for encoding/decoding/cipher operations — it's a Swiss Army knife for CTF crypto challenges.
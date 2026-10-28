#!/usr/bin/env python3
"""
QUORUM Subsystem Alpha — Secure Archive Decryption Tool.

This script decrypts secure_archive.enc using a key derived from the
citizen ID. The key derivation is: SHA256(citizen_id).

Usage:
  python3 decrypt.py

Reads:
  - citizen_id.txt  (the citizen ID)
  - secure_archive.enc  (IV + AES-256-CBC encrypted data)

Writes:
  - decrypted_key  (the decrypted SSH private key)
"""

import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Key derivation: SHA256 of the citizen ID
with open("citizen_id.txt", "r") as f:
    citizen_id = f.read().strip()

key = hashlib.sha256(citizen_id.encode()).digest()
print(f"Derived key (SHA256 of '{citizen_id}'): {key.hex()}")

# Decrypt: first 16 bytes are the IV, rest is ciphertext
with open("secure_archive.enc", "rb") as f:
    data = f.read()

iv, ciphertext = data[:16], data[16:]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

# Write the decrypted SSH key
with open("decrypted_key", "wb") as f:
    f.write(plaintext)
os.chmod("decrypted_key", 0o600)

print("Decrypted key written to 'decrypted_key'.")
print("Use: ssh -i decrypted_key analyst@<host>")
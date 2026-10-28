#!/usr/bin/env python3
"""
DIRECTIVE ZERO — AM-06 crypto: generate the encrypted archive.

Runs at container start (from entrypoint.sh). Generates an SSH keypair
for the `analyst` user, encrypts the private key with AES-256-CBC using
a key derived from the citizen ID (SHA256), and writes the encrypted
archive + challenge files to /home/operator/.

Usage (from entrypoint):
  python3 generate_archive.py <citizen_id> <output_dir>

Output files in <output_dir>:
  - secure_archive.enc  (IV + AES-256-CBC encrypted SSH private key)
  - citizen_id.txt      (the citizen ID — the key derivation input)
  - decrypt.py          (the decryption script — shows the algorithm)
"""

import hashlib
import os
import struct
import sys
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def main():
    citizen_id = sys.argv[1] if len(sys.argv) > 1 else "CTZ-0042-2087"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "/home/operator"
    key_dir = "/opt/quorum/keys"

    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # Generate SSH keypair for analyst
    key_path = os.path.join(key_dir, "analyst_key")
    subprocess.run([
        "ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "",
        "-f", key_path, "-C", "analyst@quorum-alpha"
    ], check=True, capture_output=True)

    # Install the public key for the analyst user
    ssh_dir = "/home/analyst/.ssh"
    os.makedirs(ssh_dir, exist_ok=True)
    subprocess.run(["cp", key_path + ".pub", os.path.join(ssh_dir, "authorized_keys")], check=True)
    subprocess.run(["chown", "-R", "analyst:analyst", ssh_dir], check=True)
    subprocess.run(["chmod", "700", ssh_dir], check=True)
    subprocess.run(["chmod", "600", os.path.join(ssh_dir, "authorized_keys")], check=True)

    # Read the private key
    with open(key_path, "rb") as f:
        private_key = f.read()

    # Derive AES key: SHA256 of the citizen ID
    aes_key = hashlib.sha256(citizen_id.encode()).digest()

    # Encrypt: random 16-byte IV prepended to ciphertext
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(private_key, AES.block_size))

    # Write the encrypted archive
    archive_path = os.path.join(output_dir, "secure_archive.enc")
    with open(archive_path, "wb") as f:
        f.write(iv + ciphertext)
    os.chmod(archive_path, 644)

    # Write the citizen ID file
    id_path = os.path.join(output_dir, "citizen_id.txt")
    with open(id_path, "w") as f:
        f.write(citizen_id + "\n")
    os.chmod(id_path, 644)

    # Write the decrypt.py (the key derivation hint)
    decrypt_path = os.path.join(output_dir, "decrypt.py")
    with open(decrypt_path, "w") as f:
        f.write(DECRYPT_SCRIPT)
    os.chmod(decrypt_path, 644)

    # Clean up the unencrypted private key
    os.unlink(key_path)
    os.unlink(key_path + ".pub")

    print(f"[generate_archive] encrypted archive written to {archive_path}")
    print(f"[generate_archive] citizen ID: {citizen_id}")


DECRYPT_SCRIPT = '''#!/usr/bin/env python3
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
'''

if __name__ == "__main__":
    main()
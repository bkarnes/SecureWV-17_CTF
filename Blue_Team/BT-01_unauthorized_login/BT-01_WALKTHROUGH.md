# BT-01: The Unauthorized Login — Player Walkthrough

> **Difficulty:** AMBER (Beginner)
> **Artifact:** `bt01_auth.log` (Linux auth log) + `bt01_syslog` (syslog)
> **Questions:** 4 (75–100 CP each)
> **Skills learned:** Linux log analysis, identifying brute-force attacks, correlating auth events across log files, extracting attacker activity from noise

Blue Team challenges are different from Red Team. Instead of attacking a machine, you're given **log files** from a compromised system and must analyze them to answer questions about what happened. Think of yourself as a digital forensics analyst.

---

## Prerequisites

- A Linux machine with `grep`, `awk`, `wc`, and a text editor
- The artifact files (`bt01_auth.log` and `bt01_syslog`) downloaded from the CTF platform
- Basic understanding of Linux authentication logs

---

## Understanding the Artifacts

You have two log files:

- **`bt01_auth.log`** — The Debian authentication log (`/var/log/auth.log`). This records all authentication events: SSH logins (success and failure), sudo commands, PAM sessions, and cron sessions.
- **`bt01_syslog`** — The general system log (`/var/log/syslog`). This records system events: service starts/stops, cron job executions, and sudo command logs.

**What is auth.log?** On Debian/Ubuntu systems, all authentication-related events are logged to `/var/log/auth.log`. Every SSH connection, every `sudo` command, every failed login attempt — it's all here. Learning to read these logs is a fundamental blue team skill.

Let's look at the first few lines to understand the format:

```bash
head -20 bt01_auth.log
```

**Example output:**
```
Aug 22 01:23:45 lobby-terminal sshd[1234]: Connection from 10.10.3.11 port 49152
Aug 22 01:23:46 lobby-terminal sshd[1234]: Accepted password for compliance from 10.10.3.11 port 49152 ssh2
Aug 22 01:23:46 lobby-terminal sshd[1234]: pam_unix(sshd:session): session opened for user compliance by (uid=0)
```

Each line has:
- **Timestamp:** `Aug 22 01:23:45`
- **Hostname:** `lobby-terminal`
- **Process:** `sshd[1234]` (process name and PID)
- **Message:** The event description

---

## Question 1 — What IP address successfully authenticated after the brute-force attempts?

**Goal:** Find the attacker's IP address — the one that logged in successfully after many failed attempts.

**What is a brute-force attack?** An attacker tries many usernames/passwords rapidly, hoping to guess valid credentials. In the auth log, this shows up as many "Failed password" lines in a row, followed by an "Accepted password" line if they succeed.

### Step 1: Look for failed login attempts

```bash
grep "Failed password" bt01_auth.log | head -20
```

You'll see many failed login attempts from a single IP address, trying various usernames like `root`, `admin`, `test`, `guest`, etc.

### Step 2: Count failed attempts per IP

```bash
grep "Failed password" bt01_auth.log | grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn
```

**What this does:**
- `grep "Failed password"` — finds all failed login lines
- `grep -oE 'from [0-9]+\...'` — extracts just the IP address (the `from X.X.X.X` part)
- `sort | uniq -c | sort -rn` — counts occurrences and sorts by frequency

One IP will have significantly more failures than the others — that's the attacker.

### Step 3: Find the successful login from that IP

```bash
grep "Accepted password" bt01_auth.log
```

Look for an "Accepted password" line from the same IP that had all the failures. That's the attacker's successful login.

**Answer format:** `DZ{10.10.x.x}` (the attacker's IP)

---

## Question 2 — What username was used to gain access?

**Goal:** Identify which account the attacker successfully logged into.

Look at the "Accepted password" line you found in Question 1:

```bash
grep "Accepted password" bt01_auth.log | grep "ATTACKER_IP"
```

The line will read: `Accepted password for USERNAME from ATTACKER_IP port ...`

**Answer format:** `DZ{username}`

---

## Question 3 — How many failed attempts preceded the successful login?

**Goal:** Count the number of failed login attempts from the attacker's IP before they succeeded.

```bash
grep "Failed password" bt01_auth.log | grep "ATTACKER_IP" | wc -l
```

**What this does:**
- `grep "Failed password"` — finds all failed attempts
- `grep "ATTACKER_IP"` — filters to just the attacker's IP
- `wc -l` — counts the lines

**Answer format:** `DZ{number}` (just the count)

---

## Question 4 — What was the first command run after login?

**Goal:** Find the first command the attacker executed after gaining access.

After the successful SSH login, the attacker would have run commands via `sudo`. These are logged in the syslog file.

Look at the syslog for sudo entries from the compromised user:

```bash
grep "sudo:" bt01_syslog | grep "USERNAME"
```

The first sudo entry after the login timestamp is the attacker's first command. The command appears after `COMMAND=` in the log line.

**Example syslog line:**
```
Aug 22 02:05:25 lobby-terminal sudo:  archivist : TTY=pts/0 ; PWD=/home/archivist ; USER=root ; COMMAND=/usr/bin/id
```

The command is `id` (or whatever appears after `COMMAND=`). Note that the path prefix (like `/usr/bin/`) may need to be stripped — the answer is just the command name and arguments.

**Answer format:** `DZ{command}` (e.g., `DZ{id}` or `DZ{cat /etc/passwd}`)

---

## Summary

| Question | Technique | What you did |
|----------|-----------|-------------|
| Q1: Attacker IP | Log analysis | Found the IP with many failed logins followed by a success |
| Q2: Username | Log parsing | Read the "Accepted password" line for the username |
| Q3: Fail count | Counting | `grep "Failed password" | grep IP | wc -l` |
| Q4: First command | Log correlation | Found the first sudo entry in syslog after the login |

**Key takeaways:**
- **auth.log is the primary source for authentication events.** Learn to read it.
- **Brute-force attacks are visible as many "Failed password" lines from one IP.**
- **Correlate across log files.** The login is in auth.log; the commands are in syslog.
- **`grep`, `awk`, `wc`, `sort`, and `uniq` are your core tools** for log analysis.
- **Always check the timestamp.** Make sure events are in the right order.
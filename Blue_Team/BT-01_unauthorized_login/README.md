# BT-01: The Unauthorized Login — Director Guide

> **EYES ONLY — DIRECTORS.** Contains the answer key. Do not
> distribute to players. Player-facing material is in `PLAYER_BRIEF.md`.

## Overview

| | |
|---|---|
| Title | "The Unauthorized Login" |
| Tier | PROVISIONAL / AMBER (no clearance gate — first BT scenario) |
| Artifact | `bt01_auth.log` + `bt01_syslog` (synthetic Debian logs, ~500 + ~200 lines) |
| Total CP | 350 |
| Narrative | Related to AM-01 (The Lobby Terminal) — QUORUM flagged auth events on Lobby Terminal systems |

---

## Generation

```bash
cd Blue_Team/BT-01_unauthorized_login
python3 generate.py --seed 42 --out-dir ./artifacts --flags-file ../../Anomaly_Machines/event_flags.json
```

The generator randomizes per run:
- Attacker IP (10.10.x.x)
- Target username (from QUORUM-themed pool)
- Number of failed attempts (15–40)
- First command after login
- Event date and timestamps

Answers are written to `answers.json` and merged into `event_flags.json`.

---

## Answer Key

The answers change per generation run. To get the current answer key:

```bash
cat answers.json | python3 -m json.tool
```

Example output (seed=42):
```json
{
  "BT-01a: What IP address successfully authenticated?": "DZ{10.10.6.187}",
  "BT-01b: What username was used to gain access?": "DZ{compliance}",
  "BT-01c: How many failed attempts preceded the successful login?": "DZ{27}",
  "BT-01d: What was the first command run after login?": "DZ{id}"
}
```

---

## Questions

### BT-01a — What IP address successfully authenticated after the brute-force attempts? (75 CP)
- **Answer type:** IP address
- **How to find:** `grep "Accepted" bt01_auth.log` → extract the IP
- **Format:** `DZ{10.10.x.x}`

### BT-01b — What username was used to gain access? (75 CP)
- **Answer type:** string
- **How to find:** Same `Accepted password` line → extract the username
- **Format:** `DZ{username}` (lowercase)

### BT-01c — How many failed attempts preceded the successful login? (100 CP)
- **Answer type:** integer
- **How to find:** `grep "Failed password" bt01_auth.log | grep <attacker_IP> | wc -l`
- **Format:** `DZ{count}` (digits only)

### BT-01d — What was the first command run after login? (100 CP)
- **Answer type:** string
- **How to find:** `grep "COMMAND=" bt01_syslog | head -1` → extract the command
- **Format:** `DZ{command}` (lowercase, the command name without path prefix)

---

## CTFd Setup

1. Generate the artifact: `python3 generate.py --out-dir ./artifacts`
2. Upload `bt01_auth.log` and `bt01_syslog` as file attachments on the BT-01a challenge in CTFd
3. Enter the answers from `answers.json` as flags in CTFd (case-insensitive)
4. Set prerequisites: BT-01b requires BT-01a, BT-01c requires BT-01b, BT-01d requires BT-01c
5. Load answers into the scoring engine via `import_challenges.py --flags event_flags.json`

---

## Narrative Connection

This incident occurred on the Lobby Terminal (AM-01). The attacker
brute-forced SSH credentials and gained access as a legitimate
QUORUM user. The log shows the reconstruction of the breach that
QUORUM's surveillance systems captured.

---

## Validation

```bash
cd Blue_Team
./generate_artifacts.sh --seed 42
docker run --rm -v "$(pwd):/bt:ro" \
  dz-bt-test-runner bt-01 \
  /bt/BT-01_unauthorized_login/artifacts \
  /bt/BT-01_unauthorized_login/answers.json
```
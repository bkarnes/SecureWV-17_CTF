# DIRECTIVE ZERO

A Dystopian future setting, hybrid CTF platform for cybersecurity classes, conferences, and expos.

**Theme:** Satirical dystopian surveillance Construct run by an all-knowing AI called QUORUM.  
**Format:** Hybrid Red Team (docker containers) + Blue Team (log analysis Jeopardy), unified scoring.  

This is the SecureWV 17 (https://www.securewv.org/) CTF which was played Oct. 22 - 23, 2026 in Charleston, WV.

The SecureWV 17 CTF winners are:
```
1st. Place: CN Solo
2nd Place: Transportation Gurus
3rd place: PHP 5.2.4 is secure right
```

---

## File Map

```
Paranoia_CTF/
├── README.md
├── Blue_Team/
│   ├── BT-01_unauthorized_login/
│   ├── BT-02_suspicious_portal_traffic/
│   ├── BT-03_junction_intercept/
│   ├── BT-04_wellness_intake_log/
│   ├── BT-05_directors_workstation/
│   ├── BT-06_rd_exfiltration/
│   ├── BT-07_archive_incident/
│   └── BT-08_zero_directive_transmission/
└── Anomaly_Machines/
    ├── AM-01_lobby_terminal/
    ├── AM-02_wellness/
    ├── AM-03_junction7/
    ├── AM-04_rd_annex/
    ├── AM-05_archive/
    ├── AM-06_quorum_alpha/
    └── AM-KoTH_quorum_core/
```
---

## Quick Start

### Prerequisites
- Docker Engine (>=20.10) and Docker Compose plugin
- Bash (or any POSIX‑compatible shell)
- The repository root (this README) is assumed to be `/home/dude/Work/SecureWV-17_CTF`
- **Note:** If your Docker setup requires root privileges, prepend `sudo` to the Docker commands; otherwise you can run them without `sudo`.

### Clone the repository

```bash
# 1. Clone the project (replace <your‑username> with the GitHub owner)
git clone https://github.com/bkarnes/SecureWV-17_CTF.git

# 2. Change into the project directory
cd SecureWV-17_CTF

# 3. Verify you have the expected contents
ls -l
```

After the repository is cloned and you are inside the project root, continue with the steps below for building and starting the Anomaly‑Machine containers.

### 1. Building and starting single machines:
Each Anomaly‑Machine directory ships a ready‑made `.env` file containing the required flag variables, which will be read at the time of the docker compose up.

#### 1.1 Build the docker containers (only need to run once per machine):
You will need to build the docker containers to ensure the flags are pulled into each docker image.  The docker containers will also build the first time you run a **docker compose up -d command**:
```bash
cd Anomaly_Machines/AM-01_lobby_terminal
sudo docker compose up -d --build
```

#### 1.2 Spin up the docker containers (after the build phase):
After the initial build phase, you can run each container by:
```bash
cd Anomaly_Machines/AM-01_lobby_terminal
sudo docker compose up -d
```

Repeat the `cd` step for any other machine you wish to start.

### 2. Stop a single machine:
You can stop each docker container by:
```bash
cd Anomaly_Machines/AM-01_lobby_terminal
sudo docker compose down
```

Repeat the `cd` step for any other machine you wish to stop.

### 3. Start all machines at once
```bash
sudo docker compose \
  -f Anomaly_Machines/AM-01_lobby_terminal/docker-compose.yml \
  -f Anomaly_Machines/AM-02_wellness/docker-compose.yml \
  -f Anomaly_Machines/AM-03_junction7/docker-compose.yml \
  -f Anomaly_Machines/AM-04_rd_annex/docker-compose.yml \
  -f Anomaly_Machines/AM-05_archive/docker-compose.yml \
  -f Anomaly_Machines/AM-06_quorum_alpha/docker-compose.yml \
  -f Anomaly_Machines/AM-KoTH_quorum_core/docker-compose.yml \
   up -d --build
```

### 4. Stop everything
```bash
sudo docker compose down   # from a single machine folder
# or, for the multi‑file launch:
docker compose \
  -f Anomaly_Machines/AM-01_lobby_terminal/docker-compose.yml \
  -f Anomaly_Machines/AM-02_wellness/docker-compose.yml \
  -f Anomaly_Machines/AM-03_junction7/docker-compose.yml \
  -f Anomaly_Machines/AM-04_rd_annex/docker-compose.yml \
  -f Anomaly_Machines/AM-05_archive/docker-compose.yml \
  -f Anomaly_Machines/AM-06_quorum_alpha/docker-compose.yml \
  -f Anomaly_Machines/AM-KoTH_quorum_core/docker-compose.yml \
  down
```

## Red Team Challenges
Each Anomaly‑Machine (AM) contains two primary flags: a *user* flag written to `user.txt` and a *root* flag written to `root.txt`. These flags are injected via the `.env` files in each AM directory and are used for scoring the red‑team exploit chain.



### Port‑map reference
| AM | Host ports | Service |
|----|------------|---------|
| AM‑01 | 80 (HTTP), 2222 (SSH) | Lobby terminal |
| AM‑02 | 21 (FTP), 2223 (SSH), 8080 (HTTP), 30000-30009 (PASV) | Wellness Observation |
| AM‑03 | 25 (SMTP), 80 (HTTP), 9001 (Status) | Network Junction |
| AM‑04 | 80 (HTTP), 2220 (SSH), 3000 (API) | R&D Annex |
| AM‑05 | 2225 (SSH), 8443 (HTTPS), 5672 (RabbitMQ) | The Archive |
| AM‑06 | 2226 (SSH), 31337 (QUORUM terminal) | QUORUM Subsystem Alpha |
| AM‑KoTH | 80 (HTTP), 2227 (SSH), 127.0.0.1:8081 (webhook) | QUORUM Core |

## Red Team Challenges

| ID | Name                                                   | Description                                           | CP  | Category   |
|----|--------------------------------------------------------|-------------------------------------------------------|-----|------------|
| 1  | AM‑01: The Lobby Terminal — User Flag                  | AM‑01: The Lobby Terminal — User Flag                | 100 | PROVISIONAL |
| 2  | AM‑01: The Lobby Terminal — Root Flag                  | AM‑01: The Lobby Terminal — Root Flag                | 200 | PROVISIONAL |
| 3  | AM‑02: Wellness Observation Center — User Flag        | AM‑02: Wellness Observation Center — User Flag        | 300 | PROVISIONAL |
| 4  | AM‑02: Wellness Observation Center — Root Flag        | AM‑02: Wellness Observation Center — Root Flag        | 400 | PROVISIONAL |
| 5  | AM‑03: Network Junction 7 — User Flag                 | AM‑03: Network Junction 7 — User Flag                 | 500 | AMBER |
| 6  | AM‑03: Network Junction 7 — Root Flag                 | AM‑03: Network Junction 7 — Root Flag                 | 600 | AMBER |
| 7  | AM‑03: Network Junction 7 — Internal User Flag        | AM‑03: Network Junction 7 — Internal User Flag        | 700 | AMBER |
| 8  | AM‑03: Network Junction 7 — Internal Root Flag        | AM‑03: Network Junction 7 — Internal Root Flag        | 800 | AMBER |
| 9  | AM‑04: R&D Annex (Provisional) — User Flag           | AM‑04: R&D Annex (Provisional) — User Flag           | 900 | TEAL |
| 10 | AM‑04: R&D Annex (Provisional) — Root Flag           | AM‑04: R&D Annex (Provisional) — Root Flag           | 1000| TEAL |
| 11 | AM‑05: The Archive — User Flag                         | AM‑05: The Archive — User Flag                         | 1500| CRIMSON |
| 12 | AM‑05: The Archive — Root Flag                         | AM‑05: The Archive — Root Flag                         | 2000| CRIMSON |
| 13 | AM‑06: QUORUM Subsystem Alpha — User Flag             | AM‑06: QUORUM Subsystem Alpha — User Flag             | 2500| IVORY |
| 14 | AM‑06: QUORUM Subsystem Alpha — Root Flag             | AM‑06: QUORUM Subsystem Alpha — Root Flag             | 3000| IVORY |

## Blue Team Challenges

| ID | Name | Description | CP | Category |
|----|------|-------------|----|----------|
| 15 | BT-01a | What IP address successfully authenticated after the brute-force attempts? | 25 | PROVISIONAL |
| 21 | BT-01b | What username was used to gain access? See previous artifacts. | 50 | PROVISIONAL |
| 22 | BT-01c | How many failed attempts preceded the successful login? | 75 | PROVISIONAL |
| 23 | BT-01d | What was the first command run after login? | 100 | PROVISIONAL |
| 24 | BT-02a | What type of attack is present in the logs? | 125 | PROVISIONAL |
| 25 | BT-02b | What parameter was targeted? | 150 | PROVISIONAL |
| 26 | BT-02c | What was the attacker's user-agent string? | 175 | PROVISIONAL |
| 28 | BT-02d | What data did the attacker successfully extract? | 200 | PROVISIONAL |
| 29 | BT-03a | What protocol is used for C2 communication? | 225 | AMBER |
| 30 | BT-03b | What is the C2 server's IP address? | 250 | AMBER |
| 31 | BT-03c | What command was issued by the C2 operator? | 275 | AMBER |
| 32 | BT-03d | What data was exfiltrated? (filename) | 300 | AMBER |
| 33 | BT-03e | What encoding was used to obfuscate the exfiltrated data? | 325 | AMBER |
| 34 | BT-04a | What persistence mechanism was installed? | 350 | AMBER |
| 35 | BT-04b | What is the full cron entry added by the attacker? | 375 | AMBER |
| 36 | BT-04c | What internal IP did the attacker pivot to? | 400 | AMBER |
| 37 | BT-05a | What Event ID indicates the initial logon? | 425 | TEAL |
| 38 | BT-05b | What process was used for lateral movement? | 450 | TEAL |
| 39 | BT-05c | What registry key was modified for persistence? | 475 | TEAL |
| 40 | BT-05d | What tool was used to dump credentials? | 500 | TEAL |
| 41 | BT-05e | At what time (UTC) did the attacker first access the Director's files? | 525 | TEAL |
| 42 | BT-06a | What vulnerability class was exploited for initial access? | 550 | TEAL |
| 43 | BT-06b | How many files were exfiltrated? | 575 | TEAL |
| 44 | BT-06c | What was the total size of exfiltrated data (bytes)? | 600 | TEAL |
| 45 | BT-06d | What IP received the exfiltrated data? | 625 | TEAL |
| 46 | BT-07a | What was the initial attack vector? | 650 | CRIMSON |
| 47 | BT-07b | What CVE was exploited? | 675 | CRIMSON |
| 48 | BT-07c | How did the attacker move from Linux to Windows? | 700 | CRIMSON |
| 49 | BT-07d | What document was accessed in the Archive? | 725 | CRIMSON |
| 50 | BT-07e | What was the attacker's final objective, based on the evidence? | 750 | CRIMSON |
| 51 | BT-08a | What encoding scheme is used in the outer layer? | 775 | IVORY |
| 52 | BT-08b | What is the decryption key? | 800 | IVORY |
| 53 | BT-08c | What is the content of the transmission? | 825 | IVORY |

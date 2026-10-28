# DIRECTIVE ZERO

A Dystopian future setting, hybrid CTF platform for cybersecurity classes, conferences, and expos.

**Theme:** Satirical dystopian surveillance Construct run by an all-knowing AI called QUORUM.  
**Format:** Hybrid Red Team (docker containers) + Blue Team (log analysis Jeopardy), unified scoring.  

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

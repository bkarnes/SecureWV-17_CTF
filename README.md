# DIRECTIVE ZERO

A Dystopian future setting, hybrid CTF platform for cybersecurity classes, conferences, and expos.

**Theme:** Satirical dystopian surveillance Construct run by an all-knowing AI called QUORUM.  
**Format:** Hybrid Red Team (boot-to-root) + Blue Team (log analysis Jeopardy), unified scoring.  
**Scales:** Classroom (1–2hr) → Conference (4–6hr) → Multi-day.

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

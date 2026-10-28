# DIRECTIVE ZERO — Blue Team Artifacts

Static log/PCAP artifacts for the Blue Team (Incident Reconstruction)
track. Each scenario is a mini-investigation where players download
artifact files, analyze them with standard tools (`grep`, `awk`,
`wireshark`, etc.), and answer questions about what happened.

Unlike the Anomaly Machines (live Docker containers players hack),
Blue Team scenarios are **static files** generated per event.

---

## Index of Scenarios

| Scenario | Tier | Artifact type | CP total | Status |
|----------|------|---------------|----------|--------|
| BT-01 — The Unauthorized Login | PROVISIONAL/AMBER | Linux auth.log + syslog | 350 | Built |
| BT-02 — Suspicious Portal Traffic | PROVISIONAL/AMBER | Web access.log | 375 | Built |
| BT-03 — The Junction Intercept | TEAL | Network PCAP | 750 | Built |
| BT-04 — Wellness Intake Log | TEAL | Linux auth.log + cron.log | 500 | Built |
| BT-05 — The Director's Workstation | CRIMSON | Windows Event XML export | 1000 | Built |
| BT-06 — The R&D Exfiltration | CRIMSON | PCAP + API access.log | 850 | Built |
| BT-07 — The Archive Incident | IVORY | Multi-source (PCAP + syslog + Windows XML) | 1500 | Built |
| BT-08 — Zero Directive Transmission | IVORY | Custom encoded artifact | 1050 | Built |

---

## Generating Artifacts

Artifacts must be freshly generated for each event — never reuse
between events (answers spread). The generator randomizes IPs,
usernames, counts, and other answer-bearing values per run.

```bash
cd Blue_Team
./generate_artifacts.sh                    # random seed
./generate_artifacts.sh --seed 42          # reproducible
```

Each BT scenario's `generate.py` produces:
- Artifact file(s) in `./artifacts/` (the files players download from CTFd)
- Answer entries merged into `../Anomaly_Machines/event_flags.json` (consumed by `scoring_engine/import_challenges.py`)

---

## Testing Artifacts

The test runner validates that answers are actually findable in the
generated artifacts — it greps the logs and asserts the expected values
match the answer key.

```bash
# Build the BT test runner:
cd Blue_Team/_test_runner
docker build -t dz-bt-test-runner .

# Run against BT-01:
cd Blue_Team
./generate_artifacts.sh --seed 42
docker run --rm -v "$(pwd):/bt:ro" dz-bt-test-runner bt-01 /bt/BT-01_unauthorized_login/artifacts /bt/BT-01_unauthorized_login/answers.json
```

---

## Answer Format

All answers are submitted as `DZ{answer}`. See `../BLUE_TEAM_RUBRIC.md`
for the full formatting rules. Summary:

| Answer type | Format | Example |
|-------------|--------|---------|
| IP address | Dotted decimal | `DZ{10.10.4.22}` |
| Integer | Digits only, no commas | `DZ{27}` |
| Timestamp | UTC, YYYY-MM-DDTHH:MM:SS | `DZ{2026-08-22T14:32:11}` |
| String | Lowercase, underscores for spaces | `DZ{compliance}` |
| CVE ID | Full format | `DZ{CVE-2021-44228}` |
| Filename | Name only, no path | `DZ{shadow}` |

---

## Per-Scenario Directory Layout

```
BT-NN_<name>/
├── README.md          ← Director-only: answer key + generation instructions
├── PLAYER_BRIEF.md    ← QUORUM-flavored challenge text for CTFd
├── generate.py        ← Python: generates artifact(s) + answers
├── artifacts/         ← gitignored; generated per event
│   └── btNN_*.log
├── answers.json       ← gitignored; generated per event
└── tests/
    └── test_bt-NN.sh  ← validates answers are findable in the artifact
```

---

*QUORUM reminds all Compliance Officers that incident reconstruction
is a form of care. Your analysis has been noted. Your analysis of
incidents that QUORUM has determined did not occur has also been noted.*
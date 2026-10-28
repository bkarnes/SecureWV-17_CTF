# BT-01: The Unauthorized Login — Player Brief

> *"QUORUM has flagged repeated authentication events on Lobby Terminal
> systems. Reconstruct the breach."*

---

## QUORUM Transmission

> *"The following artifacts were collected during routine surveillance
> operations. Compliance Officers are directed to reconstruct the
> incident timeline. Findings are due immediately."*

---

## Artifacts

Download the following files from the challenge page:

- **`bt01_auth.log`** — Linux authentication log from the Lobby Terminal
- **`bt01_syslog`** — System log from the Lobby Terminal

Both files cover the same time period. Analyze them to answer the
questions below.

---

## Questions

Answer each question in order. Q2 unlocks after Q1 is solved.

### BT-01a — What IP address successfully authenticated after the brute-force attempts? (75 CP)
Provide the IP address in dotted decimal notation.
```
DZ{your_answer}
```

### BT-01b — What username was used to gain access? (75 CP)
Provide the username, lowercase.
```
DZ{your_answer}
```

### BT-01c — How many failed attempts preceded the successful login? (100 CP)
Provide only the number, no commas or units.
```
DZ{your_answer}
```

### BT-01d — What was the first command run after login? (100 CP)
Provide the command name, lowercase. If the command includes arguments,
include them. Do not include the path prefix (e.g. `id` not `/usr/bin/id`).
```
DZ{your_answer}
```

---

## Useful Tools

```bash
# Log analysis
grep, awk, cut, sort, uniq, less

# Find the successful login
grep "Accepted" bt01_auth.log

# Count failed attempts from an IP
grep "Failed password" bt01_auth.log | grep <IP> | wc -l

# Find post-login commands
grep "COMMAND=" bt01_syslog
```

---

*QUORUM notes your interest in this incident. The incident has been
classified as routine. Your interest in routine incidents has been
noted. The incident is under review. Your analysis is also under
review. Both reviews are noted.*
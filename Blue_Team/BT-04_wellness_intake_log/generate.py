#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-04 "Wellness Intake Log" artifact generator.

Generates synthetic WOC (Wellness Observation Center) auth.log and
cron.log that tell the story of an attacker logging in out-of-hours
to a compromised service account, installing a crontab beacon for
persistence, then pivoting via SSH to an internal host. The artifact
is randomized per run so answers don't spread between events.

Output files (in --out-dir, default ./artifacts):
  - woc_auth.log — Debian auth.log (~400 lines)
  - cron.log     — Debian cron.log (~150 lines)
  - answers.json — answer key in DZ{...} format

The answers are also merged into the event_flags.json file (if
--flags-file is specified) so import_challenges.py can load them.

Usage:
  python3 generate.py                          # random seed
  python3 generate.py --seed 42                # reproducible
  python3 generate.py --out-dir ./artifacts    # custom output dir
  python3 generate.py --flags-file ../../Anomaly_Machines/event_flags.json
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta

# ── Pools for randomization ────────────────────────────────────────────────

# WOC service accounts — the compromised account is randomized from these
SERVICE_ACCOUNTS = ["woc-observer", "woc-intake", "woc-clinic", "wellness-op"]

# Other WOC staff (cover traffic logins)
WOC_STAFF = ["clinician1", "clinician2", "nurse-a", "nurse-b",
             "admin-liason", "intake-coord", "records-clerk"]

# Recon commands the attacker runs via sudo before installing persistence
RECON_COMMANDS = [
    "/usr/bin/find / -perm -4000 -type f 2>/dev/null",
    "/bin/cat /etc/crontab",
    "/usr/bin/crontab -l",
    "/bin/ls -la /etc/cron.d/",
    "/usr/bin/cat /etc/passwd",
    "/bin/netstat -tulpn",
]

# Cron schedules for the beacon entry (BT-04b content)
CRON_SCHEDULES = [
    "*/15 * * * *",
    "*/30 * * * *",
    "0 * * * *",
    "*/10 * * * *",
    "*/5 * * * *",
]

# Beacon URL path component
BEACON_PATHS = ["/beacon", "/checkin", "/ping", "/update", "/status"]

# Beacon tool (curl or wget)
BEACON_TOOLS = ["curl -s", "wget -q -O-"]

# Cover-traffic cron jobs (system-style, so the attacker entry stands out)
COVER_CRON_JOBS = [
    "/usr/lib/php/sessionclean",
    "/usr/sbin/logrotate /etc/logrotate.conf",
    "/etc/cron.daily/apt-compat",
    "/usr/local/bin/woc-health-check.sh",
    "/usr/local/bin/routing_updater.sh",
    "/etc/cron.hourly/woc-sync",
]

# Internal Construct IPs (cover traffic)
COVER_IPS = ["10.10.3.11", "10.10.3.12", "10.10.3.15", "10.10.3.20",
             "10.10.5.7", "10.10.5.18", "10.10.7.3", "10.10.7.9"]

HOSTNAME = "woc-terminal"

# ── Log line generators ────────────────────────────────────────────────────

def fmt_ts(dt):
    """Format a datetime as syslog timestamp: 'Aug 22 02:03:17'"""
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")

def gen_pid(rng):
    return rng.randint(1000, 9999)

def gen_port(rng):
    return rng.randint(49152, 65535)

def sshd_connection_from(ts, pid, ip, port):
    return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Connection from {ip} port {port}"

def sshd_failed_login(ts, pid, port, username, ip, invalid=False):
    if invalid:
        return (f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Failed password for "
                f"invalid user {username} from {ip} port {port} ssh2")
    return (f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Failed password for "
            f"{username} from {ip} port {port} ssh2")

def sshd_accepted_login(ts, pid, port, username, ip):
    return (f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Accepted password for "
            f"{username} from {ip} port {port} ssh2")

def sshd_session_opened(ts, pid, username):
    return (f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: pam_unix(sshd:session): "
            f"session opened for user {username} by (uid=0)")

def sshd_session_closed(ts, pid, username):
    return (f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: pam_unix(sshd:session): "
            f"session closed for user {username}")

def sudo_command(ts, user, command, cwd="/home"):
    """Generate a sudo command log line."""
    return (f"{fmt_ts(ts)} {HOSTNAME} sudo:  {user} : "
            f"TTY=pts/0 ; PWD={cwd} ; USER=root ; COMMAND={command}")

def cron_line(ts, user, cmd):
    return f"{fmt_ts(ts)} {HOSTNAME} CRON[{gen_pid(rng_global)}]: (root) CMD ({cmd})"

def cron_session_open(ts, pid, user):
    return (f"{fmt_ts(ts)} {HOSTNAME} CRON[{pid}]: "
            f"pam_unix(cron:session): session opened for user {user} by (uid=0)")

def cron_session_close(ts, pid, user):
    return (f"{fmt_ts(ts)} {HOSTNAME} CRON[{pid}]: "
            f"pam_unix(cron:session): session closed for user {user}")

def systemd_line(ts, msg):
    return f"{fmt_ts(ts)} {HOSTNAME} systemd[1]: {msg}"

# ── Cover traffic generators ───────────────────────────────────────────────

rng_global = random.Random()

def gen_cover_auth_log(rng, start_time, count=300, exclude_user=None):
    """Generate cover traffic for auth.log — legitimate WOC activity."""
    exclude = exclude_user or ""
    lines = []
    t = start_time
    for _ in range(count):
        r = rng.random()
        if r < 0.30:
            # Cron session
            user = rng.choice(["root", "www-data"])
            pid = gen_pid(rng)
            lines.append(cron_session_open(t, pid, user))
            t += timedelta(seconds=rng.randint(1, 30))
            lines.append(cron_session_close(t, pid, user))
        elif r < 0.50:
            # Legitimate staff SSH login from internal IP
            ip = rng.choice(COVER_IPS)
            port = gen_port(rng)
            pid = gen_pid(rng)
            user = rng.choice([u for u in WOC_STAFF if u != exclude])
            lines.append(sshd_connection_from(t, pid, ip, port))
            t += timedelta(seconds=rng.randint(1, 5))
            lines.append(sshd_accepted_login(t, pid, port, user, ip))
            t += timedelta(seconds=rng.randint(1, 10))
            lines.append(sshd_session_opened(t, pid, user))
            t += timedelta(seconds=rng.randint(60, 1800))
            lines.append(sshd_session_closed(t, pid, user))
        elif r < 0.60:
            # Failed login from internal IP (typos)
            ip = rng.choice(COVER_IPS)
            port = gen_port(rng)
            pid = gen_pid(rng)
            user = rng.choice(WOC_STAFF)
            lines.append(sshd_failed_login(t, pid, port, user, ip))
            t += timedelta(seconds=rng.randint(1, 30))
        elif r < 0.70:
            # Scanner noise — invalid users from internal IPs
            ip = rng.choice(COVER_IPS)
            port = gen_port(rng)
            pid = gen_pid(rng)
            user = rng.choice(["root", "admin", "test", "guest", "ubuntu"])
            lines.append(sshd_failed_login(t, pid, port, user, ip, invalid=True))
            t += timedelta(seconds=rng.randint(1, 20))
        elif r < 0.85:
            # Legit sudo from WOC staff (exclude the compromised account)
            users = [u for u in WOC_STAFF if u != exclude]
            user = rng.choice(users)
            cmd = rng.choice(["/usr/bin/apt update", "/bin/systemctl status ssh",
                             "/usr/bin/journalctl --since today",
                             "/usr/bin/tail -f /var/log/auth.log",
                             "/bin/systemctl restart cron"])
            lines.append(sudo_command(t, user, cmd, f"/home/{user}"))
            t += timedelta(seconds=rng.randint(1, 60))
        else:
            # System events
            msg = rng.choice([
                "Starting Daily apt download activities...",
                "Finished Daily apt download activities.",
                "Starting Cleanup of Temporary Directories...",
                "pam_unix(sudo:session): session opened for user root by (uid=0)",
                "pam_unix(sudo:session): session closed for user root",
            ])
            lines.append(f"{fmt_ts(t)} {HOSTNAME} {msg}")
            t += timedelta(seconds=rng.randint(1, 45))
    return lines, t

def gen_cover_cron_log(rng, start_time, count=120):
    """Generate cover traffic for cron.log — routine system cron jobs."""
    lines = []
    t = start_time
    for _ in range(count):
        r = rng.random()
        if r < 0.70:
            # Routine cron job execution
            cmd = rng.choice(COVER_CRON_JOBS)
            lines.append(cron_line(t, "root", cmd))
            t += timedelta(seconds=rng.randint(1, 60))
        elif r < 0.85:
            # Cron session open/close
            user = rng.choice(["root", "www-data", "ntp"])
            pid = gen_pid(rng)
            lines.append(cron_session_open(t, pid, user))
            t += timedelta(seconds=rng.randint(1, 30))
            lines.append(cron_session_close(t, pid, user))
        else:
            # System cron messages
            msg = rng.choice([
                "modprobe: FATAL: Module cpufreq not found",
                "CRON[1]: (root) MAILTO set to root",
                "(root) CMD (/usr/local/bin/woc-backup.sh)",
            ])
            lines.append(f"{fmt_ts(t)} {HOSTNAME} {msg}")
            t += timedelta(seconds=rng.randint(1, 90))
    return lines, t

# ── Attack sequence generators ─────────────────────────────────────────────

def gen_attack_auth_log(rng, start_time, attacker_ip, service_account,
                        recon_command, pivot_ip):
    """Generate the auth.log attack sequence:
       login -> recon sudo -> ssh pivot (sudo) -> logout.
    """
    lines = []
    t = start_time
    pid = rng.randint(2000, 2999)
    port = gen_port(rng)

    # Out-of-hours login from external IP
    lines.append(sshd_connection_from(t, pid, attacker_ip, port))
    t += timedelta(seconds=rng.randint(1, 3))
    lines.append(sshd_accepted_login(t, pid, port, service_account, attacker_ip))
    t += timedelta(seconds=1)
    lines.append(sshd_session_opened(t, pid, service_account))

    # Recon via sudo
    t += timedelta(seconds=rng.randint(2, 10))
    lines.append(sudo_command(t, service_account, recon_command,
                              f"/home/{service_account}"))

    # Pivot via sudo ssh
    t += timedelta(seconds=rng.randint(5, 30))
    lines.append(sudo_command(t, service_account,
                              f"/usr/bin/ssh {pivot_ip}",
                              f"/home/{service_account}"))

    # Session close
    t += timedelta(seconds=rng.randint(60, 600))
    lines.append(sshd_session_closed(t, pid, service_account))
    return lines, t

def gen_attack_cron_log(rng, start_time, service_account, cron_schedule,
                        beacon_ip, beacon_path, beacon_tool):
    """Generate the cron.log attack sequence: crontab install marker +
       the beacon entry executing.
    """
    lines = []
    t = start_time

    # Marker: crontab install event (the attacker ran `crontab -e` /
    # installed a user crontab). Logged by the cron subsystem.
    pid = rng.randint(3000, 3999)
    lines.append(cron_session_open(t, pid, service_account))
    t += timedelta(seconds=rng.randint(1, 3))
    # The install line — this is the tell-tale "user crontab installed"
    lines.append(
        f"{fmt_ts(t)} {HOSTNAME} crontab[{pid}]: "
        f"(user {service_account}) BEGIN EDIT (/var/spool/cron/crontabs/{service_account})"
    )
    t += timedelta(seconds=rng.randint(1, 2))
    lines.append(
        f"{fmt_ts(t)} {HOSTNAME} crontab[{pid}]: "
        f"(user {service_account}) END EDIT (/var/spool/cron/crontabs/{service_account})"
    )
    t += timedelta(seconds=rng.randint(1, 5))
    lines.append(cron_session_close(t, pid, service_account))

    # The beacon entry executing — this is the BT-04b answer.
    # Format: "(root) CMD (<cron_schedule> <user> <tool> http://<ip><path>)"
    # Actually, cron logs the CMD field of the crontab line, so the entry
    # in cron.log is the command portion. We log the full schedule + cmd
    # so players can reconstruct the crontab line.
    beacon_cmd = f"{beacon_tool} http://{beacon_ip}{beacon_path}"
    # The cron daemon logs: (user) CMD (command)
    lines.append(
        f"{fmt_ts(t)} {HOSTNAME} CRON[{gen_pid(rng)}]: "
        f"({service_account}) CMD ({beacon_cmd})"
    )
    # Also log the crontab line itself (some systems log the parsed entry)
    cron_entry = f"{cron_schedule} {service_account} {beacon_cmd}"
    lines.append(
        f"{fmt_ts(t)} {HOSTNAME} crontab[{pid}]: "
        f"installed crontab for {service_account}: {cron_entry}"
    )
    return lines, t, cron_entry

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    global rng_global
    parser = argparse.ArgumentParser(description="BT-04 artifact generator")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--out-dir", default="./artifacts",
                        help="Output directory")
    parser.add_argument("--flags-file", default=None,
                        help="Path to event_flags.json to merge answers into")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    rng_global = rng  # for cron_line() helper

    # Randomize the key parameters
    attacker_ip = f"10.10.{rng.randint(4, 8)}.{rng.randint(2, 254)}"
    service_account = rng.choice(SERVICE_ACCOUNTS)
    recon_command = rng.choice(RECON_COMMANDS)
    cron_schedule = rng.choice(CRON_SCHEDULES)
    beacon_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    # Ensure beacon_ip != attacker_ip
    while beacon_ip == attacker_ip:
        beacon_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    beacon_path = rng.choice(BEACON_PATHS)
    beacon_tool = rng.choice(BEACON_TOOLS)
    pivot_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    # Ensure pivot_ip distinct
    while pivot_ip == attacker_ip or pivot_ip == beacon_ip:
        pivot_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"

    # Event date: random day in the last 30 days
    base_date = datetime(2026, 8, 1) + timedelta(days=rng.randint(0, 30))
    start_time = base_date.replace(hour=rng.randint(0, 23),
                                    minute=rng.randint(0, 59),
                                    second=rng.randint(0, 59),
                                    microsecond=0)

    # Attack starts ~2-4 hours into the log
    attack_start = start_time + timedelta(hours=rng.randint(1, 4))

    # Build the full cron entry string (BT-04b answer)
    beacon_cmd = f"{beacon_tool} http://{beacon_ip}{beacon_path}"
    full_cron_entry = f"{cron_schedule} {service_account} {beacon_cmd}"

    # Generate cover traffic
    cover_auth, _ = gen_cover_auth_log(rng, start_time, count=300,
                                       exclude_user=service_account)
    cover_cron, _ = gen_cover_cron_log(rng, start_time, count=120)

    # Generate attack sequences
    attack_auth, _ = gen_attack_auth_log(
        rng, attack_start, attacker_ip, service_account,
        recon_command, pivot_ip
    )
    # cron attack starts a bit after the auth log attack
    cron_attack_start = attack_start + timedelta(minutes=rng.randint(2, 15))
    attack_cron, _, _ = gen_attack_cron_log(
        rng, cron_attack_start, service_account, cron_schedule,
        beacon_ip, beacon_path, beacon_tool
    )

    # Merge and sort by timestamp
    auth_lines = cover_auth + attack_auth
    cron_lines = cover_cron + attack_cron
    auth_lines.sort(key=lambda l: l[:15] if len(l) > 15 else l)
    cron_lines.sort(key=lambda l: l[:15] if len(l) > 15 else l)

    # Write artifacts
    os.makedirs(args.out_dir, exist_ok=True)
    auth_path = os.path.join(args.out_dir, "woc_auth.log")
    cron_path = os.path.join(args.out_dir, "cron.log")
    with open(auth_path, "w") as f:
        f.write("\n".join(auth_lines) + "\n")
    with open(cron_path, "w") as f:
        f.write("\n".join(cron_lines) + "\n")

    # Build the answer key
    answers = {
        "BT-04a: What persistence mechanism was installed?":
            "DZ{crontab}",
        "BT-04b: What is the full cron entry added by the attacker?":
            f"DZ{{{full_cron_entry}}}",
        "BT-04c: What internal IP did the attacker pivot to?":
            f"DZ{{{pivot_ip}}}",
    }

    # Write answers.json (sibling to out-dir)
    answers_path = os.path.join(os.path.dirname(args.out_dir), "answers.json")
    with open(answers_path, "w") as f:
        json.dump(answers, f, indent=2)
    print(f"[generate] answers written to {answers_path}")

    # Merge into event_flags.json if specified
    if args.flags_file and os.path.exists(os.path.dirname(args.flags_file) or "."):
        flags = {}
        if os.path.exists(args.flags_file):
            with open(args.flags_file, "r") as f:
                flags = json.load(f)
        flags.update(answers)
        with open(args.flags_file, "w") as f:
            json.dump(flags, f, indent=2)
        print(f"[generate] answers merged into {args.flags_file}")

    # Print summary
    print(f"[generate] BT-04 artifacts generated:")
    print(f"  attacker_ip:      {attacker_ip}")
    print(f"  service_account:  {service_account}")
    print(f"  recon_command:    {recon_command}")
    print(f"  cron_schedule:    {cron_schedule}")
    print(f"  beacon_ip:        {beacon_ip}")
    print(f"  beacon_path:      {beacon_path}")
    print(f"  beacon_tool:      {beacon_tool}")
    print(f"  pivot_ip:         {pivot_ip}")
    print(f"  full_cron_entry:  {full_cron_entry}")
    print(f"  auth.log:         {auth_path} ({len(auth_lines)} lines)")
    print(f"  cron.log:         {cron_path} ({len(cron_lines)} lines)")
    print(f"  answers:          {answers_path}")

if __name__ == "__main__":
    main()
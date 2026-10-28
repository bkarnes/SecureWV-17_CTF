#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-02 "Suspicious Portal Traffic" artifact generator.

Generates a synthetic Nginx combined-format access.log that tells the
story of a UNION-based SQL injection attack against the QUORUM
enrollment portal. The artifact is randomized per run so answers
don't spread between events.

Output files (in --out-dir, default ./artifacts):
  - bt02_access.log — Nginx combined access.log (~300 lines)
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

# The QUORUM enrollment portal endpoint and the vulnerable parameter
# are randomized per run from these pools.
ENDPOINT = "/enroll"
TARGET_PARAMS = ["enrollment_id", "applicant_id", "record_id", "user_id"]

# Tables the attacker exfiltrates from. The randomized pick becomes the
# BT-02d answer ("what data did the attacker successfully extract?").
TARGET_TABLES = [
    "quorum_enrollment",
    "citizen_registry",
    "enrollment_records",
    "portal_users",
]

# Distinctive scanner user-agents. The randomized pick becomes the
# BT-02c answer. sqlmap is pedagogically obvious — good for AMBER tier.
ATTACKER_UAS = [
    "sqlmap/1.7.8#stable (http://sqlmap.org)",
    "sqlmap/1.7.11#stable (http://sqlmap.org)",
    "sqlmap/1.8.2#stable (http://sqlmap.org)",
]

# Columns used in the final UNION SELECT (flavor only; not an answer).
EXFIL_COLUMNS = [
    ("id", "username", "password_hash", "email"),
    ("uid", "name", "password", "email"),
    ("id", "login", "pass_hash", "mail"),
]

# Cover-traffic user-agents (realistic browsers)
COVER_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

# Internal Construct IPs that generate legitimate portal browsing
COVER_IPS = ["10.10.3.11", "10.10.3.12", "10.10.3.15", "10.10.3.20",
             "10.10.5.7", "10.10.5.18", "10.10.7.3", "10.10.7.9"]

# Legitimate portal paths and their typical status codes / sizes
COVER_PATHS = [
    ("/", 200, 2048),
    ("/login", 200, 1024),
    ("/about", 200, 1536),
    ("/contact", 200, 768),
    ("/enroll", 200, 1280),
    ("/static/style.css", 200, 4096),
    ("/static/main.js", 200, 8192),
    ("/favicon.ico", 404, 0),
    ("/robots.txt", 200, 64),
]

HOSTNAME = "portal"

# ── Log line generators ────────────────────────────────────────────────────

def fmt_ts(dt):
    """Format a datetime as Nginx log timestamp: '22/Aug/2026:02:03:17 +0000'"""
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def gen_cover_line(rng, dt, ip, ua, path, status, size, referer="-"):
    """Generate a Nginx combined log line."""
    return (f'{ip} - - [{fmt_ts(dt)}] "{path}" {status} {size} '
            f'"{referer}" "{ua}"')

def gen_attack_line(rng, dt, ip, ua, method, path, status, size, referer="-"):
    """Generate an attack log line with a method (GET/POST)."""
    full_path = f"{method} {path} HTTP/1.1"
    return (f'{ip} - - [{fmt_ts(dt)}] "{full_path}" {status} {size} '
            f'"{referer}" "{ua}"')

# ── Cover traffic generator ───────────────────────────────────────────────

def gen_cover_traffic(rng, start_time, count=250, target_param=None,
                      target_table=None):
    """Generate legitimate portal browsing traffic.

    A few cover lines hit /enroll?<param>=<int> with sane integer values
    so the attack lines aren't the ONLY requests to that endpoint.
    """
    lines = []
    t = start_time
    for _ in range(count):
        ip = rng.choice(COVER_IPS)
        ua = rng.choice(COVER_UAS)
        r = rng.random()
        if r < 0.20 and target_param is not None:
            # A legitimate /enroll?<param>=<int> request
            val = rng.randint(1000, 9999)
            path = f"{ENDPOINT}?{target_param}={val}"
            status = 200
            size = rng.randint(800, 1600)
            referer = f"http://{HOSTNAME}/enroll"
        elif r < 0.70:
            path, status, base_size = rng.choice(COVER_PATHS)
            size = base_size + rng.randint(-128, 128)
            if size < 0:
                size = 0
            referer = f"http://{HOSTNAME}/" if rng.random() < 0.3 else "-"
        else:
            # Random 404s (probing noise, but from internal IPs)
            path = rng.choice(["/admin", "/wp-admin", "/.env",
                               "/config.php", "/api/v1/users"])
            status = 404
            size = 0
            referer = "-"
        lines.append(gen_cover_line(rng, t, ip, ua, path, status, size, referer))
        t += timedelta(seconds=rng.randint(1, 20))
    return lines, t

# ── Attack sequence generator ──────────────────────────────────────────────

def gen_attack_traffic(rng, start_time, attacker_ip, attacker_ua,
                       target_param, target_table):
    """Generate the SQLi attack sequence.

    Phases:
      1. Recon — error-based probes (single quotes, comments) → 500
      2. UNION fingerprinting — UNION SELECT 1,2,3.. → 200
      3. Exfiltration — UNION SELECT <cols> FROM <table> → 200, large bytes
    """
    lines = []
    t = start_time
    columns = rng.choice(EXFIL_COLUMNS)

    # Phase 1: error-based recon (~8 lines)
    recon_payloads = [
        f"{ENDPOINT}?{target_param}=1'",
        f"{ENDPOINT}?{target_param}=1'--",
        f"{ENDPOINT}?{target_param}=1' OR '1'='1",
        f"{ENDPOINT}?{target_param}=1' AND '1'='2",
        f"{ENDPOINT}?{target_param}=1' ORDER BY 1--",
        f"{ENDPOINT}?{target_param}=1' ORDER BY 4--",
        f"{ENDPOINT}?{target_param}=1' ORDER BY 5--",
        f"{ENDPOINT}?{target_param}=-1' UNION SELECT 1,2,3,4--",
    ]
    for payload in recon_payloads:
        # Recon probes mostly return 500 (SQL error) or 200 (silent fail)
        status = 500 if rng.random() < 0.7 else 200
        size = rng.randint(64, 512) if status == 500 else rng.randint(800, 1400)
        lines.append(gen_attack_line(rng, t, attacker_ip, attacker_ua,
                                     "GET", payload, status, size))
        t += timedelta(seconds=rng.randint(2, 15))

    # Phase 2: UNION fingerprinting (~6 lines, 200s)
    fingerprint_payloads = [
        f"{ENDPOINT}?{target_param}=-1 UNION SELECT 1,2,3,4--",
        f"{ENDPOINT}?{target_param}=-1 UNION SELECT 1,2,3,4-- -",
        f"{ENDPOINT}?{target_param}=-1' UNION SELECT 1,2,3,4-- -",
        f"{ENDPOINT}?{target_param}=-1 UNION ALL SELECT 1,2,3,4--",
        f"{ENDPOINT}?{target_param}=-1 UNION SELECT NULL,NULL,NULL,NULL--",
        f"{ENDPOINT}?{target_param}=-1 UNION SELECT 1,2,3,4,5--",
    ]
    for payload in fingerprint_payloads:
        status = 200
        size = rng.randint(900, 1500)
        lines.append(gen_attack_line(rng, t, attacker_ip, attacker_ua,
                                     "GET", payload, status, size))
        t += timedelta(seconds=rng.randint(2, 10))

    # Phase 3: exfiltration — the key line(s) that answer BT-02d
    cols_str = ",".join(columns)
    exfil_payloads = [
        f"{ENDPOINT}?{target_param}=-1 UNION SELECT {cols_str} FROM {target_table}--",
        f"{ENDPOINT}?{target_param}=-1 UNION SELECT {cols_str} FROM {target_table} WHERE 1=1--",
        f"{ENDPOINT}?{target_param}=-1 UNION SELECT {cols_str} FROM {target_table} LIMIT 1--",
    ]
    for i, payload in enumerate(exfil_payloads):
        status = 200
        # Final exfil returns a large response (dumped rows)
        size = rng.randint(8192, 16384) if i == 0 else rng.randint(2048, 4096)
        lines.append(gen_attack_line(rng, t, attacker_ip, attacker_ua,
                                     "GET", payload, status, size))
        t += timedelta(seconds=rng.randint(3, 12))

    return lines, t

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BT-02 artifact generator")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--out-dir", default="./artifacts",
                        help="Output directory")
    parser.add_argument("--flags-file", default=None,
                        help="Path to event_flags.json to merge answers into")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # Randomize the key parameters
    attacker_ip = f"10.10.{rng.randint(4, 8)}.{rng.randint(2, 254)}"
    attacker_ua = rng.choice(ATTACKER_UAS)
    target_param = rng.choice(TARGET_PARAMS)
    target_table = rng.choice(TARGET_TABLES)

    # Event date: random day in the last 30 days
    base_date = datetime(2026, 8, 1) + timedelta(days=rng.randint(0, 30))
    start_time = base_date.replace(hour=rng.randint(0, 23),
                                   minute=rng.randint(0, 59),
                                   second=rng.randint(0, 59),
                                   microsecond=0)

    # Attack starts ~2-4 hours into the log
    attack_start = start_time + timedelta(hours=rng.randint(1, 4))

    # Generate cover traffic (attack inserted after, then sorted by ts)
    cover_lines, cover_end_time = gen_cover_traffic(
        rng, start_time, count=250, target_param=target_param,
        target_table=target_table)

    # Generate attack traffic
    attack_lines, attack_end_time = gen_attack_traffic(
        rng, attack_start, attacker_ip, attacker_ua,
        target_param, target_table)

    # Merge and sort by timestamp (field within [..])
    all_lines = cover_lines + attack_lines
    all_lines.sort(key=lambda line: line.split("]")[0][1:] if "[" in line else line)

    # Write artifacts
    os.makedirs(args.out_dir, exist_ok=True)
    access_path = os.path.join(args.out_dir, "bt02_access.log")
    with open(access_path, "w") as f:
        f.write("\n".join(all_lines) + "\n")

    # Build the answer key — keys must match import_challenges.py output:
    #   f"{q['qid']}: {q['question']}"
    answers = {
        "BT-02a: What type of attack is present in the logs?":
            "DZ{SQL injection}",
        "BT-02b: What parameter was targeted?":
            f"DZ{{{target_param}}}",
        "BT-02c: What was the attacker's user-agent string?":
            f"DZ{{{attacker_ua}}}",
        "BT-02d: What data did the attacker successfully extract?":
            f"DZ{{{target_table}}}",
    }

    # Write answers.json (sibling to out-dir, matching BT-01 convention)
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
    print(f"[generate] BT-02 artifacts generated:")
    print(f"  attacker_ip:    {attacker_ip}")
    print(f"  attacker_ua:    {attacker_ua}")
    print(f"  target_param:   {target_param}")
    print(f"  target_table:   {target_table}")
    print(f"  access.log:     {access_path} ({len(all_lines)} lines)")
    print(f"  answers:        {answers_path}")

if __name__ == "__main__":
    main()
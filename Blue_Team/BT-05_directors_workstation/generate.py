#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-05 "The Director's Workstation" artifact generator.

Generates sanitized Windows Event XML exports for the Director's
workstation: a Security log and a System log. The Security log
contains six anomalous events (off-hours logon, lateral movement,
registry persistence, credential theft, file access, logoff)
embedded among ~150 cover events of normal Windows activity. The
System log contains routine service lifecycle events for cover.

Artifacts are randomized per run so answers don't spread between
events. The XML format matches what `wevtutil qn`/EvtxECmd exports
produce, so players analyze with xmllint/grep.

Output files (in --out-dir, default ./artifacts):
  - Security_events.xml — Windows Security event log export
  - System_events.xml   — Windows System event log export
  - answers.json        — answer key in DZ{...} format

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
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

# ── Pools for randomization ────────────────────────────────────────────────

# The compromised executive account
DIRECTOR_ACCOUNTS = ["director", "exec-dir", "ceo", "coo", "cso"]

# Lateral movement tools (BT-05b answer)
LATERAL_TOOLS = ["PsExec64.exe", "wmic.exe", "powershell.exe", "wsmprovhost.exe"]

# Credential dump tools (BT-05d answer)
CRED_TOOLS = ["mimikatz.exe", "procdump.exe", "sekurlsa.exe"]

# Registry persistence locations (BT-05c answer)
REG_BASE_PATHS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SYSTEM\\CurrentVersion\\Control\\Session Manager",
]
REG_VALUE_NAMES = ["UpdateCheck", "OneDriveSync", "TelemetrySvc",
                   "HealthMonitor", "WMIConfig", "DefenderUpdate"]

# Director files (BT-05e references this in the file-access event)
DIRECTOR_FILES = ["directives.docx", "manifest.xlsx", "charter.pdf",
                   "roster.csv", "succession.pdf"]

# Internal Construct IPs (cover traffic)
COVER_IPS = ["10.10.3.11", "10.10.3.12", "10.10.3.15", "10.10.3.20",
             "10.10.5.7", "10.10.5.18", "10.10.7.3", "10.10.7.9"]
COVER_STAFF = ["jdoe", "asmith", "bwilliams", "ltaylor", "mchen",
               "drossi", "ekim", "fpatel"]

# Benign processes for cover 4688 events
COVER_PROCESSES = ["chrome.exe", "explorer.exe", "outlook.exe", "winword.exe",
                   "excel.exe", "teams.exe", "onedrive.exe", "sihost.exe",
                   "taskhostw.exe", "SearchFilterHost.exe"]

# Benign registry paths for cover 4657 events
COVER_REG_PATHS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\General",
    "HKLM\\SYSTEM\\CurrentVersion\\Services\\Tcpip\\Parameters",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
]

# Windows provider names + GUIDs for the events we emit
PROVIDERS = {
    "Security": ("Microsoft-Windows-Security-Auditing",
                 "{54849625-5478-4994-A5BA-3E3B0328C30D}"),
    "System": ("Service Control Manager", "{555908d1-a6d7-4695-8e1e-f9c2f87a4c66}"),
    "Kernel": ("Microsoft-Windows-Kernel-General", "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F0D}"),
}

# ── Event XML builder ─────────────────────────────────────────────────────

# We build the XML using ElementTree so structure and escaping are
# guaranteed well-formed. The output matches the canonical Windows
# Event XML shape that wevtutil/EvtxECmd exports.

def make_event(event_id, system_time, provider_name, provider_guid,
               channel, computer, level="Information", task=None,
               event_data=None):
    """Build a single Windows Event XML element.

    event_data: list of (name, value) tuples -> <Data Name="...">value</Data>
    """
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    ET.register_namespace("", ns)
    event = ET.Element("{%s}Event" % ns)

    sys = ET.SubElement(event, "{%s}System" % ns)
    ET.SubElement(sys, "{%s}Provider" % ns, Name=provider_name,
                 Guid=provider_guid)
    ET.SubElement(sys, "{%s}EventID" % ns).text = str(event_id)
    ET.SubElement(sys, "{%s}Version" % ns).text = "0"
    ET.SubElement(sys, "{%s}Level" % ns).text = "0"
    ET.SubElement(sys, "{%s}Task" % ns).text = str(task or 0)
    ET.SubElement(sys, "{%s}Channel" % ns).text = channel
    ET.SubElement(sys, "{%s}Computer" % ns).text = computer
    # TimeCreated is an empty element with SystemTime attribute
    ts_iso = system_time.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    ET.SubElement(sys, "{%s}TimeCreated" % ns, SystemTime=ts_iso)
    ET.SubElement(sys, "{%s}Correlation" % ns)
    ET.SubElement(sys, "{%s}Execution" % ns, ProcessID="4", ThreadID="0")

    if event_data:
        ed = ET.SubElement(event, "{%s}EventData" % ns)
        for name, value in event_data:
            d = ET.SubElement(ed, "{%s}Data" % ns, Name=name)
            d.text = str(value)

    return event

# ── Cover traffic generators ───────────────────────────────────────────────

def gen_cover_security_events(rng, base_date, count=140, director_account=None,
                              exclude_accounts=None):
    """Generate cover Security events (business-hours activity)."""
    events = []
    exclude = set(exclude_accounts or [])
    # Business hours window: 08:00-18:00 UTC
    t = base_date.replace(hour=8, minute=0, second=0, microsecond=0)
    end = t + timedelta(days=1)
    for _ in range(count):
        r = rng.random()
        provider, guid = PROVIDERS["Security"]
        if r < 0.25:
            # Routine 4624 logon during business hours from a known IP
            ip = rng.choice(COVER_IPS)
            user = rng.choice([u for u in COVER_STAFF if u not in exclude])
            events.append(make_event(
                4624, t, provider, guid, "Security", "DIR-WORKSTATION",
                event_data=[("TargetUserName", user), ("LogonType", "2"),
                            ("IpAddress", ip), ("AuthenticationPackageName", "Negotiate")]
            ))
            t += timedelta(seconds=rng.randint(30, 600))
        elif r < 0.40:
            # Routine 4634 logoff
            user = rng.choice([u for u in COVER_STAFF if u not in exclude])
            events.append(make_event(
                4634, t, provider, guid, "Security", "DIR-WORKSTATION",
                event_data=[("TargetUserName", user), ("LogonType", "2")]
            ))
            t += timedelta(seconds=rng.randint(30, 1800))
        elif r < 0.55:
            # Routine 4688 process creation (benign app)
            proc = rng.choice(COVER_PROCESSES)
            events.append(make_event(
                4688, t, provider, guid, "Security", "DIR-WORKSTATION",
                event_data=[("NewProcessName", f"C:\\Program Files\\{proc}"),
                            ("CommandLine", f"C:\\Program Files\\{proc}")]
            ))
            t += timedelta(seconds=rng.randint(10, 300))
        elif r < 0.68:
            # Routine 4657 registry write (benign app reg change)
            reg_path = rng.choice(COVER_REG_PATHS)
            events.append(make_event(
                4657, t, provider, guid, "Security", "DIR-WORKSTATION",
                event_data=[("ObjectName", reg_path), ("OldValue", ""),
                            ("NewValue", "0x1")]
            ))
            t += timedelta(seconds=rng.randint(30, 900))
        elif r < 0.80:
            # Routine 4663 file access (Director's shared docs, benign)
            file = rng.choice(DIRECTOR_FILES)
            user = rng.choice([u for u in COVER_STAFF if u not in exclude])
            events.append(make_event(
                4663, t, provider, guid, "Security", "DIR-WORKSTATION",
                event_data=[("ObjectName", f"C:\\Users\\{director_account}\\Documents\\{file}"),
                            ("SubjectUserName", user), ("AccessMask", "0x10080")]
            ))
            t += timedelta(seconds=rng.randint(30, 1200))
        else:
            # 4624 network logon (Type 3) from internal IP
            ip = rng.choice(COVER_IPS)
            user = rng.choice([u for u in COVER_STAFF if u not in exclude])
            events.append(make_event(
                4624, t, provider, guid, "Security", "DIR-WORKSTATION",
                event_data=[("TargetUserName", user), ("LogonType", "3"),
                            ("IpAddress", ip), ("AuthenticationPackageName", "Kerberos")]
            ))
            t += timedelta(seconds=rng.randint(30, 900))
    return events

def gen_cover_system_events(rng, base_date, count=60):
    """Generate cover System events (service lifecycle noise)."""
    events = []
    t = base_date.replace(hour=0, minute=0, second=0, microsecond=0)
    for _ in range(count):
        r = rng.random()
        if r < 0.50:
            # 7036 service stopped
            svc = rng.choice(["WdiSystemHost", "WinMgmt", "SysMain", "BITS",
                              "wuauserv", "Spooler", "LanmanServer"])
            events.append(make_event(
                7036, t, *PROVIDERS["System"], "System", "DIR-WORKSTATION",
                event_data=[("param1", svc), ("param2", "stopped")]
            ))
            t += timedelta(seconds=rng.randint(30, 3600))
        elif r < 0.80:
            # 7045 service installed (routine)
            svc = rng.choice(["OneSyncSvc", "DiagTrack", "DoSvc", "BcastDVRUserService"])
            events.append(make_event(
                7045, t, *PROVIDERS["System"], "System", "DIR-WORKSTATION",
                event_data=[("ServiceName", svc), ("ImagePath", f"C:\\Windows\\System32\\{svc}.exe")]
            ))
            t += timedelta(seconds=rng.randint(60, 7200))
        else:
            # 6005/6006 event log start/stop
            events.append(make_event(
                6005, t, *PROVIDERS["Kernel"], "System", "DIR-WORKSTATION",
            ))
            t += timedelta(seconds=rng.randint(60, 14400))
    return events

# ── Attack sequence generator ─────────────────────────────────────────────

def gen_attack_events(rng, base_date, attacker_ip, director_account,
                      lateral_tool, reg_base_path, reg_value_name,
                      cred_tool, director_file):
    """Generate the six anomalous events in chronological order, all
       in the 01:00-04:00 UTC off-hours window.

    Returns (events, file_access_time_iso) where file_access_time_iso
    is the BT-05e answer (ISO-8601 UTC).
    """
    events = []
    provider, guid = PROVIDERS["Security"]
    computer = "DIR-WORKSTATION"

    # Start time within off-hours window (01:00-03:30 UTC)
    t = base_date.replace(hour=1, minute=rng.randint(0, 59),
                          second=rng.randint(0, 59), microsecond=0)

    # 1. Initial logon: 4624 Logon Type 2 (interactive) from attacker IP
    events.append(make_event(
        4624, t, provider, guid, "Security", computer,
        event_data=[("TargetUserName", director_account), ("LogonType", "2"),
                    ("IpAddress", attacker_ip),
                    ("AuthenticationPackageName", "Negotiate")]
    ))
    t += timedelta(seconds=rng.randint(10, 60))

    # 2. Lateral movement: 4688 process creation for the lateral tool
    lateral_path = f"C:\\Windows\\System32\\{lateral_tool}"
    events.append(make_event(
        4688, t, provider, guid, "Security", computer,
        event_data=[("NewProcessName", lateral_path),
                    ("CommandLine", f"{lateral_tool} \\\\10.10.5.18 -s")]
    ))
    t += timedelta(seconds=rng.randint(30, 180))

    # 3. Persistence: 4657 registry modification of a Run/RunOnce key
    full_reg_path = f"{reg_base_path}\\{reg_value_name}"
    events.append(make_event(
        4657, t, provider, guid, "Security", computer,
        event_data=[("ObjectName", full_reg_path), ("OldValue", ""),
                    ("NewValue", f"C:\\Users\\{director_account}\\appdata\\update.exe")]
    ))
    t += timedelta(seconds=rng.randint(30, 120))

    # 4. Credential theft: 4688 process creation for the cred-dump tool
    cred_path = f"C:\\Users\\{director_account}\\Downloads\\{cred_tool}"
    events.append(make_event(
        4688, t, provider, guid, "Security", computer,
        event_data=[("NewProcessName", cred_path),
                    ("CommandLine", f"{cred_tool} sekurlsa logonpasswords")]
    ))
    t += timedelta(seconds=rng.randint(30, 120))

    # 5. File access: 4663 first access of the Director's files
    file_path = f"C:\\Users\\{director_account}\\Documents\\{director_file}"
    file_access_event = make_event(
        4663, t, provider, guid, "Security", computer,
        event_data=[("ObjectName", file_path),
                    ("SubjectUserName", director_account),
                    ("AccessMask", "0x10080")]
    )
    events.append(file_access_event)
    # Capture the file-access timestamp (BT-05e answer)
    file_access_time = t
    t += timedelta(seconds=rng.randint(60, 600))

    # 6. (cover context) Logoff: 4634
    events.append(make_event(
        4634, t, provider, guid, "Security", computer,
        event_data=[("TargetUserName", director_account), ("LogonType", "2")]
    ))

    return events, file_access_time

# ── XML serialization ──────────────────────────────────────────────────────

def write_events_xml(events, path):
    """Write a list of Event elements to an XML file with an <Events> root."""
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    ET.register_namespace("", ns)
    root = ET.Element("Events")
    for event in events:
        root.append(event)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BT-05 artifact generator")
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
    director_account = rng.choice(DIRECTOR_ACCOUNTS)
    lateral_tool = rng.choice(LATERAL_TOOLS)
    reg_base_path = rng.choice(REG_BASE_PATHS)
    reg_value_name = rng.choice(REG_VALUE_NAMES)
    cred_tool = rng.choice(CRED_TOOLS)
    director_file = rng.choice(DIRECTOR_FILES)

    # Event date: random day in the last 30 days
    base_date = datetime(2026, 8, 1, tzinfo=timezone.utc) + \
                timedelta(days=rng.randint(0, 30))

    # Generate cover traffic
    cover_sec = gen_cover_security_events(
        rng, base_date, count=140, director_account=director_account,
        exclude_accounts=[director_account]
    )
    cover_sys = gen_cover_system_events(rng, base_date, count=60)

    # Generate attack events (off-hours)
    attack_events, file_access_time = gen_attack_events(
        rng, base_date, attacker_ip, director_account, lateral_tool,
        reg_base_path, reg_value_name, cred_tool, director_file
    )

    # Merge and sort all Security events by SystemTime
    all_sec = cover_sec + attack_events
    all_sec.sort(key=lambda e: e.find(
        "{http://schemas.microsoft.com/win/2004/08/events/event}System/"
        "{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated"
    ).get("SystemTime"))

    # Build the full registry path (BT-05c answer)
    full_reg_path = f"{reg_base_path}\\{reg_value_name}"

    # Format file access timestamp as ISO-8601 UTC (BT-05e answer)
    file_access_iso = file_access_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Write artifacts
    os.makedirs(args.out_dir, exist_ok=True)
    sec_path = os.path.join(args.out_dir, "Security_events.xml")
    sys_path = os.path.join(args.out_dir, "System_events.xml")
    write_events_xml(all_sec, sec_path)
    write_events_xml(cover_sys, sys_path)

    # Build the answer key
    answers = {
        "BT-05a: What Event ID indicates the initial logon?":
            "DZ{4624}",
        "BT-05b: What process was used for lateral movement?":
            f"DZ{{{lateral_tool}}}",
        "BT-05c: What registry key was modified for persistence?":
            f"DZ{{{full_reg_path}}}",
        "BT-05d: What tool was used to dump credentials?":
            f"DZ{{{cred_tool}}}",
        "BT-05e: At what time (UTC) did the attacker first access the Director's files?":
            f"DZ{{{file_access_iso}}}",
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
    print(f"[generate] BT-05 artifacts generated:")
    print(f"  attacker_ip:      {attacker_ip}")
    print(f"  director_account:  {director_account}")
    print(f"  lateral_tool:      {lateral_tool}")
    print(f"  reg_path:          {full_reg_path}")
    print(f"  cred_tool:         {cred_tool}")
    print(f"  director_file:     {director_file}")
    print(f"  file_access_time:  {file_access_iso}")
    print(f"  Security_events.xml: {sec_path} ({len(all_sec)} events)")
    print(f"  System_events.xml:   {sys_path} ({len(cover_sys)} events)")
    print(f"  answers:           {answers_path}")

if __name__ == "__main__":
    main()
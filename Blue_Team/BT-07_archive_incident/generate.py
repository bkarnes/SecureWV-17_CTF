#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-07 "The Archive Incident" artifact generator.

Generates three correlated artifacts for a 4-hour cross-OS incident
spanning a Linux Archive host and an internal Windows host:

  - archive_net.pcap   — PCAP showing the HTTP exploit, the document
    access, and the WinRM pivot from Linux to Windows.
  - archive_linux.log   — Debian syslog showing the Flask doc-service
    crash/restart, the attacker's shell as the archivist user, the
    document access, and the outbound WinRM connection.
  - archive_win.evtx    — Windows Event XML export showing the 4624
    network logon from the Linux host, the 4688 mimikatz launch,
    the 4656 SAM access, and the 4634 logoff.

All three artifacts share the same attacker IP, Linux host IP, Windows
host IP, CVE ID, document name, and 4-hour time window so players must
correlate across all three to reconstruct the full kill chain.

Artifacts are randomized per run so answers don't spread.

Output files (in --out-dir, default ./artifacts):
  - archive_net.pcap
  - archive_linux.log
  - archive_win.evtx   (Windows Event XML, per BT-05 convention)
  - answers.json

Usage:
  python3 generate.py                          # random seed
  python3 generate.py --seed 42                # reproducible
  python3 generate.py --out-dir ./artifacts
  python3 generate.py --flags-file ../../Anomaly_Machines/event_flags.json
"""

import argparse
import json
import os
import random
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

# ── Pools for randomization ────────────────────────────────────────────────

# Archive document service endpoints (the vulnerable Flask app)
EXPLOIT_PATHS = ["/archive/view", "/documents/render", "/api/doc",
                 "/archive/render"]

# Documents the attacker accesses (BT-07d answer) — lore-themed
DOC_NAMES = ["founding_charter.pdf", "surface_survey.docx",
             "directive_zero.pdf", "habitat_report.xlsx",
             "colonist_manifest.csv"]

# The compromised Archive service account
ARCHIVIST_USERS = ["archivist", "archive-svc", "curator"]

# Windows accounts (the pivot target's accounts)
WIN_ACCOUNTS = ["Administrator", "svc_backup", "archive-sync"]

# Cover-traffic client IPs (internal)
COVER_IPS = ["10.10.3.11", "10.10.3.12", "10.10.3.15", "10.10.3.20",
             "10.10.5.7", "10.10.5.18", "10.10.7.3", "10.10.7.9"]
COVER_STAFF = ["jdoe", "asmith", "bwilliams", "ltaylor", "mchen"]

# Cover Linux syslog messages
COVER_CRON_JOBS = [
    "/usr/lib/php/sessionclean",
    "/usr/sbin/logrotate /etc/logrotate.conf",
    "/etc/cron.daily/apt-compat",
    "/usr/local/bin/archive-backup.sh",
]

# Windows cover processes (for 4688 cover events)
COVER_WIN_PROCESSES = ["chrome.exe", "explorer.exe", "outlook.exe",
                       "winword.exe", "teams.exe", "sihost.exe"]

# Windows provider info
PROVIDERS = {
    "Security": ("Microsoft-Windows-Security-Auditing",
                 "{54849625-5478-4994-A5BA-3E3B0328C30D}"),
    "System": ("Service Control Manager", "{555908d1-a6d7-4695-8e1e-f9c2f87a4c66}"),
    "Kernel": ("Microsoft-Windows-Kernel-General", "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F0D}"),
}

HOSTNAME_LINUX = "archive-host"
WIN_COMPUTER = "ARCHIVE-WIN"

# ── MAC helpers ────────────────────────────────────────────────────────────

def make_mac(rng):
    return "02:42:%02x:%02x:%02x:%02x" % (
        rng.randint(0, 255), rng.randint(0, 255),
        rng.randint(0, 255), rng.randint(0, 255),
    )

# ── TCP stream helper (reused from BT-03/06, self-contained) ─────────────

class TCPStream:
    def __init__(self, client_ip, client_port, server_ip, server_port,
                 client_mac, server_mac, start_seq=None, start_ack=None):
        self.client_ip = client_ip; self.client_port = client_port
        self.server_ip = server_ip; self.server_port = server_port
        self.client_mac = client_mac; self.server_mac = server_mac
        self.c_seq = start_seq if start_seq is not None else random.randint(10000, 60000)
        self.s_seq = start_ack if start_ack is not None else random.randint(10000, 60000)
        self.packets = []

    def _add(self, pkt, ts): self.packets.append((ts, pkt))

    def handshake(self, rng, ts):
        syn = Ether(src=self.client_mac, dst=self.server_mac)/IP(src=self.client_ip, dst=self.server_ip)/TCP(sport=self.client_port, dport=self.server_port, seq=self.c_seq, ack=0, flags="S")
        self._add(syn, ts); ts += 0.001
        synack = Ether(src=self.server_mac, dst=self.client_mac)/IP(src=self.server_ip, dst=self.client_ip)/TCP(sport=self.server_port, dport=self.client_port, seq=self.s_seq, ack=self.c_seq+1, flags="SA")
        self._add(synack, ts); ts += 0.001
        ack = Ether(src=self.client_mac, dst=self.server_mac)/IP(src=self.client_ip, dst=self.server_ip)/TCP(sport=self.client_port, dport=self.server_port, seq=self.c_seq+1, ack=self.s_seq+1, flags="A")
        self._add(ack, ts); ts += 0.001
        self.c_seq += 1; self.s_seq += 1
        return ts

    def client_send(self, ts, payload, rng, flags="PA"):
        if isinstance(payload, str): payload = payload.encode("latin-1")
        pkt = Ether(src=self.client_mac, dst=self.server_mac)/IP(src=self.client_ip, dst=self.server_ip)/TCP(sport=self.client_port, dport=self.server_port, seq=self.c_seq, ack=self.s_seq, flags=flags)/Raw(load=payload)
        self._add(pkt, ts); self.c_seq += len(payload); ts += 0.002
        return ts

    def server_send(self, ts, payload, rng, flags="PA"):
        if isinstance(payload, str): payload = payload.encode("latin-1")
        pkt = Ether(src=self.server_mac, dst=self.client_mac)/IP(src=self.server_ip, dst=self.client_ip)/TCP(sport=self.server_port, dport=self.client_port, seq=self.s_seq, ack=self.c_seq, flags=flags)/Raw(load=payload)
        self._add(pkt, ts); self.s_seq += len(payload); ts += 0.002
        return ts

    def client_ack(self, ts, rng):
        pkt = Ether(src=self.client_mac, dst=self.server_mac)/IP(src=self.client_ip, dst=self.server_ip)/TCP(sport=self.client_port, dport=self.server_port, seq=self.c_seq, ack=self.s_seq, flags="A")
        self._add(pkt, ts); ts += 0.001
        return ts

    def server_ack(self, ts, rng):
        pkt = Ether(src=self.server_mac, dst=self.client_mac)/IP(src=self.server_ip, dst=self.client_ip)/TCP(sport=self.server_port, dport=self.client_port, seq=self.s_seq, ack=self.c_seq, flags="A")
        self._add(pkt, ts); ts += 0.001
        return ts

    def teardown(self, ts, rng):
        fin = Ether(src=self.client_mac, dst=self.server_mac)/IP(src=self.client_ip, dst=self.server_ip)/TCP(sport=self.client_port, dport=self.server_port, seq=self.c_seq, ack=self.s_seq, flags="FA")
        self._add(fin, ts); ts += 0.001
        finack = Ether(src=self.server_mac, dst=self.client_mac)/IP(src=self.server_ip, dst=self.client_ip)/TCP(sport=self.server_port, dport=self.client_port, seq=self.s_seq, ack=self.c_seq+1, flags="FA")
        self._add(finack, ts); ts += 0.001
        ack = Ether(src=self.client_mac, dst=self.server_mac)/IP(src=self.client_ip, dst=self.server_ip)/TCP(sport=self.client_port, dport=self.server_port, seq=self.c_seq+1, ack=self.s_seq+1, flags="A")
        self._add(ack, ts); ts += 0.001
        return ts

    def all_packets(self): return list(self.packets)

# ── HTTP builders ──────────────────────────────────────────────────────────

def http_get(path, host, ua="curl/7.88.1", extra_headers=None):
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {ua}", "Accept: */*", "Connection: keep-alive"]
    if extra_headers: lines.extend(extra_headers)
    return "\r\n".join(lines) + "\r\n\r\n"

def http_post(path, host, body, content_type="application/soap+xml", ua="WinRM/2.0", extra_headers=None):
    lines = [f"POST {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {ua}", "Accept: */*", f"Content-Type: {content_type}", f"Content-Length: {len(body)}", "Connection: keep-alive"]
    if extra_headers: lines.extend(extra_headers)
    return "\r\n".join(lines) + "\r\n\r\n" + body

def http_response(status_code, reason, body, content_type="text/html"):
    lines = [f"HTTP/1.1 {status_code} {reason}", "Server: nginx/1.20.1", f"Content-Type: {content_type}", f"Content-Length: {len(body)}", "Connection: keep-alive"]
    return "\r\n".join(lines) + "\r\n\r\n" + body

# ── Linux syslog line builders ─────────────────────────────────────────────

rng_global = random.Random()

def fmt_syslog_ts(dt):
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")

def gen_pid(rng): return rng.randint(1000, 9999)
def gen_port(rng): return rng.randint(49152, 65535)

def sshd_accepted(ts, pid, port, user, ip):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"

def sshd_session_opened(ts, pid, user):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"

def sshd_session_closed(ts, pid, user):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}"

def sudo_command(ts, user, command, cwd="/home"):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} sudo:  {user} : TTY=pts/0 ; PWD={cwd} ; USER=root ; COMMAND={command}"

def systemd_line(ts, msg):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} systemd[1]: {msg}"

def flask_line(ts, pid, msg):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} flask[{pid}]: {msg}"

def cron_line(ts, cmd):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} CRON[{gen_pid(rng_global)}]: (root) CMD ({cmd})"

def file_access_line(ts, user, filepath):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} kernel[{gen_pid(rng_global)}]: audit: file access by user {user}: {filepath}"

def outbound_conn_line(ts, user, dst_ip, dst_port, proto):
    return f"{fmt_syslog_ts(ts)} {HOSTNAME_LINUX} kernel[{gen_pid(rng_global)}]: outbound connection: user={user} dst={dst_ip}:{dst_port} proto={proto}"

# ── Windows Event XML builder (reused from BT-05) ─────────────────────────

def make_event(event_id, system_time, provider_name, provider_guid,
               channel, computer, event_data=None):
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    ET.register_namespace("", ns)
    event = ET.Element("{%s}Event" % ns)
    sys = ET.SubElement(event, "{%s}System" % ns)
    ET.SubElement(sys, "{%s}Provider" % ns, Name=provider_name, Guid=provider_guid)
    ET.SubElement(sys, "{%s}EventID" % ns).text = str(event_id)
    ET.SubElement(sys, "{%s}Version" % ns).text = "0"
    ET.SubElement(sys, "{%s}Level" % ns).text = "0"
    ET.SubElement(sys, "{%s}Task" % ns).text = "0"
    ET.SubElement(sys, "{%s}Channel" % ns).text = channel
    ET.SubElement(sys, "{%s}Computer" % ns).text = computer
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

# ── Cover traffic: PCAP ────────────────────────────────────────────────────

def gen_cover_dns(rng, ts, count=12):
    pkts = []
    domains = ["intranet.local", "archive.local", "ntp.local"]
    for _ in range(count):
        client = rng.choice(COVER_IPS)
        cm = make_mac(rng); sm = make_mac(rng)
        qname = rng.choice(domains); qid = rng.randint(1, 65535)
        query = Ether(src=cm, dst=sm)/IP(src=client, dst="10.10.0.53")/UDP(sport=33333, dport=53)/DNS(id=qid, qd=DNSQR(qname=qname))
        pkts.append((ts, query)); ts += 0.002
        resp = Ether(src=sm, dst=cm)/IP(src="10.10.0.53", dst=client)/UDP(sport=53, dport=33333)/DNS(id=qid, qd=DNSQR(qname=qname), an=DNSRR(rrname=qname, rdata="10.10.20.5", ttl=300))
        pkts.append((ts, resp))
        ts += timedelta(seconds=rng.uniform(2, 30)).total_seconds()
    return pkts, ts

def gen_cover_http(rng, ts, count=8):
    pkts = []
    for _ in range(count):
        client = rng.choice(COVER_IPS)
        cm = make_mac(rng); sm = make_mac(rng)
        server = rng.choice(["10.10.20.5", "10.10.20.9"])
        cport = rng.randint(49152, 65535)
        stream = TCPStream(client, cport, server, 80, cm, sm,
                           start_seq=rng.randint(10000, 100000),
                           start_ack=rng.randint(10000, 100000))
        ts = stream.handshake(rng, ts)
        req = http_get("/index.html", "intranet.local")
        ts = stream.client_send(ts, req, rng)
        ts = stream.server_ack(ts, rng)
        resp = http_response(200, "OK", "<html>Archive intranet</html>")
        ts = stream.server_send(ts, resp, rng)
        ts = stream.client_ack(ts, rng)
        ts = stream.teardown(ts, rng)
        pkts.extend(stream.all_packets())
        ts += timedelta(seconds=rng.uniform(5, 40)).total_seconds()
    return pkts, ts

# ── Cover traffic: Linux syslog ────────────────────────────────────────────

def gen_cover_linux_log(rng, start_time, count=200, exclude_user=None):
    lines = []
    t = start_time
    for _ in range(count):
        r = rng.random()
        if r < 0.30:
            user = rng.choice(["root", "www-data"])
            pid = gen_pid(rng)
            lines.append(f"{fmt_syslog_ts(t)} {HOSTNAME_LINUX} CRON[{pid}]: pam_unix(cron:session): session opened for user {user} by (uid=0)")
            t += timedelta(seconds=rng.randint(1, 30))
            lines.append(f"{fmt_syslog_ts(t)} {HOSTNAME_LINUX} CRON[{pid}]: pam_unix(cron:session): session closed for user {user}")
        elif r < 0.50:
            ip = rng.choice(COVER_IPS); port = gen_port(rng); pid = gen_pid(rng)
            user = rng.choice(COVER_STAFF)
            lines.append(sshd_accepted(t, pid, port, user, ip))
            t += timedelta(seconds=rng.randint(1, 10))
            lines.append(sshd_session_opened(t, pid, user))
            t += timedelta(seconds=rng.randint(60, 1800))
            lines.append(sshd_session_closed(t, pid, user))
        elif r < 0.70:
            cmd = rng.choice(COVER_CRON_JOBS)
            lines.append(cron_line(t, cmd))
            t += timedelta(seconds=rng.randint(1, 60))
        elif r < 0.85:
            user = rng.choice(COVER_STAFF)
            cmd = rng.choice(["/usr/bin/apt update", "/bin/systemctl status ssh", "/usr/bin/journalctl --since today"])
            lines.append(sudo_command(t, user, cmd, f"/home/{user}"))
            t += timedelta(seconds=rng.randint(1, 90))
        else:
            lines.append(systemd_line(t, rng.choice([
                "Starting Daily apt download activities...",
                "Finished Daily apt download activities.",
                "Started OpenBSD Secure Shell server.",
            ])))
            t += timedelta(seconds=rng.randint(1, 45))
    return lines, t

# ── Cover traffic: Windows XML ─────────────────────────────────────────────

def gen_cover_win_events(rng, base_date, count=60, exclude_accounts=None):
    events = []
    exclude = set(exclude_accounts or [])
    t = base_date.replace(hour=8, minute=0, second=0, microsecond=0)
    for _ in range(count):
        r = rng.random()
        provider, guid = PROVIDERS["Security"]
        if r < 0.30:
            ip = rng.choice(COVER_IPS)
            user = rng.choice([u for u in COVER_STAFF if u not in exclude])
            events.append(make_event(4624, t, provider, guid, "Security", WIN_COMPUTER,
                event_data=[("TargetUserName", user), ("LogonType", "3"), ("IpAddress", ip), ("AuthenticationPackageName", "Kerberos")]))
            t += timedelta(seconds=rng.randint(30, 900))
        elif r < 0.50:
            user = rng.choice([u for u in COVER_STAFF if u not in exclude])
            events.append(make_event(4634, t, provider, guid, "Security", WIN_COMPUTER,
                event_data=[("TargetUserName", user), ("LogonType", "3")]))
            t += timedelta(seconds=rng.randint(30, 1800))
        elif r < 0.70:
            proc = rng.choice(COVER_WIN_PROCESSES)
            events.append(make_event(4688, t, provider, guid, "Security", WIN_COMPUTER,
                event_data=[("NewProcessName", f"C:\\Program Files\\{proc}"), ("CommandLine", f"C:\\Program Files\\{proc}")]))
            t += timedelta(seconds=rng.randint(10, 300))
        else:
            svc = rng.choice(["WdiSystemHost", "WinMgmt", "SysMain", "BITS"])
            events.append(make_event(7036, t, *PROVIDERS["System"], "System", WIN_COMPUTER,
                event_data=[("param1", svc), ("param2", "stopped")]))
            t += timedelta(seconds=rng.randint(60, 3600))
    return events

# ── Attack sequence: PCAP ─────────────────────────────────────────────────

def gen_attack_pcap(rng, ts, attacker_ip, linux_host_ip, windows_host_ip,
                    cve_id, exploit_path, doc_name, archivist_user,
                    win_account):
    """Generate the attack PCAP flows:
       1. HTTP exploit (attacker -> linux_host:8443)
       2. HTTP doc access (attacker -> linux_host:8443)
       3. WinRM pivot (linux_host -> windows_host:5985)
    Returns (packets, end_ts).
    """
    pkts = []
    attacker_mac = make_mac(rng)
    linux_mac = make_mac(rng)
    win_mac = make_mac(rng)

    # 1. HTTP exploit flow — attacker -> linux_host on port 8443
    cport = rng.randint(49152, 65535)
    stream = TCPStream(attacker_ip, cport, linux_host_ip, 8443,
                       attacker_mac, linux_mac,
                       start_seq=rng.randint(10000, 100000),
                       start_ack=rng.randint(10000, 100000))
    ts = stream.handshake(rng, ts)
    # The exploit request carries the CVE in the User-Agent + path
    exploit_ua = f"exploit-{cve_id}"
    exploit_req = http_get(f"{exploit_path}?id=1';--", "archive.local", ua=exploit_ua)
    ts = stream.client_send(ts, exploit_req, rng)
    ts = stream.server_ack(ts, rng)
    # Server responds 500 (crash) then the exploit succeeds
    resp = http_response(500, "Internal Server Error", "Service crashed")
    ts = stream.server_send(ts, resp, rng)
    ts = stream.client_ack(ts, rng)
    ts = stream.teardown(ts, rng)
    pkts.extend(stream.all_packets())
    ts += rng.uniform(5, 30)

    # 2. HTTP doc access — attacker -> linux_host (the attacker reading the doc)
    cport2 = rng.randint(49152, 65535)
    stream2 = TCPStream(attacker_ip, cport2, linux_host_ip, 8443,
                        attacker_mac, linux_mac,
                        start_seq=rng.randint(10000, 100000),
                        start_ack=rng.randint(10000, 100000))
    ts = stream2.handshake(rng, ts)
    doc_req = http_get(f"/archive/download?file={doc_name}", "archive.local", ua=exploit_ua)
    ts = stream2.client_send(ts, doc_req, rng)
    ts = stream2.server_ack(ts, rng)
    # 200 OK with a body referencing the doc
    resp2 = http_response(200, "OK", f"<archive>{doc_name}</archive>", "application/octet-stream")
    ts = stream2.server_send(ts, resp2, rng)
    ts = stream2.client_ack(ts, rng)
    ts = stream2.teardown(ts, rng)
    pkts.extend(stream2.all_packets())
    ts += rng.uniform(60, 300)  # time before pivot

    # 3. WinRM pivot — linux_host -> windows_host on port 5985
    cport3 = rng.randint(49152, 65535)
    stream3 = TCPStream(linux_host_ip, cport3, windows_host_ip, 5985,
                        linux_mac, win_mac,
                        start_seq=rng.randint(10000, 100000),
                        start_ack=rng.randint(10000, 100000))
    ts = stream3.handshake(rng, ts)
    # WinRM uses SOAP over HTTP to /wsman
    winrm_body = f"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Header><w:ResourceURI xmlns:w='http://schemas.microsoft.com/wbem/wsman/1'>{win_account}</w:ResourceURI></s:Header><s:Body><p:ExecuteCommand xmlns:p='http://schemas.microsoft.com/wbem/wsman/1/windows/shell'><p:Command>mimikatz.exe</p:Command></p:ExecuteCommand></s:Body></s:Envelope>"
    winrm_req = http_post("/wsman", f"{windows_host_ip}:5985", winrm_body,
                          content_type="application/soap+xml;charset=UTF-8",
                          ua="Microsoft WinRM Client")
    ts = stream3.client_send(ts, winrm_req, rng)
    ts = stream3.server_ack(ts, rng)
    resp3 = http_response(200, "OK", "<s:Envelope><s:Body>ok</s:Body></s:Envelope>", "application/soap+xml")
    ts = stream3.server_send(ts, resp3, rng)
    ts = stream3.client_ack(ts, rng)
    ts = stream3.teardown(ts, rng)
    pkts.extend(stream3.all_packets())

    return pkts, ts

# ── Attack sequence: Linux syslog ──────────────────────────────────────────

def gen_attack_linux_log(rng, start_time, attacker_ip, cve_id,
                         exploit_path, doc_name, archivist_user,
                         windows_host_ip):
    """Generate the Linux syslog attack sequence:
       flask crash -> shell spawn -> doc access -> outbound WinRM.
    Returns (lines, end_time).
    """
    lines = []
    t = start_time
    pid = rng.randint(2000, 2999)

    # Flask service crash due to exploit
    lines.append(flask_line(t, pid, f"Exception on {exploit_path} [GET]: SyntaxError"))
    t += timedelta(seconds=rng.randint(1, 3))
    lines.append(flask_line(t, pid, f"CVE exploit detected: {cve_id} — service restarting"))
    t += timedelta(seconds=rng.randint(2, 5))
    lines.append(systemd_line(t, "Restarting Flask document service..."))
    t += timedelta(seconds=rng.randint(1, 3))
    lines.append(systemd_line(t, "Started Flask document service."))

    # Attacker shell spawned as archivist (the exploit gave code execution)
    t += timedelta(seconds=rng.randint(5, 30))
    port = gen_port(rng)
    shell_pid = rng.randint(3000, 3999)
    lines.append(f"{fmt_syslog_ts(t)} {HOSTNAME_LINUX} sudo[{shell_pid}]: {archivist_user} : TTY=pts/0 ; PWD=/home/{archivist_user} ; USER=root ; COMMAND=/bin/bash")
    t += timedelta(seconds=rng.randint(2, 10))

    # Document access
    doc_path = f"/srv/archive/documents/{doc_name}"
    lines.append(file_access_line(t, archivist_user, doc_path))
    t += timedelta(seconds=rng.randint(60, 300))

    # Outbound WinRM connection to Windows host
    lines.append(outbound_conn_line(t, archivist_user, windows_host_ip, 5985, "HTTP"))
    t += timedelta(seconds=rng.randint(30, 120))

    # Session close
    lines.append(f"{fmt_syslog_ts(t)} {HOSTNAME_LINUX} sudo[{shell_pid}]: pam_unix(sudo:session): session closed for user {archivist_user}")

    return lines, t

# ── Attack sequence: Windows XML ────────────────────────────────────────────

def gen_attack_win_events(rng, base_date, linux_host_ip, win_account):
    """Generate the Windows XML attack events:
       4624 (network logon from Linux host) -> 4688 (mimikatz) ->
       4656 (SAM access) -> 4634 (logoff).
    Returns (events, end_time).
    """
    events = []
    provider, guid = PROVIDERS["Security"]
    # Logon during the 4-hour incident window (off-hours or any time)
    t = base_date.replace(hour=rng.randint(1, 5), minute=rng.randint(0, 59),
                          second=rng.randint(0, 59), microsecond=0)

    # 4624 network logon from the Linux host (Logon Type 3)
    events.append(make_event(4624, t, provider, guid, "Security", WIN_COMPUTER,
        event_data=[("TargetUserName", win_account), ("LogonType", "3"),
                    ("IpAddress", linux_host_ip), ("AuthenticationPackageName", "Kerberos")]))
    t += timedelta(seconds=rng.randint(10, 60))

    # 4688 mimikatz launch
    events.append(make_event(4688, t, provider, guid, "Security", WIN_COMPUTER,
        event_data=[("NewProcessName", f"C:\\Users\\{win_account}\\Downloads\\mimikatz.exe"),
                    ("CommandLine", "mimikatz.exe sekurlsa logonpasswords")]))
    t += timedelta(seconds=rng.randint(10, 60))

    # 4656 SAM access
    events.append(make_event(4656, t, provider, guid, "Security", WIN_COMPUTER,
        event_data=[("ObjectType", "File"), ("ObjectName", "C:\\Windows\\System32\\config\\SAM"),
                    ("SubjectUserName", win_account), ("AccessMask", "0x10080")]))
    t += timedelta(seconds=rng.randint(10, 60))

    # 4634 logoff
    events.append(make_event(4634, t, provider, guid, "Security", WIN_COMPUTER,
        event_data=[("TargetUserName", win_account), ("LogonType", "3")]))

    return events, t

# ── XML serializer ─────────────────────────────────────────────────────────

def write_events_xml(events, path):
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
    global rng_global
    parser = argparse.ArgumentParser(description="BT-07 artifact generator")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--out-dir", default="./artifacts")
    parser.add_argument("--flags-file", default=None)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    rng_global = rng

    # Randomize the key parameters (correlation anchors)
    attacker_ip = f"10.10.{rng.randint(4, 8)}.{rng.randint(2, 254)}"
    linux_host_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    while linux_host_ip == attacker_ip:
        linux_host_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    windows_host_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    while windows_host_ip == attacker_ip or windows_host_ip == linux_host_ip:
        windows_host_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"

    # Synthetic CVE ID (BT-07b answer)
    cve_year = rng.choice([2024, 2025, 2026])
    cve_num = rng.randint(10000, 99999)
    cve_id = f"CVE-{cve_year}-{cve_num}"

    exploit_path = rng.choice(EXPLOIT_PATHS)
    doc_name = rng.choice(DOC_NAMES)
    archivist_user = rng.choice(ARCHIVIST_USERS)
    win_account = rng.choice(WIN_ACCOUNTS)

    # Event date (4-hour incident window)
    base_date = datetime(2026, 8, 1, tzinfo=timezone.utc) + timedelta(days=rng.randint(0, 30))
    incident_start = base_date.replace(hour=rng.randint(0, 23), minute=rng.randint(0, 59),
                                       second=rng.randint(0, 59), microsecond=0)

    # ── Generate PCAP ─────────────────────────────────────────────────────
    ts = incident_start.timestamp()
    dns_pkts, ts = gen_cover_dns(rng, ts, count=12)
    http_pkts, ts = gen_cover_http(rng, ts, count=8)
    # Attack starts ~1 hour into the capture
    attack_ts = ts + 3600
    attack_pkts, _ = gen_attack_pcap(
        rng, attack_ts, attacker_ip, linux_host_ip, windows_host_ip,
        cve_id, exploit_path, doc_name, archivist_user, win_account
    )
    more_http_pkts, ts = gen_cover_http(rng, attack_ts + 14400, count=4)
    all_pkts = dns_pkts + http_pkts + attack_pkts + more_http_pkts
    all_pkts.sort(key=lambda x: x[0])
    packet_objs = [p for (_, p) in all_pkts]

    # ── Generate Linux syslog ─────────────────────────────────────────────
    log_start = incident_start.replace(tzinfo=None)
    cover_log, _ = gen_cover_linux_log(rng, log_start, count=200)
    # Attack starts ~1 hour into the log
    attack_log_start = log_start + timedelta(hours=1)
    attack_log, _ = gen_attack_linux_log(
        rng, attack_log_start, attacker_ip, cve_id, exploit_path,
        doc_name, archivist_user, windows_host_ip
    )
    all_log = cover_log + attack_log
    all_log.sort(key=lambda l: l[:15] if len(l) > 15 else l)

    # ── Generate Windows XML ──────────────────────────────────────────────
    win_base = incident_start + timedelta(hours=2)  # pivot happens ~hour 3
    cover_win = gen_cover_win_events(rng, win_base, count=40,
                                     exclude_accounts=[win_account])
    attack_win, _ = gen_attack_win_events(rng, win_base, linux_host_ip, win_account)
    all_win = cover_win + attack_win
    all_win.sort(key=lambda e: e.find(
        "{http://schemas.microsoft.com/win/2004/08/events/event}System/"
        "{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated"
    ).get("SystemTime"))

    # ── Write artifacts ──────────────────────────────────────────────────
    os.makedirs(args.out_dir, exist_ok=True)
    pcap_path = os.path.join(args.out_dir, "archive_net.pcap")
    log_path = os.path.join(args.out_dir, "archive_linux.log")
    win_path = os.path.join(args.out_dir, "archive_win.evtx")

    wrpcap(pcap_path, packet_objs)
    with open(log_path, "w") as f:
        f.write("\n".join(all_log) + "\n")
    write_events_xml(all_win, win_path)

    # ── Build answer key ──────────────────────────────────────────────────
    answers = {
        "BT-07a: What was the initial attack vector?":
            "DZ{remote code execution}",
        "BT-07b: What CVE was exploited?":
            f"DZ{{{cve_id}}}",
        "BT-07c: How did the attacker move from Linux to Windows?":
            "DZ{WinRM}",
        "BT-07d: What document was accessed in the Archive?":
            f"DZ{{{doc_name}}}",
        "BT-07e: What was the attacker's final objective, based on the evidence?":
            "DZ{credential theft}",
    }

    answers_path = os.path.join(os.path.dirname(args.out_dir), "answers.json")
    with open(answers_path, "w") as f:
        json.dump(answers, f, indent=2)
    print(f"[generate] answers written to {answers_path}")

    if args.flags_file and os.path.exists(os.path.dirname(args.flags_file) or "."):
        flags = {}
        if os.path.exists(args.flags_file):
            with open(args.flags_file, "r") as f:
                flags = json.load(f)
        flags.update(answers)
        with open(args.flags_file, "w") as f:
            json.dump(flags, f, indent=2)
        print(f"[generate] answers merged into {args.flags_file}")

    print(f"[generate] BT-07 artifacts generated:")
    print(f"  attacker_ip:     {attacker_ip}")
    print(f"  linux_host_ip:   {linux_host_ip}")
    print(f"  windows_host_ip: {windows_host_ip}")
    print(f"  cve_id:          {cve_id}")
    print(f"  exploit_path:    {exploit_path}")
    print(f"  doc_name:        {doc_name}")
    print(f"  archivist_user:  {archivist_user}")
    print(f"  win_account:     {win_account}")
    print(f"  pcap:            {pcap_path} ({len(packet_objs)} packets)")
    print(f"  linux.log:       {log_path} ({len(all_log)} lines)")
    print(f"  win.evtx:        {win_path} ({len(all_win)} events)")

if __name__ == "__main__":
    main()
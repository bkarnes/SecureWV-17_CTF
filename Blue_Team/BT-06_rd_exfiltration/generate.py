#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-06 "The R&D Exfiltration" artifact generator.

Generates two correlated artifacts for a multi-stage exfiltration
against the R&D Annex API:

  - api_access.log — Nginx combined-format web access log showing
    a SQLi attack against the API followed by N staging GETs to
    /api/files/<id> (one per file the attacker will steal).
  - rnd_traffic.pcap — PCAP showing the attacker exfiltrating N
    files via HTTP POST /upload to an external receiver IP.

The two artifacts share the same attacker IP, file count N, and
time window so players must correlate them: the access log
answers BT-06a (vuln class) and, combined with the PCAP, BT-06b
(file count); the PCAP answers BT-06c (total bytes) and BT-06d
(receiver IP).

Artifacts are randomized per run so answers don't spread between
events.

Output files (in --out-dir, default ./artifacts):
  - api_access.log   — Nginx combined access log (~300 lines)
  - rnd_traffic.pcap — PCAP with cover + exfil traffic (~150 pkts)
  - answers.json     — answer key in DZ{...} format

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

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

# ── Pools for randomization ────────────────────────────────────────────────

# API endpoints (the vulnerable resource)
API_ENDPOINTS = ["/api/research", "/api/projects", "/api/datasets",
                 "/api/blueprints"]

# Vulnerable parameter names
VULN_PARAMS = ["id", "project_id", "dataset_id", "blueprint_id"]

# API hostnames (appears in Host header)
API_HOSTS = ["rnd-annex.local", "api.rd.local", "research.local"]

# External receiver host (for the exfil POSTs)
RECEIVER_HOSTS = ["exfil-c2.net", "drop.rnd-external.net", "cdn-collector.net"]

# Cover-traffic browsers
COVER_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "curl/7.88.1",
]

# Attacker user-agent (distinctive, for easy grep)
ATTACKER_UAS = ["sqlmap/1.7.8#stable (http://sqlmap.org)",
                "sqlmap/1.8.2#stable (http://sqlmap.org)",
                "python-requests/2.31.0"]

# Cover-traffic client IPs (internal)
COVER_IPS = ["10.10.3.11", "10.10.3.12", "10.10.3.15", "10.10.3.20",
             "10.10.5.7", "10.10.5.18", "10.10.7.3", "10.10.7.9"]

# Cover API paths + typical status/size
COVER_API_PATHS = [
    ("/api/health", 200, 64),
    ("/api/version", 200, 32),
    ("/api/status", 200, 128),
    ("/api/research?limit=10", 200, 2048),
    ("/api/projects?status=active", 200, 1024),
    ("/api/datasets?type=public", 200, 512),
    ("/", 200, 256),
    ("/docs", 200, 1024),
]

# Cover DNS servers + decoy HTTP servers (for PCAP cover)
DNS_SERVER = "10.10.0.53"
DECOY_SERVERS = ["10.10.20.5", "10.10.20.9", "10.10.21.3"]
DECOY_DOMAINS = ["intranet.local", "docs.local", "status.local"]
DECOY_PATHS = ["/", "/index.html", "/about.html", "/status", "/api/health"]

HOSTNAME = "rnd-annex"

# ── MAC helpers ────────────────────────────────────────────────────────────

def make_mac(rng):
    return "02:42:%02x:%02x:%02x:%02x" % (
        rng.randint(0, 255), rng.randint(0, 255),
        rng.randint(0, 255), rng.randint(0, 255),
    )

# ── TCP stream helper (reused from BT-03, self-contained) ─────────────────

class TCPStream:
    """Tracks seq/ack for a single TCP flow so wireshark's 'Follow TCP
    Stream' reconstructs clean HTTP request/response pairs."""

    def __init__(self, client_ip, client_port, server_ip, server_port,
                 client_mac, server_mac, start_seq=None, start_ack=None):
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.c_seq = start_seq if start_seq is not None else random.randint(10000, 60000)
        self.s_seq = start_ack if start_ack is not None else random.randint(10000, 60000)
        self.packets = []

    def _add(self, pkt, ts):
        self.packets.append((ts, pkt))

    def handshake(self, rng, ts):
        syn = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=0, flags="S")
        self._add(syn, ts); ts += 0.001
        synack = Ether(src=self.server_mac, dst=self.client_mac) / \
                 IP(src=self.server_ip, dst=self.client_ip) / \
                 TCP(sport=self.server_port, dport=self.client_port,
                     seq=self.s_seq, ack=self.c_seq + 1, flags="SA")
        self._add(synack, ts); ts += 0.001
        ack = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq + 1, ack=self.s_seq + 1, flags="A")
        self._add(ack, ts); ts += 0.001
        self.c_seq += 1; self.s_seq += 1
        return ts

    def client_send(self, ts, payload, rng, flags="PA"):
        if isinstance(payload, str):
            payload = payload.encode("latin-1")
        pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=self.s_seq, flags=flags) / \
              Raw(load=payload)
        self._add(pkt, ts)
        self.c_seq += len(payload); ts += 0.002
        return ts

    def server_send(self, ts, payload, rng, flags="PA"):
        if isinstance(payload, str):
            payload = payload.encode("latin-1")
        pkt = Ether(src=self.server_mac, dst=self.client_mac) / \
              IP(src=self.server_ip, dst=self.client_ip) / \
              TCP(sport=self.server_port, dport=self.client_port,
                  seq=self.s_seq, ack=self.c_seq, flags=flags) / \
              Raw(load=payload)
        self._add(pkt, ts)
        self.s_seq += len(payload); ts += 0.002
        return ts

    def client_ack(self, ts, rng):
        pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=self.s_seq, flags="A")
        self._add(pkt, ts); ts += 0.001
        return ts

    def server_ack(self, ts, rng):
        pkt = Ether(src=self.server_mac, dst=self.client_mac) / \
              IP(src=self.server_ip, dst=self.client_ip) / \
              TCP(sport=self.server_port, dport=self.client_port,
                  seq=self.s_seq, ack=self.c_seq, flags="A")
        self._add(pkt, ts); ts += 0.001
        return ts

    def teardown(self, ts, rng):
        fin = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=self.s_seq, flags="FA")
        self._add(fin, ts); ts += 0.001
        finack = Ether(src=self.server_mac, dst=self.client_mac) / \
                IP(src=self.server_ip, dst=self.client_ip) / \
                TCP(sport=self.server_port, dport=self.client_port,
                    seq=self.s_seq, ack=self.c_seq + 1, flags="FA")
        self._add(finack, ts); ts += 0.001
        ack = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq + 1, ack=self.s_seq + 1, flags="A")
        self._add(ack, ts); ts += 0.001
        return ts

    def all_packets(self):
        return list(self.packets)

# ── HTTP builders ──────────────────────────────────────────────────────────

def http_get(path, host, ua="QUORUM-Node/2.3", extra_headers=None):
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}",
             f"User-Agent: {ua}", "Accept: */*",
             "Connection: keep-alive"]
    if extra_headers:
        lines.extend(extra_headers)
    return "\r\n".join(lines) + "\r\n\r\n"

def http_post(path, host, body, content_type="application/octet-stream",
              ua="QUORUM-Node/2.3", extra_headers=None):
    lines = [f"POST {path} HTTP/1.1", f"Host: {host}",
             f"User-Agent: {ua}", "Accept: */*",
             f"Content-Type: {content_type}",
             f"Content-Length: {len(body)}",
             "Connection: keep-alive"]
    if extra_headers:
        lines.extend(extra_headers)
    return "\r\n".join(lines) + "\r\n\r\n" + body

def http_response(status_code, reason, body, content_type="text/html"):
    lines = [f"HTTP/1.1 {status_code} {reason}",
             "Server: nginx/1.20.1",
             f"Content-Type: {content_type}",
             f"Content-Length: {len(body)}",
             "Connection: keep-alive"]
    return "\r\n".join(lines) + "\r\n\r\n" + body

# ── Access log line builder ────────────────────────────────────────────────

def fmt_access_ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def access_log_line(ip, dt, method, path, status, size, ua, referer="-"):
    req = f"{method} {path} HTTP/1.1"
    return (f'{ip} - - [{fmt_access_ts(dt)}] "{req}" {status} {size} '
            f'"{referer}" "{ua}"')

# ── Cover traffic: access log ──────────────────────────────────────────────

def gen_cover_access_log(rng, start_time, count=250, vuln_param=None):
    """Generate legitimate API browsing traffic."""
    lines = []
    t = start_time
    for _ in range(count):
        ip = rng.choice(COVER_IPS)
        ua = rng.choice(COVER_UAS)
        r = rng.random()
        if r < 0.25 and vuln_param:
            # Legit /api/<endpoint>?<param>=<int>
            val = rng.randint(1000, 9999)
            path = f"{rng.choice(API_ENDPOINTS)}?{vuln_param}={val}"
            status = 200
            size = rng.randint(512, 2048)
        elif r < 0.80:
            path, status, base_size = rng.choice(COVER_API_PATHS)
            size = base_size + rng.randint(-64, 64)
            if size < 0: size = 0
        else:
            path = rng.choice(["/admin", "/wp-admin", "/.env", "/api/private"])
            status = 404
            size = 0
        lines.append(access_log_line(ip, t, "GET", path, status, size, ua))
        t += timedelta(seconds=rng.randint(1, 20))
    return lines, t

# ── Attack sequence: access log ─────────────────────────────────────────────

def gen_attack_access_log(rng, start_time, attacker_ip, attacker_ua,
                          api_endpoint, vuln_param, file_count, file_ids):
    """Generate the SQLi + staging GETs for the access log.

    Returns (lines, end_time).
    """
    lines = []
    t = start_time

    # Phase 1: SQLi recon (~8 lines)
    sqli_payloads = [
        f"{api_endpoint}?{vuln_param}=1'",
        f"{api_endpoint}?{vuln_param}=1'--",
        f"{api_endpoint}?{vuln_param}=1' OR '1'='1",
        f"{api_endpoint}?{vuln_param}=1' AND '1'='2",
        f"{api_endpoint}?{vuln_param}=1' ORDER BY 1--",
        f"{api_endpoint}?{vuln_param}=-1' UNION SELECT 1,2,3,4--",
        f"{api_endpoint}?{vuln_param}=-1 UNION SELECT 1,2,3,4--",
        f"{api_endpoint}?{vuln_param}=-1 UNION SELECT 1,2,3,4-- -",
    ]
    for payload in sqli_payloads:
        status = 500 if rng.random() < 0.5 else 200
        size = rng.randint(64, 512) if status == 500 else rng.randint(800, 1600)
        lines.append(access_log_line(attacker_ip, t, "GET", payload,
                                      status, size, attacker_ua))
        t += timedelta(seconds=rng.randint(2, 10))

    # Phase 2: staging GETs — one per file to be exfiltrated
    for fid in file_ids:
        path = f"/api/files/{fid}"
        status = 200
        size = rng.randint(1024, 4096)
        lines.append(access_log_line(attacker_ip, t, "GET", path,
                                      status, size, attacker_ua))
        t += timedelta(seconds=rng.randint(1, 5))

    return lines, t

# ── Cover traffic: PCAP ────────────────────────────────────────────────────

def gen_cover_dns(rng, ts, count=15):
    pkts = []
    domains = ["intranet.local", "docs.local", "rnd-annex.local", "ntp.local"]
    for _ in range(count):
        client = rng.choice(COVER_IPS)
        client_mac = make_mac(rng); server_mac = make_mac(rng)
        qname = rng.choice(domains); qid = rng.randint(1, 65535)
        query = Ether(src=client_mac, dst=server_mac) / \
                IP(src=client, dst=DNS_SERVER) / \
                UDP(sport=33333, dport=53) / \
                DNS(id=qid, qd=DNSQR(qname=qname))
        pkts.append((ts, query)); ts += 0.002
        resp = Ether(src=server_mac, dst=client_mac) / \
               IP(src=DNS_SERVER, dst=client) / \
               UDP(sport=53, dport=33333) / \
               DNS(id=qid, qd=DNSQR(qname=qname),
                   an=DNSRR(rrname=qname, rdata="10.10.20.5", ttl=300))
        pkts.append((ts, resp))
        ts += timedelta(seconds=rng.uniform(2, 20)).total_seconds()
    return pkts, ts

def gen_cover_http(rng, ts, count=10):
    pkts = []
    for _ in range(count):
        client = rng.choice(COVER_IPS)
        client_mac = make_mac(rng)
        server = rng.choice(DECOY_SERVERS)
        server_mac = make_mac(rng)
        cport = rng.randint(49152, 65535)
        path = rng.choice(DECOY_PATHS); host = rng.choice(DECOY_DOMAINS)
        stream = TCPStream(client, cport, server, 80, client_mac, server_mac,
                           start_seq=rng.randint(10000, 100000),
                           start_ack=rng.randint(10000, 100000))
        ts = stream.handshake(rng, ts)
        req = http_get(path, host)
        ts = stream.client_send(ts, req, rng)
        ts = stream.server_ack(ts, rng)
        body = "<html><body>R&D Annex intranet.</body></html>"
        resp = http_response(200, "OK", body)
        ts = stream.server_send(ts, resp, rng)
        ts = stream.client_ack(ts, rng)
        ts = stream.teardown(ts, rng)
        pkts.extend(stream.all_packets())
        ts += timedelta(seconds=rng.uniform(2, 30)).total_seconds()
    return pkts, ts

# ── Exfiltration: PCAP ─────────────────────────────────────────────────────

def gen_exfil_traffic(rng, ts, attacker_ip, receiver_ip, receiver_host,
                      attacker_ua, file_ids, file_sizes):
    """Generate N HTTP POST /upload flows (one per file) from the
    attacker (R&D host) to the external receiver. Each POST body is
    a dummy payload of the given size.

    Returns (packets, total_bytes).
    """
    pkts = []
    total_bytes = 0
    attacker_mac = make_mac(rng)
    receiver_mac = make_mac(rng)

    for fid, size in zip(file_ids, file_sizes):
        cport = rng.randint(49152, 65535)
        stream = TCPStream(attacker_ip, cport, receiver_ip, 80,
                           attacker_mac, receiver_mac,
                           start_seq=rng.randint(10000, 100000),
                           start_ack=rng.randint(10000, 100000))
        ts = stream.handshake(rng, ts)

        # Build the POST body — a dummy payload of exactly `size` bytes.
        # The body includes a header naming the file id so players can
        # correlate with the access log.
        header = f"file_id={fid}\n"
        body = header + ("X" * (size - len(header)))
        if len(body) < size:  # pad if header larger than size
            body = body[:size]
        post = http_post("/upload", receiver_host, body,
                         content_type="application/octet-stream",
                         ua=attacker_ua)
        # Send the POST (may split into 2 segments for realism)
        chunk = 1024
        body_bytes = post.encode("latin-1")
        ts = stream.client_send(ts, body_bytes[:chunk], rng)
        ts = stream.server_ack(ts, rng)
        if len(body_bytes) > chunk:
            ts = stream.client_send(ts, body_bytes[chunk:chunk*2], rng)
            ts = stream.server_ack(ts, rng)
        if len(body_bytes) > chunk*2:
            ts = stream.client_send(ts, body_bytes[chunk*2:], rng)
            ts = stream.server_ack(ts, rng)
        # Server 200 OK
        resp = http_response(200, "OK", "OK")
        ts = stream.server_send(ts, resp, rng)
        ts = stream.client_ack(ts, rng)
        ts = stream.teardown(ts, rng)

        pkts.extend(stream.all_packets())
        total_bytes += size
        ts += rng.uniform(1, 5)

    return pkts, total_bytes

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BT-06 artifact generator")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--out-dir", default="./artifacts",
                        help="Output directory")
    parser.add_argument("--flags-file", default=None,
                        help="Path to event_flags.json to merge answers into")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # Randomize the key parameters
    attacker_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    receiver_ip = f"10.10.{rng.randint(4, 8)}.{rng.randint(2, 254)}"
    while receiver_ip == attacker_ip:
        receiver_ip = f"10.10.{rng.randint(4, 8)}.{rng.randint(2, 254)}"
    api_endpoint = rng.choice(API_ENDPOINTS)
    vuln_param = rng.choice(VULN_PARAMS)
    api_host = rng.choice(API_HOSTS)
    receiver_host = rng.choice(RECEIVER_HOSTS)
    attacker_ua = rng.choice(ATTACKER_UAS)

    # File count + IDs + sizes (the correlation anchors)
    file_count = rng.randint(3, 7)
    file_ids = rng.sample(range(10000, 99999), file_count)
    file_sizes = [rng.randint(4096, 65536) for _ in range(file_count)]
    total_bytes = sum(file_sizes)

    # Event date
    base_date = datetime(2026, 8, 1) + timedelta(days=rng.randint(0, 30))
    start_time = base_date.replace(hour=rng.randint(0, 23),
                                    minute=rng.randint(0, 59),
                                    second=rng.randint(0, 59),
                                    microsecond=0)

    # Access log: cover + attack
    cover_log, _ = gen_cover_access_log(rng, start_time, count=250,
                                         vuln_param=vuln_param)
    attack_start = start_time + timedelta(hours=rng.randint(1, 4))
    attack_log, attack_end = gen_attack_access_log(
        rng, attack_start, attacker_ip, attacker_ua,
        api_endpoint, vuln_param, file_count, file_ids
    )
    all_log = cover_log + attack_log
    all_log.sort(key=lambda l: l.split("]")[0][1:] if "[" in l else l)

    # PCAP: cover + exfil (exfil starts shortly after the staging GETs)
    ts = start_time.timestamp()
    dns_pkts, ts = gen_cover_dns(rng, ts, count=15)
    http_pkts, ts = gen_cover_http(rng, ts, count=10)
    # Exfil starts ~1-2 minutes after the access-log attack ends
    exfil_start = attack_end.timestamp() + rng.uniform(60, 120)
    exfil_pkts, exfil_total = gen_exfil_traffic(
        rng, exfil_start, attacker_ip, receiver_ip, receiver_host,
        attacker_ua, file_ids, file_sizes
    )
    more_http_pkts, ts = gen_cover_http(rng, exfil_start + 600, count=5)
    more_dns_pkts, ts = gen_cover_dns(rng, exfil_start + 600, count=8)

    all_pkts = dns_pkts + http_pkts + exfil_pkts + more_http_pkts + more_dns_pkts
    all_pkts.sort(key=lambda x: x[0])
    packet_objs = [p for (_, p) in all_pkts]

    # Write artifacts
    os.makedirs(args.out_dir, exist_ok=True)
    log_path = os.path.join(args.out_dir, "api_access.log")
    pcap_path = os.path.join(args.out_dir, "rnd_traffic.pcap")
    with open(log_path, "w") as f:
        f.write("\n".join(all_log) + "\n")
    wrpcap(pcap_path, packet_objs)

    # Build the answer key
    answers = {
        "BT-06a: What vulnerability class was exploited for initial access?":
            "DZ{SQL injection}",
        "BT-06b: How many files were exfiltrated?":
            f"DZ{{{file_count}}}",
        "BT-06c: What was the total size of exfiltrated data (bytes)?":
            f"DZ{{{total_bytes}}}",
        "BT-06d: What IP received the exfiltrated data?":
            f"DZ{{{receiver_ip}}}",
    }

    # Write answers.json
    answers_path = os.path.join(os.path.dirname(args.out_dir), "answers.json")
    with open(answers_path, "w") as f:
        json.dump(answers, f, indent=2)
    print(f"[generate] answers written to {answers_path}")

    # Merge into event_flags.json
    if args.flags_file and os.path.exists(os.path.dirname(args.flags_file) or "."):
        flags = {}
        if os.path.exists(args.flags_file):
            with open(args.flags_file, "r") as f:
                flags = json.load(f)
        flags.update(answers)
        with open(args.flags_file, "w") as f:
            json.dump(flags, f, indent=2)
        print(f"[generate] answers merged into {args.flags_file}")

    # Summary
    print(f"[generate] BT-06 artifacts generated:")
    print(f"  attacker_ip:    {attacker_ip}")
    print(f"  receiver_ip:    {receiver_ip}")
    print(f"  api_endpoint:   {api_endpoint}?{vuln_param}=")
    print(f"  attacker_ua:    {attacker_ua}")
    print(f"  file_count:     {file_count}")
    print(f"  file_ids:        {file_ids}")
    print(f"  file_sizes:     {file_sizes}")
    print(f"  total_bytes:    {total_bytes}")
    print(f"  access.log:     {log_path} ({len(all_log)} lines)")
    print(f"  pcap:           {pcap_path} ({len(packet_objs)} packets)")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
DIRECTIVE ZERO — BT-03 "The Junction Intercept" artifact generator.

Generates a synthetic PCAP capture at "Network Junction 7" containing
an HTTP-based C2 session: a compromised internal host beacons to a
C2 server, receives a command, and exfiltrates a file with an encoded
body. The artifact is randomized per run so answers don't spread
between events.

Output files (in --out-dir, default ./artifacts):
  - junction7_capture.pcap — PCAP with cover + C2 traffic (~3-5MB)
  - answers.json            — answer key in DZ{...} format

The answers are also merged into the event_flags.json file (if
--flags-file is specified) so import_challenges.py can load them.

Usage:
  python3 generate.py                          # random seed
  python3 generate.py --seed 42                # reproducible
  python3 generate.py --out-dir ./artifacts    # custom output dir
  python3 generate.py --flags-file ../../Anomaly_Machines/event_flags.json
"""

import argparse
import base64
import codecs
import json
import os
import random
import struct
import sys
from datetime import datetime, timedelta

# Scapy is used purely as a build-time dependency to emit a valid PCAP.
# We import only what we need and never send packets on the wire.
from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR,
    Raw, wrpcap, Raw as ScapyRaw,
)

# ── Pools for randomization ────────────────────────────────────────────────

# C2 domain (appears in HTTP Host header)
C2_DOMAINS = ["c2-update.net", "portal-check.net", "cdn-sync.net"]

# Command verb the C2 operator issues (BT-03c answer)
COMMAND_VERBS = ["harvest", "collect", "gather", "retrieve", "fetch"]

# Exfiltrated filename (BT-03d answer)
EXFIL_FILENAMES = [
    "enrollment.dat",
    "registry.csv",
    "personnel.dat",
    "roster.csv",
    "manifest.dat",
]

# Encoding used to obfuscate the exfil body (BT-03e answer)
ENCODINGS = ["base64", "hex", "rot13"]

# Beacon identifier for the compromised host
VICTIM_IDS = ["node-7a", "node-12b", "agent-3c", "host-19d"]

# Cover-traffic HTTP servers (decoy web servers internal hosts browse)
DECOY_SERVERS = ["10.10.20.5", "10.10.20.9", "10.10.21.3"]
DECOY_DOMAINS = ["intranet.local", "docs.local", "status.local"]
DECOY_PATHS = ["/", "/index.html", "/about.html", "/status", "/api/health"]

# Cover-traffic DNS servers
DNS_SERVER = "10.10.0.53"

# Internal IPs for cover-traffic clients
COVER_CLIENT_IPS = ["10.10.3.11", "10.10.3.12", "10.10.3.15",
                    "10.10.5.7", "10.10.5.18", "10.10.7.3"]

# MAC address helpers (synthetic, locally-administered range)
def make_mac(rng):
    return "02:42:%02x:%02x:%02x:%02x" % (
        rng.randint(0, 255), rng.randint(0, 255),
        rng.randint(0, 255), rng.randint(0, 255),
    )

# ── TCP stream helper ──────────────────────────────────────────────────────

class TCPStream:
    """Tracks seq/ack numbers for a single client->server TCP flow.

    Scapy doesn't auto-track state, so we maintain seq/ack manually to
    produce reassemblable HTTP streams (so wireshark's 'Follow TCP
    Stream' reconstructs clean HTTP request/response pairs).
    """

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
        self.packets = []  # list of (timestamp, packet)

    def _add(self, pkt, ts):
        self.packets.append((ts, pkt))

    def handshake(self, rng, ts):
        """3-way handshake. Returns updated ts."""
        # SYN
        syn = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=0, flags="S")
        self._add(syn, ts)
        ts += 0.001
        # SYN-ACK
        synack = Ether(src=self.server_mac, dst=self.client_mac) / \
                 IP(src=self.server_ip, dst=self.client_ip) / \
                 TCP(sport=self.server_port, dport=self.client_port,
                     seq=self.s_seq, ack=self.c_seq + 1, flags="SA")
        self._add(synack, ts)
        ts += 0.001
        # ACK
        ack = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq + 1, ack=self.s_seq + 1, flags="A")
        self._add(ack, ts)
        ts += 0.001
        # Advance seqs past the handshake
        self.c_seq += 1
        self.s_seq += 1
        return ts

    def client_send(self, ts, payload, rng, flags="PA"):
        """Client -> server data segment. Returns updated ts."""
        if isinstance(payload, str):
            payload = payload.encode("latin-1")
        pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=self.s_seq, flags=flags) / \
              Raw(load=payload)
        self._add(pkt, ts)
        self.c_seq += len(payload)
        ts += 0.002
        return ts

    def server_send(self, ts, payload, rng, flags="PA"):
        """Server -> client data segment. Returns updated ts."""
        if isinstance(payload, str):
            payload = payload.encode("latin-1")
        pkt = Ether(src=self.server_mac, dst=self.client_mac) / \
              IP(src=self.server_ip, dst=self.client_ip) / \
              TCP(sport=self.server_port, dport=self.client_port,
                  seq=self.s_seq, ack=self.c_seq, flags=flags) / \
              Raw(load=payload)
        self._add(pkt, ts)
        self.s_seq += len(payload)
        ts += 0.002
        return ts

    def client_ack(self, ts, rng):
        """Pure ACK from client (advances ack to server seq)."""
        pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=self.s_seq, flags="A")
        self._add(pkt, ts)
        ts += 0.001
        return ts

    def server_ack(self, ts, rng):
        """Pure ACK from server."""
        pkt = Ether(src=self.server_mac, dst=self.client_mac) / \
              IP(src=self.server_ip, dst=self.client_ip) / \
              TCP(sport=self.server_port, dport=self.client_port,
                  seq=self.s_seq, ack=self.c_seq, flags="A")
        self._add(pkt, ts)
        ts += 0.001
        return ts

    def teardown(self, ts, rng):
        """4-way FIN teardown. Returns updated ts."""
        fin = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq, ack=self.s_seq, flags="FA")
        self._add(fin, ts)
        ts += 0.001
        finack = Ether(src=self.server_mac, dst=self.client_mac) / \
                IP(src=self.server_ip, dst=self.client_ip) / \
                TCP(sport=self.server_port, dport=self.client_port,
                    seq=self.s_seq, ack=self.c_seq + 1, flags="FA")
        self._add(finack, ts)
        ts += 0.001
        ack = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=self.client_ip, dst=self.server_ip) / \
              TCP(sport=self.client_port, dport=self.server_port,
                  seq=self.c_seq + 1, ack=self.s_seq + 1, flags="A")
        self._add(ack, ts)
        ts += 0.001
        return ts

    def all_packets(self):
        return list(self.packets)

# ── HTTP request/response builders ─────────────────────────────────────────

def http_get(path, host, extra_headers=None):
    """Build a minimal HTTP/1.1 GET request."""
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}",
             "User-Agent: QUORUM-Node/2.3", "Accept: */*",
             "Connection: keep-alive"]
    if extra_headers:
        lines.extend(extra_headers)
    return "\r\n".join(lines) + "\r\n\r\n"

def http_post(path, host, body, content_type="application/octet-stream",
              extra_headers=None):
    """Build a minimal HTTP/1.1 POST request."""
    lines = [f"POST {path} HTTP/1.1", f"Host: {host}",
             "User-Agent: QUORUM-Node/2.3", "Accept: */*",
             f"Content-Type: {content_type}",
             f"Content-Length: {len(body)}",
             "Connection: keep-alive"]
    if extra_headers:
        lines.extend(extra_headers)
    return "\r\n".join(lines) + "\r\n\r\n" + body

def http_response(status_code, reason, body, content_type="text/html"):
    """Build a minimal HTTP/1.1 response."""
    lines = [f"HTTP/1.1 {status_code} {reason}",
             "Server: nginx/1.20.1",
             f"Content-Type: {content_type}",
             f"Content-Length: {len(body)}",
             "Connection: keep-alive"]
    return "\r\n".join(lines) + "\r\n\r\n" + body

# ── Encoding helpers ───────────────────────────────────────────────────────

def encode_payload(plaintext, encoding):
    """Encode the exfil body per the chosen scheme."""
    if encoding == "base64":
        return base64.b64encode(plaintext.encode()).decode()
    elif encoding == "hex":
        return plaintext.encode().hex()
    elif encoding == "rot13":
        return codecs.encode(plaintext, "rot_13")
    else:
        raise ValueError(f"unknown encoding: {encoding}")

# ── Cover traffic generators ───────────────────────────────────────────────

def gen_cover_dns(rng, ts, count=20):
    """Generate DNS query/response cover traffic."""
    pkts = []
    domains = ["intranet.local", "docs.local", "status.local",
               "updates.local", "ntp.local"]
    for _ in range(count):
        client = rng.choice(COVER_CLIENT_IPS)
        client_mac = make_mac(rng)
        server_mac = make_mac(rng)
        qname = rng.choice(domains)
        qid = rng.randint(1, 65535)
        # Query
        query = Ether(src=client_mac, dst=server_mac) / \
                IP(src=client, dst=DNS_SERVER) / \
                UDP(sport=33333, dport=53) / \
                DNS(id=qid, qd=DNSQR(qname=qname))
        pkts.append((ts, query))
        ts += 0.002
        # Response
        resp = Ether(src=server_mac, dst=client_mac) / \
               IP(src=DNS_SERVER, dst=client) / \
               UDP(sport=53, dport=33333) / \
               DNS(id=qid, qd=DNSQR(qname=qname),
                   an=DNSRR(rrname=qname, rdata="10.10.20.5", ttl=300))
        pkts.append((ts, resp))
        ts += timedelta(seconds=rng.uniform(1, 15)).total_seconds()
    return pkts, ts

def gen_cover_http(rng, ts, count=15):
    """Generate HTTP cover traffic to decoy servers."""
    pkts = []
    for _ in range(count):
        client = rng.choice(COVER_CLIENT_IPS)
        client_mac = make_mac(rng)
        server = rng.choice(DECOY_SERVERS)
        server_mac = make_mac(rng)
        cport = rng.randint(49152, 65535)
        path = rng.choice(DECOY_PATHS)
        host = rng.choice(DECOY_DOMAINS)
        stream = TCPStream(client, cport, server, 80,
                          client_mac, server_mac,
                          start_seq=rng.randint(10000, 100000),
                          start_ack=rng.randint(10000, 100000))
        ts = stream.handshake(rng, ts)
        req = http_get(path, host)
        ts = stream.client_send(ts, req, rng)
        ts = stream.server_ack(ts, rng)
        body = "<html><body>Welcome to the Construct intranet.</body></html>"
        resp = http_response(200, "OK", body)
        ts = stream.server_send(ts, resp, rng)
        ts = stream.client_ack(ts, rng)
        ts = stream.teardown(ts, rng)
        pkts.extend(stream.all_packets())
        ts += timedelta(seconds=rng.uniform(2, 30)).total_seconds()
    return pkts, ts

# ── C2 traffic generator ───────────────────────────────────────────────────

def gen_c2_traffic(rng, ts, victim_ip, c2_ip, c2_domain, victim_id,
                   command_verb, exfil_filename, encoding):
    """Generate the full C2 session: beacons -> command -> exfil.

    Returns a list of (timestamp, packet) tuples.
    """
    victim_mac = make_mac(rng)
    c2_mac = make_mac(rng)
    c2_port = 80
    victim_port = rng.randint(49152, 65535)

    stream = TCPStream(victim_ip, victim_port, c2_ip, c2_port,
                      victim_mac, c2_mac,
                      start_seq=rng.randint(10000, 100000),
                      start_ack=rng.randint(10000, 100000))

    pkts = []
    # ── 3-way handshake ─────────────────────────────────────────────────
    ts = stream.handshake(rng, ts)

    # ── Beacon phase: ~10 GET /ping exchanges ───────────────────────────
    beacon_count = rng.randint(8, 12)
    for i in range(beacon_count):
        beacon_path = f"/ping?id={victim_id}&seq={i}"
        req = http_get(beacon_path, c2_domain)
        ts = stream.client_send(ts, req, rng)
        ts = stream.server_ack(ts, rng)
        # Server responds 200 OK with minimal body
        body = "ACK"
        resp = http_response(200, "OK", body)
        ts = stream.server_send(ts, resp, rng)
        ts = stream.client_ack(ts, rng)
        # Inter-beacon delay (seconds, added as float to ts)
        ts += rng.uniform(5, 30)

    # ── Command phase: 1 GET /task, server returns the command ─────────
    req = http_get("/task", c2_domain)
    ts = stream.client_send(ts, req, rng)
    ts = stream.server_ack(ts, rng)
    # The command body is just the verb (the C2 operator's instruction)
    resp = http_response(200, "OK", command_verb,
                         content_type="text/plain")
    ts = stream.server_send(ts, resp, rng)
    ts = stream.client_ack(ts, rng)
    ts += rng.uniform(2, 8)

    # ── Exfiltration phase: POST /upload with header + encoded body ────
    # The plaintext is a small fake data blob. The header line names
    # the file; the body is the encoded blob.
    plaintext = (f"id={victim_id},command={command_verb},"
                 f"file={exfil_filename},"
                 f"records=42,status=complete")
    encoded = encode_payload(plaintext, encoding)
    exfil_body = f"filename: {exfil_filename}\n{encoded}\n"
    req = http_post("/upload", c2_domain, exfil_body,
                    content_type="application/octet-stream")
    # Exfil is large — split into 2-3 segments for realism
    chunk = 1024
    body_bytes = req.encode("latin-1")
    # Send request headers + first chunk
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

    # ── Teardown ───────────────────────────────────────────────────────
    ts = stream.teardown(ts, rng)

    return stream.all_packets(), ts

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BT-03 artifact generator")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--out-dir", default="./artifacts",
                        help="Output directory")
    parser.add_argument("--flags-file", default=None,
                        help="Path to event_flags.json to merge answers into")
    args = parser.parse_args()

    # NOTE: scapy imports set the global random state; we use a separate
    # random.Random for our own pool picks so seed control is deterministic.
    rng = random.Random(args.seed)

    # Randomize the key parameters
    victim_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
    # Ensure c2_ip != victim_ip
    while True:
        c2_ip = f"10.10.{rng.randint(2, 8)}.{rng.randint(2, 254)}"
        if c2_ip != victim_ip:
            break
    c2_domain = rng.choice(C2_DOMAINS)
    victim_id = rng.choice(VICTIM_IDS)
    command_verb = rng.choice(COMMAND_VERBS)
    exfil_filename = rng.choice(EXFIL_FILENAMES)
    encoding = rng.choice(ENCODINGS)

    # Event date: random day in the last 30 days. Use a float base ts
    # (seconds since epoch) so we can add sub-second offsets.
    base_date = datetime(2026, 8, 1) + timedelta(days=rng.randint(0, 30))
    base_dt = base_date.replace(hour=rng.randint(0, 23),
                                 minute=rng.randint(0, 59),
                                 second=rng.randint(0, 59),
                                 microsecond=0)
    ts = base_dt.timestamp()

    # Generate cover traffic
    dns_pkts, ts = gen_cover_dns(rng, ts, count=20)
    http_pkts, ts = gen_cover_http(rng, ts, count=15)

    # Generate C2 traffic (starts ~2-5 minutes into the capture)
    c2_start = ts + rng.uniform(120, 300)
    c2_pkts, ts = gen_c2_traffic(
        rng, c2_start, victim_ip, c2_ip, c2_domain, victim_id,
        command_verb, exfil_filename, encoding
    )

    # A bit more cover traffic after the C2 session ends
    more_http_pkts, ts = gen_cover_http(rng, ts, count=5)
    more_dns_pkts, ts = gen_cover_dns(rng, ts, count=10)

    # Merge all packets and sort by timestamp
    all_pkts = dns_pkts + http_pkts + c2_pkts + more_http_pkts + more_dns_pkts
    all_pkts.sort(key=lambda x: x[0])

    # Extract just the packet objects (drop timestamps; wrpcap writes
    # its own. We sorted to get correct ordering.)
    packet_objs = [p for (_, p) in all_pkts]

    # Write artifacts
    os.makedirs(args.out_dir, exist_ok=True)
    pcap_path = os.path.join(args.out_dir, "junction7_capture.pcap")
    wrpcap(pcap_path, packet_objs)

    # Build the answer key — keys must match import_challenges.py output:
    #   f"{q['qid']}: {q['question']}"
    answers = {
        "BT-03a: What protocol is used for C2 communication?":
            "DZ{HTTP}",
        "BT-03b: What is the C2 server's IP address?":
            f"DZ{{{c2_ip}}}",
        "BT-03c: What command was issued by the C2 operator?":
            f"DZ{{{command_verb}}}",
        "BT-03d: What data was exfiltrated? (filename)":
            f"DZ{{{exfil_filename}}}",
        "BT-03e: What encoding was used to obfuscate the exfiltrated data?":
            f"DZ{{{encoding}}}",
    }

    # Write answers.json (sibling to out-dir, matching BT-01/02 convention)
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
    print(f"[generate] BT-03 artifacts generated:")
    print(f"  victim_ip:      {victim_ip}")
    print(f"  c2_ip:          {c2_ip}")
    print(f"  c2_domain:      {c2_domain}")
    print(f"  victim_id:      {victim_id}")
    print(f"  command_verb:   {command_verb}")
    print(f"  exfil_filename: {exfil_filename}")
    print(f"  encoding:       {encoding}")
    print(f"  pcap:           {pcap_path} ({len(packet_objs)} packets)")

if __name__ == "__main__":
    main()
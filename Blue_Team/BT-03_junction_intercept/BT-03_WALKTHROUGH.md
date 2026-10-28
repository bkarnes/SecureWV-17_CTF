# BT-03: The Junction Intercept — Player Walkthrough

> **Difficulty:** TEAL (Intermediate)
> **Artifact:** `junction7_capture.pcap` (network packet capture)
> **Questions:** 5 (125–175 CP each)
> **Skills learned:** PCAP analysis, identifying C2 (command and control) traffic, TCP stream reassembly, recognizing beaconing patterns, decoding obfuscated data

This challenge gives you a network packet capture (PCAP) file. You must analyze the captured traffic to identify a Command and Control (C2) session and determine what data was exfiltrated. This is a core network forensics skill.

---

## Prerequisites

- A machine with **Wireshark** installed (GUI tool) OR a Linux machine with `tshark` / `strings` / `python3`
- The artifact file `junction7_capture.pcap`
- Basic understanding of network protocols (TCP, HTTP, DNS)

---

## Understanding the Artifact

**What is a PCAP?** A PCAP (Packet Capture) file contains raw network traffic — every packet that was sent and received on the network during the capture period. It's the most detailed form of network evidence.

Open the PCAP in Wireshark:

```bash
wireshark junction7_capture.pcap
```

Or use `tshark` (command-line Wireshark) for a quick overview:

```bash
tshark -r junction7_capture.pcap -q -z conv,tcp
```

This shows all TCP conversations — you'll see several connections. Some are normal (DNS queries, HTTP to internal servers), and one is the C2 traffic.

You can also use `strings` to quickly find readable text in the PCAP:

```bash
strings junction7_capture.pcap | grep -i "GET\|POST\|HTTP\|Host:" | head -20
```

---

## Question 1 — What protocol is used for C2 communication?

**Goal:** Identify the protocol the attacker used for command and control.

Look at the protocol hierarchy in Wireshark: **Statistics → Protocol Hierarchy**. Or use tshark:

```bash
tshark -r junction7_capture.pcap -q -z io,phs
```

The C2 traffic uses a common protocol (HTTP) blended with normal web traffic. The key is identifying which HTTP sessions are C2 vs. normal browsing.

Look for repeated requests to the same endpoint — this "beaconing" pattern is characteristic of C2:

```bash
strings junction7_capture.pcap | grep "GET /ping"
```

If you see multiple `/ping` requests to the same server, that's a C2 beacon. The protocol is **HTTP**.

**Answer format:** `DZ{HTTP}`

---

## Question 2 — What is the C2 server's IP address?

**Goal:** Identify which IP address is the C2 server.

Look at the beaconing requests you found. The C2 server is the destination IP of those requests.

In Wireshark:
1. Right-click on a beacon packet → Follow → TCP Stream
2. Look at the IP addresses — the server is the one receiving the GET requests

Or with strings:

```bash
strings junction7_capture.pcap | grep "Host:" | sort -u
```

Look for a domain that doesn't match the normal internal servers. Then find the IP associated with that host.

Alternatively, look at the destination IPs of all HTTP traffic and identify the outlier — the one that's different from the internal web servers.

**Answer format:** `DZ{10.10.x.x}`

---

## Question 3 — What command was issued by the C2 operator?

**Goal:** Find the command the attacker sent through the C2 channel.

After the beaconing phase, the C2 server sends a command to the compromised host. Look for a request to a `/task` or similar endpoint — this is where the C2 sends commands.

In Wireshark, follow the TCP stream of the C2 session:
1. Click on any C2 packet
2. Right-click → Follow → TCP Stream
3. Read the conversation — you'll see beacon requests and responses

The server's response to the `/task` request contains the command. It will be a short word like `harvest`, `collect`, `gather`, etc.

Or with strings:

```bash
strings junction7_capture.pcap | grep -A2 "/task"
```

**Answer format:** `DZ{command}`

---

## Question 4 — What data was exfiltrated? (filename)

**Goal:** Find the name of the file the attacker exfiltrated.

Look for a POST request (data being sent FROM the compromised host TO the C2 server). This is the exfiltration — the compromised host is sending stolen data back.

In Wireshark, look for HTTP POST requests in the C2 stream. The POST body will contain a header line like `filename: <name>`.

Or with strings:

```bash
strings junction7_capture.pcap | grep "filename:"
```

**Answer format:** `DZ{filename}` (e.g., `DZ{registry.csv}`)

---

## Question 5 — What encoding was used to obfuscate the exfiltrated data?

**Goal:** Determine how the attacker encoded the exfiltrated data to hide it.

The exfiltration POST body (after the filename header) contains encoded data. You need to figure out which encoding scheme was used.

Look at the data after the `filename:` line in the exfil POST:

**Base64** — uses characters `A-Z`, `a-z`, `0-9`, `+`, `/`, `=` (padding). Example: `aGVsbG8=`

**Hex** — uses only `0-9` and `a-f`. Example: `68656c6c6f`

**ROT13** — looks like readable text but with letters shifted by 13. Example: `uryyb` (which is "hello" in ROT13)

To verify your guess, decode the data and check if it contains the filename or other expected content:

```bash
# If base64:
echo "ENCODED_DATA" | base64 -d

# If hex:
echo "ENCODED_DATA" | xxd -r -p

# If ROT13:
echo "ENCODED_DATA" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

The decoded output should mention the filename or contain recognizable text.

**Answer format:** `DZ{encoding}` (e.g., `DZ{base64}`, `DZ{hex}`, or `DZ{rot13}`)

---

## Summary

| Question | Technique | What you did |
|----------|-----------|-------------|
| Q1: Protocol | Protocol analysis | Identified HTTP beaconing pattern in the PCAP |
| Q2: C2 server IP | Traffic analysis | Found the destination of the beacon requests |
| Q3: Command | Stream reassembly | Followed the TCP stream, read the /task response |
| Q4: Filename | POST body analysis | Found the `filename:` header in the exfil POST |
| Q5: Encoding | Pattern recognition + decode | Identified the encoding by character set, verified by decoding |

**Key takeaways:**
- **PCAPs are the gold standard for network forensics.** They contain every packet — nothing is hidden.
- **C2 beaconing is recognizable.** Regular requests to the same endpoint at regular intervals = beacon.
- **Follow TCP Stream is your best friend in Wireshark.** It reassembles the full conversation so you can read it.
- **Exfiltration is usually a POST request.** Data going OUT from a compromised host to an external server.
- **Encoding ≠ encryption.** Base64, hex, and ROT13 are encodings — they can be reversed without a key. The challenge is identifying which one was used.
# BT-06: The R&D Exfiltration — Player Walkthrough

> **Difficulty:** CRIMSON (Advanced)
> **Artifacts:** `api_access.log` (web access log) + `rnd_traffic.pcap` (network PCAP)
> **Questions:** 4 (200–225 CP each)
> **Skills learned:** Multi-artifact correlation, identifying attack vectors from web logs, counting exfiltrated files from PCAP, calculating total exfiltrated bytes, identifying exfiltration destination

This is a **correlation challenge** — you have two artifacts from the same incident, and you must cross-reference them to answer all questions. Neither file alone has all the answers. This is a critical skill for real-world incident response where evidence comes from multiple sources.

---

## Prerequisites

- A machine with `grep`, `curl`, `wireshark` (or `tshark`/`strings`), and `bc` (or Python)
- The artifact files `api_access.log` and `rnd_traffic.pcap`
- Understanding of web logs (from BT-02) and PCAP analysis (from BT-03)

---

## Understanding the Artifacts

- **`api_access.log`** — Nginx access log from the R&D Annex API. Contains the initial attack (SQLi) and the staging phase (enumerating files to steal).
- **`rnd_traffic.pcap`** — Network capture showing the exfiltration phase (the actual data leaving the network).

**The correlation:** The same attacker IP appears in both files. The access log shows HOW the attacker got in and WHICH files they targeted. The PCAP shows WHERE the files were sent and HOW MUCH data was exfiltrated. You need both to complete the picture.

---

## Question 1 — What vulnerability class was exploited for initial access?

**Goal:** Identify the attack type from the web access log.

Analyze the access log for attack signatures (same technique as BT-02):

```bash
grep -i "UNION" api_access.log
grep -i "SELECT" api_access.log
grep "'" api_access.log | head -10
```

If you see SQL injection patterns (UNION, SELECT, single quotes, SQL comments), the vulnerability class is **SQL injection**.

**Answer format:** `DZ{SQL injection}`

---

## Question 2 — How many files were exfiltrated?

**Goal:** Count the number of files the attacker stole. This requires correlating both artifacts.

### From the access log: count staging GETs

After the SQLi, the attacker enumerated files to steal. Look for GET requests to `/api/files/<id>`:

```bash
grep "GET /api/files/" api_access.log | grep " 200 "
```

Count the distinct file IDs:

```bash
grep "GET /api/files/" api_access.log | grep " 200 " | grep -oE "/api/files/[0-9]+" | sort -u | wc -l
```

### From the PCAP: count exfiltration POSTs

The exfiltration appears as HTTP POST requests in the PCAP:

```bash
strings rnd_traffic.pcap | grep -c "POST /upload"
```

**The correlation:** The number of staging GETs in the log should equal the number of exfil POSTs in the PCAP — that's the file count.

**Answer format:** `DZ{number}`

---

## Question 3 — What was the total size of exfiltrated data (bytes)?

**Goal:** Calculate the total bytes of data the attacker exfiltrated. This answer comes from the PCAP.

Each exfiltration POST has a `Content-Length` header that tells you how many bytes were sent. Sum them all:

```bash
strings rnd_traffic.pcap | grep "POST /upload" | grep -oE "Content-Length: [0-9]+" | grep -oE "[0-9]+" | paste -sd+ | bc
```

**What this does:**
- `strings rnd_traffic.pcap` — extracts readable text from the PCAP
- `grep "POST /upload"` — finds the exfil requests
- `grep -oE "Content-Length: [0-9]+"` — extracts the Content-Length headers
- `grep -oE "[0-9]+"` — extracts just the numbers
- `paste -sd+ | bc` — joins them with `+` and computes the sum

Alternatively, you can use Wireshark: follow each exfil TCP stream and note the data size, then add them up.

**Answer format:** `DZ{number}` (total bytes)

---

## Question 4 — What IP received the exfiltrated data?

**Goal:** Find the destination IP of the exfiltration traffic. This comes from the PCAP.

The exfil POSTs go to a specific destination IP. Find it by looking at the destination of the POST requests:

In Wireshark:
1. Filter for HTTP POST requests: `http.request.method == "POST"`
2. Look at the destination IP

Or with strings:

```bash
strings rnd_traffic.pcap | grep -B5 "POST /upload" | grep "Host:"
```

Then correlate the Host header to the destination IP in the PCAP. The destination IP of the exfil traffic is the answer.

**Answer format:** `DZ{10.10.x.x}`

---

## Summary

| Question | Source | Technique | What you did |
|----------|--------|-----------|-------------|
| Q1: Vulnerability | access.log | Pattern matching | Found SQLi signatures in URLs |
| Q2: File count | Both | Correlation | Counted staging GETs = exfil POSTs |
| Q3: Total bytes | PCAP | Content-Length sum | Added up all POST body sizes |
| Q4: Receiver IP | PCAP | Traffic analysis | Found the destination of exfil POSTs |

**Key takeaways:**
- **Multi-artifact correlation is the hallmark of advanced IR.** No single source has the full picture — you must combine evidence.
- **The attacker IP links the artifacts.** The same IP appears in the access log (attacking) and the PCAP (exfiltrating).
- **Staging precedes exfiltration.** The attacker first enumerates files (GET requests), then sends them out (POST requests). Count the GETs to know how many files were taken.
- **Content-Length headers tell you data volume.** Sum them across all exfil requests to get the total bytes exfiltrated.
- **Practice correlating across sources.** In real incidents, you'll often have firewall logs, web logs, PCAPs, and endpoint telemetry — all needing correlation.
# BT-07: The Archive Incident — Player Walkthrough

> **Difficulty:** IVORY (Expert)
> **Artifacts:** `archive_net.pcap` (PCAP) + `archive_linux.log` (Linux syslog) + `archive_win.evtx` (Windows Event XML)
> **Questions:** 5 (250–350 CP each)
> **Skills learned:** Three-artifact correlation, cross-OS attack reconstruction, CVE identification, detecting WinRM pivoting, inference-based analysis

This is the hardest Blue Team challenge. You have **three artifacts from three different sources** spanning a 4-hour incident across two operating systems (Linux and Windows). You must correlate evidence across all three to reconstruct the full attack chain.

---

## Prerequisites

- A machine with `grep`, `strings`, `python3`, and Wireshark (optional)
- The artifact files: `archive_net.pcap`, `archive_linux.log`, `archive_win.evtx`
- Understanding of Linux logs (BT-01/04), PCAP analysis (BT-03/06), and Windows Event logs (BT-05)

---

## Understanding the Artifacts

| File | Source | What it covers |
|------|--------|----------------|
| `archive_net.pcap` | Network capture | The HTTP exploit, document access, and WinRM pivot traffic |
| `archive_linux.log` | Linux syslog | The Flask service crash, attacker's shell, file access, outbound connection |
| `archive_win.evtx` | Windows Event XML | The post-pivot logon, mimikatz, SAM access, logoff |

**The attack spans two hosts:**
1. A **Linux Archive host** (exploited via a web vulnerability)
2. A **Windows host** (reached by pivoting from Linux via WinRM)

The three correlation anchors across all artifacts:
- **Attacker IP** — appears in the PCAP (exploit source)
- **Linux host IP** — appears in PCAP (exploit target + WinRM source) and Windows XML (4624 source IP)
- **CVE ID** — appears in PCAP (exploit payload) and Linux log (service crash message)

---

## Question 1 — What was the initial attack vector?

**Goal:** Identify how the attacker first compromised the system.

Look at the PCAP for the initial HTTP exploit traffic:

```bash
strings archive_net.pcap | grep "GET " | head -10
```

And look at the Linux log for evidence of a service crash/exploit:

```bash
grep -i "exception\|crash\|exploit\|CVE" archive_linux.log
```

The combination of an HTTP exploit request in the PCAP and a service crash in the Linux log indicates a **remote code execution** via a web exploit.

**Answer format:** `DZ{remote code execution}`

---

## Question 2 — What CVE was exploited?

**Goal:** Find the specific CVE identifier the attacker used.

The CVE appears in two places:

**In the PCAP** — the exploit's User-Agent or request path may contain the CVE:

```bash
strings archive_net.pcap | grep -i "CVE"
```

**In the Linux log** — the Flask service crash message references the CVE:

```bash
grep -i "CVE" archive_linux.log
```

The CVE will be in the format `CVE-YYYY-NNNNN`.

**Answer format:** `DZ{CVE-YYYY-NNNNN}`

---

## Question 3 — How did the attacker move from Linux to Windows?

**Goal:** Identify the method used to pivot from the Linux host to the Windows host.

Look in the PCAP for traffic from the Linux host to the Windows host on a non-standard port:

```bash
strings archive_net.pcap | grep -i "wsman\|winrm\|5985"
```

WinRM (Windows Remote Management) uses port **5985** (HTTP) or 5986 (HTTPS) and sends SOAP requests to the `/wsman` endpoint.

Also check the Linux log for evidence of an outbound connection:

```bash
grep -i "outbound\|connection" archive_linux.log
```

And check the Windows XML for a network logon (Event ID 4624, Logon Type 3) from the Linux host's IP:

```bash
grep "4624" archive_win.evtx
```

If the PCAP shows port 5985 + `/wsman`, and the Windows log shows a Type 3 logon from the Linux IP, the pivot method is **WinRM**.

**Answer format:** `DZ{WinRM}`

---

## Question 4 — What document was accessed in the Archive?

**Goal:** Find the name of the sensitive document the attacker read on the Linux host.

Look in the Linux log for file access events:

```bash
grep -i "file access\|audit" archive_linux.log
```

The log line will contain the full path to the document, like:
```
audit: file access by user archive-svc: /srv/archive/documents/founding_charter.pdf
```

The document name (just the filename, not the full path) is the answer.

You can also check the PCAP for a document download request:

```bash
strings archive_net.pcap | grep "download\|file="
```

**Answer format:** `DZ{filename.ext}`

---

## Question 5 — What was the attacker's final objective?

**Goal:** Infer the attacker's goal from the evidence on the Windows host.

This is an **inference question** — you must connect the dots from the Windows Event log evidence.

Look for these events in the Windows XML:

```bash
# Process creation — what tool did the attacker run?
grep -A5 "4688" archive_win.evtx | grep "NewProcessName"

# File/object access — what did they access?
grep -A5 "4656" archive_win.evtx | grep "ObjectName"
```

**Key evidence:**
- A 4688 event showing `mimikatz.exe` was launched → credential theft tool
- A 4656 event showing access to `C:\Windows\System32\config\SAM` → the SAM database contains password hashes

**Conclusion:** If the attacker ran mimikatz and accessed the SAM database, their objective was **credential theft** — stealing Windows password hashes for further lateral movement or cracking.

**Answer format:** `DZ{credential theft}`

---

## Summary

| Question | Source(s) | Technique | What you did |
|----------|-----------|-----------|-------------|
| Q1: Attack vector | PCAP + Linux log | Correlation | HTTP exploit + service crash = RCE |
| Q2: CVE | PCAP + Linux log | String search | Found CVE in exploit UA and crash message |
| Q3: Pivot method | PCAP + Windows XML | Correlation | Port 5985/`/wsman` in PCAP + 4624 Type 3 in XML = WinRM |
| Q4: Document | Linux log | Log parsing | Found file access audit line |
| Q5: Objective | Windows XML | Inference | mimikatz + SAM access = credential theft |

**Key takeaways:**
- **Three-artifact correlation is the peak of DFIR.** Real incidents span multiple systems, OS types, and evidence sources.
- **The same identifiers appear across sources.** The CVE is in both the PCAP and the Linux log. The Linux host IP is in both the PCAP and the Windows XML.
- **WinRM (port 5985, `/wsman`) is a common Linux-to-Windows pivot.** Learn to recognize it in PCAPs.
- **Some questions require inference.** Not every answer is a direct grep — sometimes you must connect multiple evidence points and draw a conclusion.
- **Mimikatz + SAM access = credential theft.** This is one of the most common Windows attack patterns. Memorize it.
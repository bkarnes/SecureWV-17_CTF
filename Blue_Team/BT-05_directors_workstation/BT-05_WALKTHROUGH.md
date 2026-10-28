# BT-05: The Director's Workstation — Player Walkthrough

> **Difficulty:** CRIMSON (Advanced)
> **Artifacts:** `Security_events.xml` + `System_events.xml` (Windows Event log XML exports)
> **Questions:** 5 (150–225 CP each)
> **Skills learned:** Windows Event ID analysis, identifying logon types, detecting lateral movement, registry persistence, credential dump tools, timeline reconstruction

This challenge gives you Windows Event logs (exported as XML). You must analyze them to reconstruct an attack on an executive's workstation. Windows Event logs are structured differently from Linux logs — they use numeric Event IDs to categorize events.

---

## Prerequisites

- A machine with a text editor or XML viewer (or `grep`/`python3` on Linux)
- The artifact files `Security_events.xml` and `System_events.xml`
- Basic understanding of Windows security events

---

## Understanding Windows Event IDs

Windows Event logs use numeric **Event IDs** to categorize events. Here are the key ones you'll need:

| Event ID | Meaning | What it tells you |
|----------|---------|-------------------|
| **4624** | Successful logon | Who logged in, from where, and how (Logon Type) |
| **4634** | Logoff | When a user's session ended |
| **4688** | Process creation | A new process was started (command, path) |
| **4657** | Registry modification | A registry key was changed |
| **4663** | File access | A file was accessed |
| **7036** | Service state change | A Windows service started or stopped |

**Logon Types** (in the 4624 event's `LogonType` field):
- **Type 2** — Interactive (physical login at the keyboard)
- **Type 3** — Network (remote access via SMB, WinRM, etc.)
- **Type 10** — Remote Interactive (RDP)

Let's look at the XML structure:

```bash
head -30 Security_events.xml
```

Each event is an `<Event>` element containing a `<System>` section (with EventID, timestamp, channel) and an `<EventData>` section (with named fields like `TargetUserName`, `IpAddress`, `NewProcessName`, etc.).

---

## Question 1 — What Event ID indicates the initial logon?

**Goal:** Identify which Event ID corresponds to the attacker's initial login.

Look for logon events in the Security log:

```bash
grep "EventID" Security_events.xml | sort | uniq -c | sort -rn
```

This counts how many of each Event ID appear. Event ID **4624** (successful logon) will be the most common.

The initial logon is a **4624** event — it's the standard Windows logon event.

**Answer format:** `DZ{4624}`

---

## Question 2 — What process was used for lateral movement?

**Goal:** Find the process the attacker used to move to or from this workstation.

Look for process creation events (Event ID 4688):

```bash
grep -A5 "EventID>4688" Security_events.xml | grep "NewProcessName"
```

Look for a process associated with lateral movement — tools like `PsExec64.exe`, `wmic.exe`, `powershell.exe`, or `wsmprovhost.exe` (WinRM). These are commonly used for remote execution.

The key is finding a 4688 event at an unusual time (off-hours) with a process known for lateral movement. The process name (without the full path) is the answer.

**Answer format:** `DZ{process.exe}`

---

## Question 3 — What registry key was modified for persistence?

**Goal:** Find the registry key the attacker modified to maintain persistence.

Look for registry modification events (Event ID 4657):

```bash
grep -A5 "EventID>4657" Security_events.xml | grep "ObjectName"
```

**What is registry persistence?** Attackers add entries to the Windows `Run` or `RunOnce` registry keys so their malware executes automatically when the system boots or a user logs in.

The key paths to look for:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`

Find the 4657 event with one of these paths. The full path (including the value name appended) is the answer.

**Answer format:** `DZ{HKLM\SOFTWARE\...\Run\ValueName}`

---

## Question 4 — What tool was used to dump credentials?

**Goal:** Identify the credential theft tool the attacker ran.

Look for 4688 (process creation) events that occurred AFTER the logon. Look for known credential dump tools:

```bash
grep -A5 "EventID>4688" Security_events.xml | grep -i "NewProcessName"
```

Known credential dump tools:
- **mimikatz.exe** — The most famous Windows credential dump tool
- **procdump.exe** — Can dump LSASS memory
- **sekurlsa.exe** — A mimikatz module

The tool name appears in the `NewProcessName` field. It's usually in the user's Downloads directory, not in a standard system path.

**Answer format:** `DZ{toolname.exe}`

---

## Question 5 — At what time (UTC) did the attacker first access the Director's files?

**Goal:** Find the exact timestamp when the attacker first accessed the Director's documents.

Look for file access events (Event ID 4663):

```bash
grep -B5 "EventID>4663" Security_events.xml | grep "TimeCreated"
```

Or look for 4663 events that reference the Director's documents:

```bash
grep -A5 "EventID>4663" Security_events.xml | grep "ObjectName"
```

Find the 4663 event where the `ObjectName` contains the Director's documents path (e.g., `C:\Users\ceo\Documents\...`). The timestamp is in the `<TimeCreated SystemTime="...">` attribute.

The time is in ISO-8601 UTC format, like `2026-08-22T01:21:56Z`.

**Answer format:** `DZ{2026-XX-XXTHH:MM:SSZ}`

---

## Summary

| Question | Technique | What you did |
|----------|-----------|-------------|
| Q1: Event ID | Event ID knowledge | 4624 = successful logon |
| Q2: Lateral tool | Process creation (4688) | Found non-standard process at off-hours |
| Q3: Registry key | Registry modification (4657) | Found Run/RunOnce key modification |
| Q4: Cred dump tool | Process creation (4688) | Found mimikatz/procdump in Downloads |
| Q5: File access time | File access (4663) + timestamp | Found Director's document access, read timestamp |

**Key takeaways:**
- **Learn the key Windows Event IDs.** 4624 (logon), 4688 (process creation), 4657 (registry), 4663 (file access) cover most attack scenarios.
- **Logon Type tells you how.** Type 2 = at the keyboard; Type 3 = network (remote); Type 10 = RDP.
- **Off-hours activity is suspicious.** If events happen at 1 AM that involve lateral movement tools and credential dumpers, it's an attack.
- **Registry Run keys are the most common persistence.** Always check for modifications to `...\CurrentVersion\Run`.
- **Timestamps matter.** The exact time of file access can be critical for incident response timelines.
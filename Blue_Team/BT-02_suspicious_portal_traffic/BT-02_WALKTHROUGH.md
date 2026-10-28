# BT-02: Suspicious Portal Traffic — Player Walkthrough

> **Difficulty:** AMBER (Beginner)
> **Artifact:** `bt02_access.log` (Nginx web server access log)
> **Questions:** 4 (75–125 CP each)
> **Skills learned:** Web access log analysis, identifying SQL injection patterns, recognizing attack tools by User-Agent, extracting exfiltrated data from request payloads

This challenge gives you a web server's access log and asks you to identify a SQL injection attack. You'll learn to read Nginx access logs, recognize attack signatures, and trace what data the attacker stole.

---

## Prerequisites

- A Linux machine with `grep`, `awk`, and a text editor
- The artifact file `bt02_access.log`
- Basic understanding of HTTP requests and web logs

---

## Understanding the Artifact

The `bt02_access.log` file is in **Nginx combined log format**. Each line represents one HTTP request:

```
10.10.3.11 - - [22/Aug/2026:14:23:17 +0000] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0..."
```

Breaking down the fields:
- `10.10.3.11` — Client IP address
- `- -` — Remote user (usually blank)
- `[22/Aug/2026:14:23:17 +0000]` — Timestamp
- `"GET /index.html HTTP/1.1"` — HTTP method + path + protocol
- `200` — HTTP status code (200 = OK, 404 = Not Found, 500 = Server Error)
- `2048` — Response size in bytes
- `"-"` — Referer
- `"Mozilla/5.0..."` — User-Agent string (identifies the client/browser)

Let's look at some lines:

```bash
head -10 bt02_access.log
```

Most lines will be normal browsing traffic — GET requests for pages with 200 status codes. But somewhere in the log, there's an attack.

---

## Question 1 — What type of attack is present in the logs?

**Goal:** Identify the attack type by looking for suspicious patterns in the request URLs.

Look for unusual query strings — especially ones containing SQL keywords:

```bash
grep -i "UNION" bt02_access.log
grep -i "SELECT" bt02_access.log
grep "'" bt02_access.log | head -10
grep "\-\-" bt02_access.log | head -10
```

**What are we looking for?** SQL injection payloads in the URL query strings. Common signatures:
- `'` (single quote — breaks out of a SQL string)
- `UNION SELECT` — combines results from multiple tables
- `--` (SQL comment — ignores the rest of the query)
- `OR '1'='1'` — always-true condition

If you see these patterns in the request URLs, the attack is **SQL injection**.

**Answer format:** `DZ{SQL injection}`

---

## Question 2 — What parameter was targeted?

**Goal:** Identify which query parameter the attacker injected into.

Look at the SQL injection requests you found:

```bash
grep -i "UNION" bt02_access.log | head -5
```

The URL will look like:
```
GET /enroll?record_id=-1 UNION SELECT 1,2,3,4-- HTTP/1.1
```

The parameter name appears before the `=` sign: `record_id` (or `applicant_id`, `user_id`, etc. — it varies per event).

**Answer format:** `DZ{parameter_name}`

---

## Question 3 — What was the attacker's user-agent string?

**Goal:** Identify the tool the attacker used, which appears in the User-Agent field.

**What is a User-Agent?** The User-Agent string identifies the client software making the HTTP request. Normal browsers send strings like `Mozilla/5.0 (Windows NT 10.0...)`. Attack tools often send distinctive User-Agents that identify them.

Look for unusual User-Agents:

```bash
grep -oE '"[^"]*"$' bt02_access.log | sort | uniq -c | sort -rn | head -10
```

**What this does:**
- `grep -oE '"[^"]*"$'` — extracts the last quoted field (the User-Agent)
- `sort | uniq -c | sort -rn` — counts and sorts by frequency

Look for a User-Agent that stands out — something like `sqlmap/1.7.8#stable (http://sqlmap.org)` or `python-requests/2.31.0`. The attack tool's User-Agent will appear on the attack requests specifically:

```bash
grep -i "UNION" bt02_access.log | grep -oE '"[^"]*"$' | sort -u
```

**Answer format:** `DZ{user-agent string}` (the full string)

---

## Question 4 — What data did the attacker successfully extract?

**Goal:** Determine which database table the attacker dumped.

Look at the final exfiltration requests — the ones with `UNION SELECT ... FROM`:

```bash
grep -i "UNION.*FROM" bt02_access.log
```

The `FROM` clause names the table the attacker extracted data from:

```
GET /enroll?record_id=-1 UNION SELECT id,username,password_hash,email FROM citizen_registry-- HTTP/1.1
```

The table name after `FROM` is the answer (e.g., `citizen_registry`, `quorum_enrollment`, etc.).

**Answer format:** `DZ{table_name}`

---

## Summary

| Question | Technique | What you did |
|----------|-----------|-------------|
| Q1: Attack type | Pattern matching | Found `UNION`, `SELECT`, `'`, `--` in URLs → SQL injection |
| Q2: Parameter | URL parsing | Found the parameter name before `=` in attack URLs |
| Q3: User-Agent | Frequency analysis | Identified the unusual UA on attack requests (e.g., sqlmap) |
| Q4: Data extracted | Payload analysis | Read the `FROM` clause in the UNION SELECT payloads |

**Key takeaways:**
- **Web access logs are rich forensic evidence.** Every HTTP request is recorded with full details.
- **SQL injection has clear signatures.** Look for `UNION`, `SELECT`, `'`, `--`, `OR 1=1` in query strings.
- **Attack tools identify themselves in the User-Agent.** sqlmap, nmap, and other tools leave distinctive signatures.
- **The attack payload tells you what was stolen.** Read the SQL query in the URL to see which table was targeted.
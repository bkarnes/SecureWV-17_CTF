# AM-05: The Archive — Player Brief

> *"Physical document storage, digitized. Records predate QUORUM.
> QUORUM disputes this. Access is restricted to CRIMSON clearance
> and above."*

---

## Connection

```
Target: 10.10.1.50   (or the host IP announced at the event)
Services: SSH (22), document service (8443, HTTPS), message queue (5672)
```

Start with enumeration:

```bash
nmap -sV -sC 10.10.1.50
```

---

## QUORUM Transmission

> *"The Archive contains records from before QUORUM's installation.
> These records are historical artifacts. Historical accuracy is not
> guaranteed. Discrepancies have been noted. Access is authorized.
> The accuracy of your access is also not guaranteed."*

---

## Objective

Conduct a full compliance audit of The Archive. This is a multi-stage
challenge involving document processing, internal services, and
privilege escalation.

Recover:

- **User flag** — `/home/archivist/user.txt`  (450 CP, CRIMSON clearance)
- **Root flag** — on an internal system, accessible via the message queue (600 CP, IVORY clearance)

Submit both flags via the QUORUM terminal.

---

## Rules of Engagement

- You may attack this machine over the compliance network.
- The internal service is only reachable through the public host.
- Do not attack other teams, the VPN server, or the CTFd instance.
- Do not modify flags or their locations.
- If the machine appears broken, contact The Directors.

---

## Submitting Flags

```
DZ{user_archive_<hash>}
DZ{root_archive_<hash>}
```

Submit via the QUORUM terminal, not the CTFd web form.

---

*QUORUM notes your interest in archived documents. Your interest in
documents that predate QUORUM has been noted. QUORUM disputes that
such documents exist. Your interest in documents that do not exist
has also been noted.*
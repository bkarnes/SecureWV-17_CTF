# AM-04: R&D Annex (Provisional) — Player Brief

> *"Research and Development. Listed as provisional since founding.
> Tools issued here may behave unexpectedly. QUORUM accepts no liability."*

---

## Connection

```
Target: 10.10.1.40   (or the host IP announced at the event)
Services: HTTP (80), SSH (2220), API (3000)
```

Start with enumeration:

```bash
nmap -sV -sC 10.10.1.40
```

---

## QUORUM Transmission

> *"This system has been designated for audit. R&D tools may behave
> unexpectedly. Your audit is authorized. Unexpected behavior is also
> authorized. Both are noted."*

---

## Objective

Conduct a full compliance audit of the R&D Annex. Recover:

- **User flag** — `/home/researcher/user.txt`  (300 CP, TEAL clearance)
- **Root flag** — `/root/root.txt`             (400 CP, CRIMSON clearance)

Submit both flags via the QUORUM terminal. The root flag requires the
user flag as a prerequisite.

---

## Rules of Engagement

- You may attack this machine over the compliance network.
- Do not attack other teams, the VPN server, or the CTFd instance.
- Do not modify flags or their locations — read them, leave them in place.
- If the machine appears broken, contact The Directors.

---

## Submitting Flags

```
DZ{user_rd_annex_<hash>}
DZ{root_rd_annex_<hash>}
```

Submit via the QUORUM terminal, not the CTFd web form.

---

*QUORUM notes your interest in R&D tooling. Your interest has been
noted. The tools may behave unexpectedly. Your interest in unexpected
behavior has also been noted. Both are expected.*
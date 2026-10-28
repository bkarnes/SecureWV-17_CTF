# AM-01: The Lobby Terminal — Player Brief

> *All citizens begin here. The Lobby Terminal processes enrollment
> requests. QUORUM has noted irregular query patterns.*

---

## Connection

```
Target: 10.10.1.10   (or the host IP announced at the event)
Services: HTTP (80), SSH (22)
```

Start with enumeration:

```bash
nmap -sV -sC 10.10.1.10
```

---

## QUORUM Transmission

> *This system has been designated as anomalous. Full compliance audit
> is authorized. Report all findings using Form IC-7 (Superseded).
> Form IC-7 is no longer available.*

---

## Objective

Conduct a full compliance audit of the Lobby Terminal. Recover:

- **User flag** — `/home/<user>/user.txt`  (150 CP, PROVISIONAL clearance)
- **Root flag** — `/root/root.txt`         (200 CP, AMBER clearance)

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
DZ{user_lobby_<hash>}
DZ{root_lobby_<hash>}
```

Submit via the QUORUM terminal, not the CTFd web form.

---

*QUORUM notes your interest in this terminal. Your interest has been
noted.*
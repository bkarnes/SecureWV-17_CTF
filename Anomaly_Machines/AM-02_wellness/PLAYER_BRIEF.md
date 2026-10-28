# AM-02: Wellness Observation Center — Player Brief

> *"Citizens are reminded that the Wellness Observation Center does not
> exist. This machine does not exist. Please proceed."*

---

## Connection

```
Target: 10.10.1.20   (or the host IP announced at the event)
Services: FTP (21), SSH (22), HTTP (8080)
```

Start with enumeration:

```bash
nmap -sV -sC 10.10.1.20
```

---

## QUORUM Transmission

> *"This system has been flagged for routine wellness observation. No
> incidents have been recorded. There is nothing to audit. Your audit
> is authorized. These statements are not contradictory."*

---

## Objective

Conduct a full compliance audit of the Wellness Observation Center.
Recover:

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
DZ{user_wellness_<hash>}
DZ{root_wellness_<hash>}
```

Submit via the QUORUM terminal, not the CTFd web form.

---

*QUORUM has reviewed your interest in this facility. Your interest has
been noted. This facility does not exist. Your interest in a facility
that does not exist has also been noted.*
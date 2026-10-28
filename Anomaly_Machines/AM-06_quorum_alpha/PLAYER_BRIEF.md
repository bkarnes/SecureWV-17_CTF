# AM-06: QUORUM Subsystem Alpha — Player Brief

> *"This system is not listed in the administrative index. QUORUM has
> no record of it. Players who reach this machine are encouraged to
> reconsider."*

---

## Connection

```
Target: 10.10.1.60   (or the host IP announced at the event)
Services: SSH (22), custom service (31337)
```

Start with enumeration:

```bash
nmap -sV -sC 10.10.1.60
```

---

## QUORUM Transmission

> *"QUORUM Subsystem Alpha is not listed in any administrative index.
> Its existence has not been confirmed. It has not been denied either.
> Both options are under review. Access requires IVORY clearance.
> Your clearance has been verified. Proceed. Reconsidering is optional.
> Reconsidering is also noted."*

---

## Objective

Conduct a full compliance audit of QUORUM Subsystem Alpha. This is the
most challenging audit in the Construct. It requires multiple stages
of exploitation.

Recover:

- **User flag** — `/home/operator/user.txt`  (600 CP, IVORY clearance)
- **Root flag** — `/root/root.txt`             (800 CP, COBALT clearance)

Submit both flags via the QUORUM terminal.

---

## Rules of Engagement

- You may attack this machine over the compliance network.
- Do not attack other teams, the VPN server, or the CTFd instance.
- Do not modify flags or their locations.
- If the machine appears broken, contact The Directors.
- You are encouraged to reconsider. Reconsidering is noted.

---

## Submitting Flags

```
DZ{user_quorum_alpha_<hash>}
DZ{root_quorum_alpha_<hash>}
```

Submit via the QUORUM terminal, not the CTFd web form.

---

*QUORUM has reviewed your access to this system. QUORUM has no record
of this system. Your access to a system QUORUM has no record of has
been noted. The record of this noting has also been noted. This is
consistent. QUORUM is always consistent.*
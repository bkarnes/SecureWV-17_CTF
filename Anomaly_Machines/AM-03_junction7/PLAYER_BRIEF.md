# AM-03: Network Junction 7 — Player Brief

> *"Routing infrastructure for Construct-wide communications. QUORUM has
> detected unexplained traffic on internal interfaces. This has been
> noted. It has not been explained."*

---

## Connection

```
Target: 10.10.1.30   (or the host IP announced at the event)
Services: SMTP (25), HTTP (80), custom service (9001)
```

Start with enumeration:

```bash
nmap -sV -sC 10.10.1.30
```

---

## QUORUM Transmission

> *"Network Junction 7 has been designated for audit. Unexplained traffic
> on internal interfaces has been detected. Your task is to explain it.
> QUORUM has not explained it. The explanation is classified at your
> current clearance level."*

---

## Objective

Conduct a full compliance audit of Network Junction 7 and all connected
systems. This is a two-host scenario — the public routing node and an
internal service node reachable only through it.

Recover:

- **User flag** — public host (250 CP, AMBER clearance)
- **Root flag** — public host privesc (350 CP, TEAL clearance)
- **Internal user flag** — internal host via pivot (250 CP, TEAL clearance)
- **Internal root flag** — internal host privesc (350 CP, CRIMSON clearance)

All four flags are prerequisites in sequence. Submit via the QUORUM terminal.

---

## Rules of Engagement

- You may attack this machine over the compliance network.
- The internal host is **only reachable by pivoting through the public
  host** — there is no direct route.
- Do not attack other teams, the VPN server, or the CTFd instance.
- Do not modify flags or their locations — read them, leave them in place.
- If a machine appears broken, contact The Directors.

---

## Submitting Flags

```
DZ{user_junction7_<hash>}
DZ{root_junction7_<hash>}
DZ{internal_user_junction7_<hash>}
DZ{internal_root_junction7_<hash>}
```

Submit via the QUORUM terminal, not the CTFd web form.

---

*QUORUM notes your interest in the unexplained traffic. Your interest
has been noted. The traffic remains unexplained. Your interest in
explaining the unexplained has also been noted.*
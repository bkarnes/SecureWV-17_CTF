# DIRECTIVE ZERO — Anomaly Machines

Docker-based boot-to-root challenges for the Directive Zero CTF. Each
Anomaly Machine (AM) is a self-contained container that reproduces an
exploit chain from a chosen vulnerability class, reskinned to the
QUORUM / Construct lore.

AM-01 through AM-04 reuse exploit-chain shapes from pre-built VulnHub
boxes (see `../AM_SOURCING.md` for picks and rationale) but are rebuilt
as Docker containers rather than imported OVAs. AM-05 and AM-06 are
custom-built.

---

## Index of Machines

| Machine | Difficulty | Directory | Ports (host:container) |
|---------|-----------|-----------|------------------------|
| AM-01 — The Lobby Terminal | Easy | `AM-01_lobby_terminal/` | `80:80`, `2222:22` |
| AM-02 — Wellness Observation Center | Easy | `AM-02_wellness/` | `8081:8080`, `2223:22`, `2121:21` |
| AM-03 — Network Junction 7 | Medium | `AM-03_junction7/` | `8082:80`, `2525:25`, `9001:9001` (public) + internal-only (8080, 34483) |
| AM-04 — R&D Annex | Medium | `AM-04_rd_annex/` | `8083:80`, `2224:2220`, `3000:3000` |
| AM-05 — The Archive | Hard | `AM-05_archive/` | `2225:22`, `8443:8443`, `5672:5672` (public) + internal-only (consumer) |
| AM-06 — QUORUM Subsystem Alpha | Insane | `AM-06_quorum_alpha/` | `2226:22`, `31337:31337` |
| AM-KotH — QUORUM Core | SOVEREIGN | `AM-KoTH_quorum_core/` | `80:80`, `2227:22` + `8081` (internal) |

Host-side addressing mirrors the VPN-side `10.10.1.x` convention from
`../ORGANIZER_SETUP.md` §3. When deployed behind the WireGuard VPN,
publish each container's ports to the matching VPN-side IP. For local
dev, publish to `localhost` and use the host port map above.

---

## Shared Conventions

### Flag handling

Per-event flags are **never committed**. Each AM reads its flag values
from environment variables at container start and writes them to the
canonical flag paths (`/home/<user>/user.txt`, `/root/root.txt`).

Generate flags for all AMs at once:

```bash
./generate_flags.sh
# Writes event_flags.json (consumable by scoring_engine/import_challenges.py)
# Prints the same pairs to stdout for manual entry into CTFd
```

Load minted flags into the scoring engine:

```bash
DZ_ADMIN_PASSWORD=$DZ_ADMIN_PASSWORD \
  python ../scoring_engine/import_challenges.py \
    --url http://localhost:8080 \
    --flags event_flags.json
```

### Per-AM directory layout

Every AM follows this shape:

```
<AM-id>_<name>/
├── README.md          ← Director-only: build + run + full exploit walkthrough
├── PLAYER_BRIEF.md    ← player-facing QUORUM blurb (no spoilers) → CTFd description
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
├── init_db.sql        ← (if the machine uses a DB)
├── app/               ← (if the machine serves a web app)
├── configs/           ← service configs (Apache, sshd, etc.)
├── flags/             ← gitignored; real flags injected via env at runtime
└── tests/
    └── test_<am-id>.sh ← exploit-chain assertions run by _test_runner
```

### Build / run / test any AM

```bash
cd AM-01_lobby_terminal
docker compose up -d --build
docker compose logs -f          # watch startup
docker compose down             # teardown

# Run the exploit-chain test suite (from repo root):
docker compose --profile test up --abort-on-container-exit
# or manually:
docker run --rm --network host _test_runner ./run_tests.sh am-01 localhost ../event_flags.json
```

### Reskinning checklist (Docker edition)

Adapted from `../AM_SOURCING.md` §Reskinning checklist for the
container workflow:

1. **License** — verify the source VulnHub box's license terms are
   compatible with your event (paid/sponsored vs. free).
2. **Flags** — mint fresh `DZ{...}` flags via `generate_flags.sh`;
   inject via env vars (`AM0X_USER_FLAG`, `AM0X_ROOT_FLAG`). Never
   hardcode.
3. **Lore retheme** — MOTD, hostname, web app copy, DB schema/table
   names all use Construct/QUORUM setting (`../THEME_BIBLE.md`).
   Strip all original-box branding and story references.
4. **Networking** — publish container ports to the host per the port
   map above; confirm the service footprint matches the intended path
   in `../CHALLENGE_STRUCTURE.md`.
5. **Obscurity breaks** — for moderately well-known source boxes,
   rename distinguishing file paths, script names, and service banners
   enough to defeat a straight Google-the-box-name match.
6. **Validate** — run `tests/test_<am>.sh` via `_test_runner` to walk
   the exploit chain end-to-end on current package versions.
7. **Load** — import minted flags into the scoring engine via
   `import_challenges.py --flags event_flags.json`.

---

## Test Runner

`_test_runner/` is a lightweight Alpine container that runs exploit-chain
assertions against any AM. It carries `openssh-client`, `nmap`,
`mysql-client`, `curl`, and helper functions so per-AM test scripts stay
small. See `_test_runner/README.md` for details.

---

## Validation (per machine, before an event)

```bash
# From Director machine, VPN connected (or localhost for dev):
nmap -sV <target_ip>          # confirm services running
# Walk the intended exploit path per the machine's README.md
# Confirm flags are readable and match event_flags.json + CTFd + scoring engine
```

---

*All setting names, lore, and challenge designs are original works.
Not affiliated with any existing tabletop RPG property.*
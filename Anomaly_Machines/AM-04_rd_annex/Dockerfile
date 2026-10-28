# DIRECTIVE ZERO — AM-04: R&D Annex (Provisional)
# Medium. Boot-to-root Docker container.
#
# Exploit chain (reproduced from the /dev/random: Pipe VulnHub shape):
#   1. Enumerate: HTTP (80, Basic Auth), SSH (2220, locked down), API (3000)
#   2. Recon: non-standard HTTP verb bypasses Basic Auth -> page source
#      reveals JS serialization + /scriptz/ dir; API on 3000 leaks /scriptz/
#   3. Gadget: /scriptz/log.php.BAK reveals Log::__destruct() file-write gadget
#   4. Foothold: craft serialized Log object -> POST param -> webshell -> RCE
#   5. Privesc: root cron runs tar cfz ... * in world-writable /home/researcher/backup/
#      -> --checkpoint-action wildcard exploit -> SUID dash -> root
#
# Flags are injected via env vars at runtime (never baked in):
#   AM04_USER_FLAG, AM04_ROOT_FLAG
#
# See README.md for the full Director walkthrough.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2 \
      php \
      libapache2-mod-php \
      openssh-server \
      python3 \
      cron \
      netcat-openbsd \
      tar \
      coreutils \
      net-tools \
      iputils-ping \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Apache: enable php module ───────────────────────────────────────────────
RUN a2enmod php8.1 2>/dev/null || a2enmod php || true \
 && a2enmod rewrite 2>/dev/null || true \
 && a2dissite 000-default 2>/dev/null || true

# ── researcher user (home owns the world-writable backup dir) ──────────────
RUN useradd -m -s /bin/bash researcher \
 && mkdir -p /home/researcher/backup /home/researcher/.ssh /run/sshd \
 && chmod 777 /home/researcher/backup

# ── Web app ─────────────────────────────────────────────────────────────────
COPY app/            /var/www/html/
COPY configs/        /tmp/configs/

# scriptz/ must be writable by www-data so the Log::__destruct() gadget
# can file_put_contents the webshell there via the HTTP deserialization path.
RUN chmod 777 /var/www/html/scriptz

# ── API on port 3000 ────────────────────────────────────────────────────────
COPY api/            /opt/rd/api/
RUN chmod +x /opt/rd/api/rd_api.py

# ── Cron scripts ───────────────────────────────────────────────────────────
COPY cron/rd_backup.sh     /usr/local/bin/rd_backup.sh
COPY cron/create_backup.sh /root/create_backup.sh
RUN chmod 755 /usr/local/bin/rd_backup.sh \
 && chmod 700 /root/create_backup.sh

# ── Hostname + MOTD retheme ─────────────────────────────────────────────────
RUN echo "rd-annex" > /etc/hostname \
 && printf '%s\n' \
    '  ┌────────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM CONSTRUCT — R&D ANNEX (PROVISIONAL)              AM-04 │' \
    '  │  "Listed as provisional since founding. Tools issued here      │' \
    '  │   may behave unexpectedly. QUORUM accepts no liability."       │' \
    '  └────────────────────────────────────────────────────────────────┘' \
    > /etc/motd

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80 2220 3000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
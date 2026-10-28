# DIRECTIVE ZERO — AM-KotH: QUORUM Core
# SOVEREIGN tier. King-of-the-Hill container.
#
# Exploit chain:
#   1. Web command injection in diagnostic.php (runs as quorum-svc)
#   2. SUID quorum-diag binary with arg injection -> root shell
#   3. Read /root/koth_flag.txt (the rotating KoTH flag)
#   4. Submit flag to scoring engine POST /api/koth/capture
#
# Flag rotation: the scoring engine pushes new flags to the internal
# webhook on port 8081 (not published to players). The flag file is
# /root/koth_flag.txt, owned by root, mode 0600.
#
# Env vars:
#   KOTH_INITIAL_FLAG  — first flag value (rotated thereafter)
#   KOTH_FLAG_SECRET   — shared secret for the webhook auth

FROM debian:11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    PYTHONUNBUFFERED=1

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2 \
      libapache2-mod-php \
      php \
      openssh-server \
      python3 \
      python3-flask \
      gcc \
      libc6-dev \
      iputils-ping \
      net-tools \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── quorum-svc user (web service runs as this user) ────────────────────────
RUN useradd -m -s /bin/bash quorum-svc \
    && mkdir -p /run/sshd

# ── Web console ────────────────────────────────────────────────────────────
COPY src/console/ /var/www/html/
RUN rm -f /var/www/html/index.html \
    && chown -R quorum-svc:quorum-svc /var/www/html

# ── Apache: run PHP as quorum-svc (not www-data) ──────────────────────────
RUN sed -i 's/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=quorum-svc/' /etc/apache2/envvars \
    && sed -i 's/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=quorum-svc/' /etc/apache2/envvars

# ── SSH: enable password auth ──────────────────────────────────────────────
RUN sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# ── SUID quorum-diag binary ────────────────────────────────────────────────
COPY src/quorum-diag.c /tmp/quorum-diag.c
RUN gcc -o /usr/local/bin/quorum-diag /tmp/quorum-diag.c \
    && rm /tmp/quorum-diag.c \
    && chown root:root /usr/local/bin/quorum-diag \
    && chmod 4755 /usr/local/bin/quorum-diag

# ── Flag webhook service ──────────────────────────────────────────────────
COPY src/flag_service.py /opt/flag_service.py
RUN chmod 755 /opt/flag_service.py

# ── Entrypoint ─────────────────────────────────────────────────────────────
COPY src/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# ── Hostname + MOTD ────────────────────────────────────────────────────────
RUN echo "quorum-core" > /etc/hostname \
    && printf '%s\n' \
    '  ┌──────────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM CORE — SOVEREIGN TIER                            AM-KotH │' \
    '  │  "You no longer exist in official records."                      │' \
    '  │  This is not reassuring.                                         │' \
    '  │  All activity is logged. Logging is mandatory.                   │' \
    '  └──────────────────────────────────────────────────────────────────┘' \
    > /etc/motd

EXPOSE 80 22

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
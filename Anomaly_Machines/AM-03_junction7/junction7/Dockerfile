# DIRECTIVE ZERO — AM-03: Network Junction 7 (public host)
# Medium. Boot-to-root Docker container — the public-facing routing node.
#
# Exploit chain (reproduced from the WinterMute Straylight shape):
#   1. Enumerate: SMTP (25, Postfix), HTTP (80, Apache+PHP), routing service (9001)
#   2. Recon: custom service on 9001 leaks the hidden /junction-bolo/ path
#   3. Foothold: LFI in bolo.php -> SMTP log poisoning on port 25 -> RCE as www-data
#   4. Privesc: root-run cron job executes a world-writable script -> root
#   5. Pivot: discover the internal network interface -> scan for junction7-internal
#
# Flags are injected via env vars at runtime (never baked in):
#   AM03_USER_FLAG, AM03_ROOT_FLAG
#
# See README.md for the full Director walkthrough.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      postfix \
      apache2 \
      php \
      libapache2-mod-php \
      python3 \
      cron \
      socat \
      net-tools \
      iputils-ping \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Apache: enable php module ───────────────────────────────────────────────
RUN a2enmod php8.1 2>/dev/null || a2enmod php || true \
 && a2dissite 000-default 2>/dev/null || true

# ── PHP: display errors so the LFI warning is visible to players ───────────
# When bolo.php tries to include a nonexistent file (e.g. ?bolo=test),
# players should see the PHP Warning confirming the include path.
RUN echo "display_errors = On" > /etc/php/8.1/apache2/conf.d/30-display-errors.ini 2>/dev/null \
 || echo "display_errors = On" > /etc/php/7.4/apache2/conf.d/30-display-errors.ini 2>/dev/null \
 || true

# ── Filesystem layout ───────────────────────────────────────────────────────
COPY app/            /var/www/html/junction-bolo/
COPY app/index.php   /var/www/html/index.php
RUN rm -f /var/www/html/index.html
COPY configs/        /tmp/configs/
COPY routing_status/  /opt/junction/routing_status/
COPY cron/            /opt/junction/
COPY entrypoint.sh    /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# ── Postfix config (relaxed for log-poisoning foothold) ─────────────────────
COPY configs/postfix_main.cf /etc/postfix/main.cf

# ── Cron privesc artifact: world-writable script run as root ────────────────
# The routing_updater.sh is world-writable (intentional misconfig: "Directors
# may modify routing criteria as infrastructure evolves"). A root cron job
# runs it every minute. Players overwrite it to read the root flag.
RUN chmod 777 /opt/junction/routing_updater.sh

# ── Hostname + MOTD retheme (Construct / QUORUM) ───────────────────────────
RUN echo "junction7" > /etc/hostname \
 && printf '%s\n' \
    '  ┌───────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM CONSTRUCT — NETWORK JUNCTION 7                 AM-03  │' \
    '  │  "Routing infrastructure for Construct-wide communications."  │' \
    '  │  "QUORUM has detected unexplained traffic on internal         │' \
    '  │   interfaces. This has been noted. It has not been explained."│' \
    '  └───────────────────────────────────────────────────────────────┘' \
    > /etc/motd

EXPOSE 25 80 9001

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
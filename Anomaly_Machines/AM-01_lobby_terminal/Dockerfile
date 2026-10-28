# DIRECTIVE ZERO — AM-01: The Lobby Terminal
# Easy. Boot-to-root Docker container.
#
# Exploit chain (reproduced from the SkyTower VulnHub shape):
#   1. SQLi auth bypass on the enrollment portal login form
#   2. Second-order command injection in the dashboard "update email" field
#   3. www-data reads app config -> MariaDB creds -> dump `login` table
#   4. SSH in as `compliance` (creds from the DB) -> user flag
#   5. sudo misconfig: NOPASSWD on a world-writable audit script -> root flag
#
# Flags are injected via env vars at runtime (never baked in):
#   AM01_USER_FLAG, AM01_ROOT_FLAG
#
# See README.md for the full Director walkthrough.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2 \
      libapache2-mod-php \
      php \
      php-mysql \
      mariadb-server \
      openssh-server \
      sudo \
      net-tools \
      iputils-ping \
      curl \
      wget \
      ca-certificates \
      sendmail-bin \
    && rm -rf /var/lib/apt/lists/*

# ── Apache: enable php module, drop default vhost ──────────────────────────
RUN a2enmod php8.1 2>/dev/null || a2enmod php || true \
 && a2dissite 000-default 2>/dev/null || true

# ── Filesystem layout ───────────────────────────────────────────────────────
# Web app lives at /var/www/html/app (Apache docroot set in configs/).
# init_db.sql is loaded by the entrypoint on first start.
COPY app/        /var/www/html/app/
COPY configs/    /tmp/configs/
COPY init_db.sql /tmp/init_db.sql
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# ── Compliance user (SSH target, owns user flag) ────────────────────────────
RUN useradd -m -s /bin/bash compliance \
 && mkdir -p /run/sshd

# ── Privesc artifact: world-writable audit script run via sudo ──────────────
# The sudoers entry lets `compliance` run /usr/local/bin/run_audit.sh as
# root with no password. The script is world-writable (intentional
# misconfig: "Directors may update the audit tool"). Players edit it to
# read /root/root.txt or spawn a root shell.
RUN printf '#!/bin/bash\n# QUORUM compliance audit runner\n# Directors may modify this script as audit criteria evolve.\necho "[run_audit] scanning..."\n' \
      > /usr/local/bin/run_audit.sh \
 && chmod 777 /usr/local/bin/run_audit.sh \
 && echo 'compliance ALL=(ALL) NOPASSWD: /usr/local/bin/run_audit.sh' \
      > /etc/sudoers.d/compliance-audit \
 && chmod 0440 /etc/sudoers.d/compliance-audit

# ── MariaDB data dir (initialized by entrypoint) ───────────────────────────
RUN mkdir -p /var/lib/mysql /run/mysqld \
 && chown -R mysql:mysql /var/lib/mysql /run/mysqld

# ── Hostname + MOTD retheme (Construct / QUORUM) ───────────────────────────
RUN echo "lobby-terminal" > /etc/hostname \
 && printf '%s\n' \
    '  ┌────────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM CONSTRUCT — LOBBY TERMINAL                       AM-01 │' \
    '  │  "All citizens begin here. Enrollment is mandatory."           │' \
    '  │  Compliance Officer access granted. Your audit is authorized.  │' \
    '  │  All activity is logged. Logging is mandatory.                 │' \
    '  └────────────────────────────────────────────────────────────────┘' \
    > /etc/motd

EXPOSE 80 22

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# DIRECTIVE ZERO — AM-02: Wellness Observation Center
# Easy. Boot-to-root Docker container.
#
# Exploit chain (reproduced from the Hannah / OnSystem ShellDredd #1 shape):
#   1. Enumerate: FTP (21, vsftpd anonymous), SSH (22), HTTP (8080 decoy)
#   2. Anonymous FTP -> hidden .wellness/ dir -> steal id_rsa
#   3. SSH in as `wellness` using the stolen key -> user flag
#   4. SUID enum -> /usr/bin/cpulimit and /usr/bin/mawk are SUID
#   5a. cpulimit -l 100 -f chmod +s /bin/bash -> bash -p -> root flag
#   5b. mawk '//' /root/root.txt -> read root flag (alternate)
#
# Flags are injected via env vars at runtime (never baked in):
#   AM02_USER_FLAG, AM02_ROOT_FLAG
#
# See README.md for the full Director walkthrough.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      vsftpd \
      openssh-server \
      cpulimit \
      mawk \
      apache2 \
      sudo \
      net-tools \
      iputils-ping \
      curl \
      ca-certificates \
      openssh-client \
    && rm -rf /var/lib/apt/lists/*

# ── wellness user ───────────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash wellness \
 && mkdir -p /home/wellness/ftp/public/.wellness \
             /home/wellness/.ssh \
             /home/wellness/transfer_logs \
             /run/sshd \
             /var/run/vsftpd

# ── SSH keypair (generated at build time) ──────────────────────────────────
# Private half goes in the anonymous FTP hidden dir (the thing players steal);
# public half goes in authorized_keys so the stolen key grants SSH access.
RUN ssh-keygen -t rsa -b 2048 -N '' -f /tmp/wellness_key \
 && cp /tmp/wellness_key     /home/wellness/ftp/public/.wellness/id_rsa \
 && cp /tmp/wellness_key.pub /home/wellness/.ssh/authorized_keys \
 && chmod 644 /home/wellness/ftp/public/.wellness/id_rsa \
 && chmod 600 /home/wellness/.ssh/authorized_keys \
 && chown -R wellness:wellness /home/wellness/.ssh \
                              /home/wellness/ftp \
                              /home/wellness/transfer_logs \
 && rm -f /tmp/wellness_key /tmp/wellness_key.pub

# ── FTP cover file ──────────────────────────────────────────────────────────
COPY configs/ftp_notice.txt /home/wellness/ftp/public/notice.txt
RUN chown wellness:wellness /home/wellness/ftp/public/notice.txt

# ── Lore log (Fragment B) ────────────────────────────────────────────────────
COPY transfer_logs/archive_status.log /home/wellness/transfer_logs/archive_status.log
RUN chown wellness:wellness /home/wellness/transfer_logs/archive_status.log \
 && chmod 644 /home/wellness/transfer_logs/archive_status.log

# ── SUID on cpulimit and mawk (the two privesc routes) ──────────────────────
RUN chmod 4755 /usr/bin/cpulimit /usr/bin/mawk

# ── Service configs ─────────────────────────────────────────────────────────
COPY configs/vsftpd.conf    /etc/vsftpd.conf
COPY configs/sshd_config   /etc/ssh/sshd_config
COPY configs/000-default.conf /etc/apache2/sites-available/000-default.conf

# Apache: listen on 8080 for the decoy page (drop the default :80 listener).
RUN sed -i 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
 && a2dissite 000-default 2>/dev/null || true \
 && a2ensite 000-default 2>/dev/null || true

COPY web/index.html /var/www/html/index.html

# ── Hostname + MOTD retheme (Construct / QUORUM) ───────────────────────────
RUN echo "wellness-observation" > /etc/hostname \
 && printf '%s\n' \
    '  ┌───────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM CONSTRUCT — WELLNESS OBSERVATION CENTER         AM-02 │' \
    '  │  "Citizens are reminded that this facility does not exist."   │' \
    '  │  "This machine does not exist. Please proceed."               │' \
    '  │  Compliance Officer access logged. Observation is care.       │' \
    '  └───────────────────────────────────────────────────────────────┘' \
    > /etc/motd

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 21 22 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
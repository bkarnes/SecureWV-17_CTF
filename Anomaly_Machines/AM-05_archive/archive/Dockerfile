# DIRECTIVE ZERO — AM-05: The Archive (document service host)
# Hard. Boot-to-root Docker container — the public-facing archive portal.
#
# Exploit chain:
#   1. Enumerate: SSH (22), document service (8443, HTTPS), RabbitMQ (5672)
#   2. Foothold: Jinja2 SSTI in the document rendering service on 8443
#   3. User flag: read /home/archivist/user.txt via SSTI or reverse shell
#   4. Discover RabbitMQ on 5672 (guest/guest, loopback_users=none)
#   5. Privesc: publish a command to the archive_commands queue -> the
#      archive-consumer executes it as root -> writes root flag to shared volume
#   6. Root flag: read /shared_archive/root_flag.txt
#
# Flags are injected via env vars at runtime (never baked in):
#   AM05_USER_FLAG, AM05_ROOT_FLAG
#
# See README.md for the full Director walkthrough.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      python3-venv \
      openssh-server \
      rabbitmq-server \
      openssl \
      curl \
      net-tools \
      iputils-ping \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python Flask for the document service ──────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages flask

# ── archivist user (owns the user flag) ────────────────────────────────────
RUN useradd -m -s /bin/bash archivist \
 && mkdir -p /run/sshd /home/archivist/.ssh

# ── Self-signed TLS cert for the document service ──────────────────────────
RUN mkdir -p /opt/archive/certs \
 && openssl req -x509 -newkey rsa:2048 -keyout /opt/archive/certs/key.pem \
    -out /opt/archive/certs/cert.pem -days 365 -nodes \
    -subj "/CN=archive" 2>/dev/null \
 && chmod 644 /opt/archive/certs/cert.pem /opt/archive/certs/key.pem

# ── Web app ────────────────────────────────────────────────────────────────
COPY app/ /opt/archive/app/

# ── RabbitMQ config (misconfig: allow guest from any host) ─────────────────
COPY configs/rabbitmq.conf /etc/rabbitmq/rabbitmq.conf

# ── SSH config ─────────────────────────────────────────────────────────────
COPY configs/sshd_config /etc/ssh/sshd_config

# ── Hostname + MOTD retheme ─────────────────────────────────────────────────
RUN echo "archive" > /etc/hostname \
 && printf '%s\n' \
    '  ┌────────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM CONSTRUCT — THE ARCHIVE                          AM-05 │' \
    '  │  "Physical document storage, digitized. Records predate        │' \
    '  │   QUORUM. QUORUM disputes this. Access is restricted to        │' \
    '  │   CRIMSON clearance and above."                                │' \
    '  └────────────────────────────────────────────────────────────────┘' \
    > /etc/motd

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 8443 5672

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
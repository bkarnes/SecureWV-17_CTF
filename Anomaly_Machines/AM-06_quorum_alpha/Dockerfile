# DIRECTIVE ZERO — AM-06: QUORUM Subsystem Alpha
# Insane. Custom-built. The hardest box at the event.
#
# Exploit chain (6 stages, 3 new techniques):
#   1. Binary exploitation: stack buffer overflow in the QUORUM terminal on :31337
#   2. Crypto: AES-encrypted archive with weak key derivation (SHA256 of citizen ID)
#   3. Privesc: writable dir + PATH hijack + SUID binary (3-step chain)
#
# Flags are injected via env vars at runtime (never baked in):
#   AM06_USER_FLAG, AM06_ROOT_FLAG
#
# Event parameterization:
#   BUFFER_SIZE — the vulnerable buffer size (default 64, changes overflow offset)
#   CITIZEN_ID  — the crypto key derivation input (changes the AES key per event)
#
# See README.md for the full Director walkthrough.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# ── Base packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc \
      libc6-dev \
      python3 \
      python3-pip \
      openssh-server \
      openssh-client \
      netcat-openbsd \
      file \
      curl \
      net-tools \
      iputils-ping \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages pycryptodome

# ── Build args (event parameterization) ─────────────────────────────────────
ARG BUFFER_SIZE=64

# ── Users: operator (low priv from overflow), analyst (from crypto) ─────────
# Note: Debian 11 has a pre-existing 'operator' group (GID 37). Use -g to
# add the user to it rather than creating a new group.
RUN useradd -m -s /bin/bash -g operator operator \
 && useradd -m -s /bin/bash analyst \
 && mkdir -p /home/analyst/.ssh /run/sshd /opt/quorum /opt/quorum/scripts /opt/quorum/keys

# ── Compile the vulnerable QUORUM terminal binary (no protections) ──────────
COPY src/quorum_terminal.c /tmp/quorum_terminal.c
RUN gcc -fno-stack-protector -no-pie -z execstack \
      -DBUFFER_SIZE=${BUFFER_SIZE} \
      -o /opt/quorum/quorum_terminal /tmp/quorum_terminal.c \
 && rm /tmp/quorum_terminal.c

# ── Compile the SUID privesc binary ─────────────────────────────────────────
COPY privesc/quorum_audit.c /tmp/quorum_audit.c
RUN gcc -o /usr/local/bin/quorum_audit /tmp/quorum_audit.c \
 && chmod 4755 /usr/local/bin/quorum_audit \
 && rm /tmp/quorum_audit.c

# ── Writable scripts directory (privesc step 1) ────────────────────────────
RUN chmod 777 /opt/quorum/scripts

# ── PATH config (privesc step 2 — adds /opt/quorum/scripts to PATH) ────────
COPY configs/quorum_path.sh /etc/profile.d/quorum.sh
RUN chmod 644 /etc/profile.d/quorum.sh

# ── SSH config ─────────────────────────────────────────────────────────────
COPY configs/sshd_config /etc/ssh/sshd_config

# ── Crypto challenge files ──────────────────────────────────────────────────
COPY crypto/generate_archive.py /opt/quorum/crypto/generate_archive.py
COPY crypto/decrypt.py /opt/quorum/crypto/decrypt.py
RUN chmod +x /opt/quorum/crypto/generate_archive.py /opt/quorum/crypto/decrypt.py

# ── Lore: the Zero Directive ───────────────────────────────────────────────
COPY lore/zero_directive.txt /root/zero_directive.txt
RUN chmod 400 /root/zero_directive.txt

# ── Hostname + MOTD retheme ─────────────────────────────────────────────────
RUN echo "quorum-alpha" > /etc/hostname \
 && printf '%s\n' \
    '  ┌───────────────────────────────────────────────────────────────┐' \
    '  │  QUORUM SUBSYSTEM ALPHA                                 AM-06 │' \
    '  │  "This system is not listed in the administrative index."     │' \
    '  │  "QUORUM has no record of it."                                │' \
    '  │  "Players who reach this machine are encouraged to            │' \
    '  │   reconsider."                                                │' \
    '  └───────────────────────────────────────────────────────────────┘' \
    > /etc/motd

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22 31337

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
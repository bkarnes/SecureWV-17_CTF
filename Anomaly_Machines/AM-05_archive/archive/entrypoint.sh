#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-05 archive (document service host) entrypoint.
#
# Writes per-event flags, starts RabbitMQ, sshd, and the Flask document
# service in the foreground.
#
# Flags come from env vars (never baked into the image):
#   AM05_USER_FLAG  -> /home/archivist/user.txt   (chmod 444)
#   AM05_ROOT_FLAG  -> /root/root.txt              (chmod 400, on the consumer)

set -euo pipefail

: "${AM05_USER_FLAG:=DZ{user_archive_PLACEHOLDER}}"
: "${AM05_ROOT_FLAG:=DZ{root_archive_PLACEHOLDER}}"

echo "[entrypoint] AM-05 The Archive starting..."

# ── 1. Flag placement (user flag on this host; root flag is on the consumer) ─
printf '%s\n' "$AM05_USER_FLAG" > /home/archivist/user.txt
chown archivist:archivist /home/archivist/user.txt
chmod 444 /home/archivist/user.txt

# The root flag goes to the consumer via env var; the consumer writes it
# to /root/root.txt. The shared volume is where the consumer will write
# the flag after the player triggers the MQ command.
mkdir -p /shared_archive
chmod 777 /shared_archive

# ── 2. RabbitMQ ────────────────────────────────────────────────────────────
echo "[entrypoint] starting RabbitMQ..."
# Start RabbitMQ in detached mode.
rabbitmq-server -detached 2>/dev/null || true
# Wait for RabbitMQ to be ready.
for i in $(seq 1 30); do
  if rabbitmqctl status >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
# Configure: allow guest user from any host (the misconfig).
rabbitmqctl set_policy -p / --priority 1 "allow_all" ".*" '{"ha-mode":"all"}' 2>/dev/null || true

# ── 3. SSH ──────────────────────────────────────────────────────────────────
echo "[entrypoint] starting sshd on :22..."
mkdir -p /run/sshd
/usr/sbin/sshd

# ── 4. Flask document service (HTTPS on :8443) ─────────────────────────────
echo "[entrypoint] starting document service on :8443..."
cd /opt/archive/app
# Run Flask as the www-data user (non-root) so the SSTI foothold gets
# a low-priv shell — the root flag requires the MQ privesc path.
exec su -s /bin/bash -c "python3 /opt/archive/app/app.py" www-data
#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-05 archive-consumer entrypoint.
#
# Writes the root flag to /root/root.txt (on this container), then runs
# the RabbitMQ consumer as root. The consumer listens for commands on
# the archive_commands queue and executes them, writing output to the
# shared volume.
#
# The player never gets a shell on this container — they interact with
# it exclusively via the MQ. The root flag lives here; the player must
# get the consumer to read it and write it to the shared volume.
#
# Flag comes from env var:
#   AM05_ROOT_FLAG -> /root/root.txt (chmod 400)

set -euo pipefail

: "${AM05_ROOT_FLAG:=DZ{root_archive_PLACEHOLDER}}"

echo "[consumer entrypoint] AM-05 archive-consumer starting..."

# ── 1. Root flag placement ─────────────────────────────────────────────────
printf '%s\n' "$AM05_ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

# ── 2. Shared volume ────────────────────────────────────────────────────────
mkdir -p /shared_archive
chmod 777 /shared_archive

# ── 3. Run the consumer as root (foreground keeps container alive) ─────────
echo "[consumer entrypoint] starting MQ consumer (running as root)..."
exec python3 /opt/consumer/consumer.py
#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-01 entrypoint.
#
# Initializes MariaDB, loads the enrollment schema + lore, configures the
# `compliance` SSH password (matching the credential planted in the
# `login` table so players can recover it via SQLi), writes the per-event
# flags to the canonical paths, then starts sshd + apache in the foreground.
#
# Flags come from env vars (never baked into the image):
#   AM01_USER_FLAG  -> /home/compliance/user.txt   (chmod 444)
#   AM01_ROOT_FLAG  -> /root/root.txt              (chmod 400)

set -euo pipefail

: "${AM01_USER_FLAG:=DZ{user_lobby_PLACEHOLDER}}"
: "${AM01_ROOT_FLAG:=DZ{root_lobby_PLACEHOLDER}}"

# The SSH password for the `compliance` user. This value is ALSO planted
# as a row in the `login` table in init_db.sql — players who dump the DB
# after SQLi + command-injection foothold recover it and SSH in.
# If you change it here, change init_db.sql to match.
COMPLIANCE_SSH_PASSWORD="WinterCaseSensitiveShallNotPass!"

echo "[entrypoint] AM-01 Lobby Terminal starting..."

# ── 1. MariaDB bootstrap ────────────────────────────────────────────────────
if [[ ! -d /var/lib/mysql/mysql ]]; then
  echo "[entrypoint] initializing MariaDB data dir..."
  mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1
fi

mkdir -p /run/mysqld
chown -R mysql:mysql /var/lib/mysql /run/mysqld

echo "[entrypoint] starting MariaDB (temp)..."
mysqld --user=mysql --datadir=/var/lib/mysql --socket=/run/mysqld/mysqld.sock &
MYSQL_PID=$!

# Wait for the socket
for i in $(seq 1 30); do
  if mysqladmin --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "[entrypoint] loading init_db.sql..."
mysql --socket=/run/mysqld/mysqld.sock < /tmp/init_db.sql

# Shut down the temp mysqld; we'll restart it detached after setup.
mysqladmin --socket=/run/mysqld/mysqld.sock shutdown 2>/dev/null || true
wait "$MYSQL_PID" 2>/dev/null || true

# ── 2. Compliance user password (must match init_db.sql login row) ──────────
echo "[entrypoint] setting compliance SSH password..."
echo "compliance:${COMPLIANCE_SSH_PASSWORD}" | chpasswd

# ── 3. Flag placement ───────────────────────────────────────────────────────
echo "[entrypoint] writing flags..."
printf '%s\n' "$AM01_USER_FLAG" > /home/compliance/user.txt
chown compliance:compliance /home/compliance/user.txt
chmod 444 /home/compliance/user.txt

printf '%s\n' "$AM01_ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

# ── 4. Apache config ────────────────────────────────────────────────────────
echo "[entrypoint] applying Apache vhost..."
cp /tmp/configs/000-default.conf /etc/apache2/sites-available/000-default.conf
a2ensite 000-default.conf 2>/dev/null || true
# PHP module already enabled in Dockerfile; make sure php-mysql is loaded.
phpenmod mysqli 2>/dev/null || true

# Tighten app config perms: config.php must be readable by www-data so
# the app can connect to the DB, but should NOT be world-readable (subtle
# hint that it contains creds worth reading).
chown www-data:www-data /var/www/html/app/config.php
chmod 640 /var/www/html/app/config.php

# ── 5. sshd config ──────────────────────────────────────────────────────────
echo "[entrypoint] applying sshd_config..."
cp /tmp/configs/sshd_config /etc/ssh/sshd_config
mkdir -p /run/sshd

# ── 6. Start services ────────────────────────────────────────────────────────
echo "[entrypoint] starting MariaDB (detached)..."
mysqld --user=mysql --datadir=/var/lib/mysql --socket=/run/mysqld/mysqld.sock &

echo "[entrypoint] starting sshd..."
/usr/sbin/sshd

echo "[entrypoint] starting Apache (foreground)..."
echo "[entrypoint] AM-01 Lobby Terminal ready."
echo "  HTTP -> :80   SSH -> :22"
echo "  User flag: /home/compliance/user.txt"
echo "  Root flag: /root/root.txt"
echo ""

# Apache in the foreground keeps the container alive.
exec apache2ctl -D FOREGROUND
#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-04 R&D Annex entrypoint.
#
# Writes per-event flags, configures Apache (Basic Auth + verb bypass),
# starts the Python API on :3000, cron, sshd, and Apache in the foreground.
#
# Flags come from env vars (never baked into the image):
#   AM04_USER_FLAG  -> /home/researcher/user.txt   (chmod 444)
#   AM04_ROOT_FLAG  -> /root/root.txt               (chmod 400)

set -euo pipefail

: "${AM04_USER_FLAG:=DZ{user_rd_annex_PLACEHOLDER}}"
: "${AM04_ROOT_FLAG:=DZ{root_rd_annex_PLACEHOLDER}}"

echo "[entrypoint] AM-04 R&D Annex starting..."

# ── 1. Flag placement ──────────────────────────────────────────────────────
printf '%s\n' "$AM04_USER_FLAG" > /home/researcher/user.txt
chown researcher:researcher /home/researcher/user.txt
chmod 444 /home/researcher/user.txt

printf '%s\n' "$AM04_ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

# ── 2. Apache config ────────────────────────────────────────────────────────
echo "[entrypoint] applying Apache vhost + Basic Auth..."
cp /tmp/configs/000-default.conf /etc/apache2/sites-available/000-default.conf
a2ensite 000-default.conf 2>/dev/null || true

# .htpasswd for Basic Auth (baked at build time with a researcher hash)
cp /tmp/configs/htpasswd /var/www/html/.htpasswd
cp /tmp/configs/htaccess /var/www/html/.htaccess

# scriptz/.htaccess allows directory listing without auth
cp /tmp/configs/scriptz_htaccess /var/www/html/scriptz/.htaccess 2>/dev/null || true

# ── 3. SSH (port 2220, locked-down decoy) ──────────────────────────────────
echo "[entrypoint] starting sshd on :2220..."
# Configure sshd to listen on 2220, key-only auth
sed -i 's/^Port 22$/Port 2220/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null || true
mkdir -p /run/sshd
/usr/sbin/sshd

# ── 4. Python API on port 3000 ──────────────────────────────────────────────
echo "[entrypoint] starting R&D API on :3000..."
python3 /opt/rd/api/rd_api.py &

# ── 5. Cron (for the privesc tar wildcard exploit) ──────────────────────────
echo "[entrypoint] starting cron..."
# Root cron: rd_backup.sh every 5 minutes, create_backup.sh every minute
echo "*/5 * * * * root /usr/local/bin/rd_backup.sh" > /etc/cron.d/rd-backup
echo "* * * * * root /root/create_backup.sh" >> /etc/cron.d/rd-backup
chmod 644 /etc/cron.d/rd-backup
cron

# ── 6. Start Apache (foreground keeps container alive) ─────────────────────
echo "[entrypoint] starting Apache (foreground)..."
echo "[entrypoint] AM-04 R&D Annex ready."
echo "  HTTP -> :80   SSH -> :2220   API -> :3000"
echo "  User flag: /home/researcher/user.txt"
echo "  Root flag: /root/root.txt"
echo ""

exec apache2ctl -D FOREGROUND
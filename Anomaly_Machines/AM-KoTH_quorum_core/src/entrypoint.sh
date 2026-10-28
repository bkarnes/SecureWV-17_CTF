#!/bin/bash
#
# QUORUM Core — container entrypoint.
#
# Starts:
#   1. Apache (web console on port 80, runs as quorum-svc via PHP-FPM)
#   2. SSH (port 22, for alt access / flavor)
#   3. Flag webhook service (Flask on port 8081, internal-only, runs as root)
#
# The flag file /root/koth_flag.txt is initialized from KOTH_INITIAL_FLAG
# and rotated thereafter by the scoring engine via the webhook.

set -e

# ── Initial flag ───────────────────────────────────────────────────────────
INITIAL_FLAG="${KOTH_INITIAL_FLAG:-DZ\{koth_initial_PLACEHOLDER\}}"
printf '%s\n' "$INITIAL_FLAG" > /root/koth_flag.txt
chmod 600 /root/koth_flag.txt
chown root:root /root/koth_flag.txt
echo "[entrypoint] initial KoTH flag written to /root/koth_flag.txt"

# ── quorum-status helper script ────────────────────────────────────────────
# The SUID quorum-diag binary calls "quorum-status <arg>" via system().
# This script provides the legitimate status checks. It must be in PATH.
cat > /usr/local/bin/quorum-status <<'STATUS'
#!/bin/bash
case "$1" in
    network) echo "[quorum-status] Network: all citizen terminals reachable" ;;
    disk)    echo "[quorum-status] Disk: 42% used, 58% available" ;;
    memory)  echo "[quorum-status] Memory: 2.1GB / 4.0GB used" ;;
    citizens) echo "[quorum-status] Citizens: 10,427 registered, 10,426 compliant" ;;
    *)       echo "[quorum-status] Unknown check: $1" ;;
esac
STATUS
chmod 755 /usr/local/bin/quorum-status

# ── SSH setup ───────────────────────────────────────────────────────────────
mkdir -p /run/sshd
# quorum-svc has a known password for SSH access (flavor / alt access)
echo "quorum-svc:qu0rum_c0re_2026" | chpasswd 2>/dev/null || true

# ── Start services ──────────────────────────────────────────────────────────

# 1. Apache (web console — runs as quorum-svc, configured in Dockerfile)
a2enmod php* 2>/dev/null || true
a2dissite 000-default 2>/dev/null || true

# Configure Apache vhost for the console
cat > /etc/apache2/sites-available/quorum.conf <<'APACHE'
<VirtualHost *:80>
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
    <FilesMatch "\.php$">
        SetHandler application/x-httpd-php
    </FilesMatch>
</VirtualHost>
APACHE
a2ensite quorum 2>/dev/null || true

# Start Apache
source /etc/apache2/envvars
apache2 -k start
echo "[entrypoint] Apache started (console on :80, running as quorum-svc)"

# 2. SSH
/usr/sbin/sshd
echo "[entrypoint] SSH started on :22"

# 3. Flag webhook service (Flask on :8081, runs as root)
python3 /opt/flag_service.py &
echo "[entrypoint] Flag webhook service started on :8081"

# ── Keep alive ─────────────────────────────────────────────────────────────
echo "[entrypoint] QUORUM Core is running. All systems nominal."
echo "[entrypoint] The surface is uninhabitable. This determination is final."

# Wait for background processes
wait
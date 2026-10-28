#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-03 junction7 (public host) entrypoint.
#
# Writes per-event flags, starts Postfix, the custom routing status
# service (port 9001), cron, and Apache in the foreground.
#
# Flags come from env vars (never baked into the image):
#   AM03_USER_FLAG  -> /root/user.txt   (chmod 444 — the foothold reward)
#   AM03_ROOT_FLAG   -> /root/root.txt   (chmod 400 — the privesc reward)

set -euo pipefail

: "${AM03_USER_FLAG:=DZ{user_junction7_PLACEHOLDER}}"
: "${AM03_ROOT_FLAG:=DZ{root_junction7_PLACEHOLDER}}"

echo "[entrypoint] AM-03 junction7 (public host) starting..."

# ── 1. Flag placement ──────────────────────────────────────────────────────
# On the public host, the "user flag" is earned by getting RCE (foothold)
# and the "root flag" by privesc. Both live in /root/ since there's no
# separate low-priv user on this box (players land as www-data).
printf '%s\n' "$AM03_USER_FLAG" > /root/user.txt
chmod 444 /root/user.txt

printf '%s\n' "$AM03_ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

# ── 2. Apache config ────────────────────────────────────────────────────────
echo "[entrypoint] applying Apache vhost..."
cp /tmp/configs/000-default.conf /etc/apache2/sites-available/000-default.conf
a2ensite 000-default.conf 2>/dev/null || true

# ── 3. Postfix ──────────────────────────────────────────────────────────────
echo "[entrypoint] starting Postfix..."
# Postfix logs to /var/log/mail.log — this is the file the LFI targets.
# Ensure the log file exists and is readable by www-data (for the LFI
# to work, Apache/PHP must be able to read /var/log/mail.log).
touch /var/log/mail.log
# www-data needs read access — make it world-readable (the misconfig).
chmod 644 /var/log/mail.log

# Apply our custom Postfix config (relaxed for the log-poisoning foothold).
cp /tmp/configs/postfix_main.cf /etc/postfix/main.cf 2>/dev/null || true
postfix start

# ── 4. Routing status service (port 9001) ───────────────────────────────────
echo "[entrypoint] starting routing status service on :9001..."
python3 /opt/junction/routing_status/routing_status.py &

# ── 5. Cron (for the privesc cron job) ───────────────────────────────────────
echo "[entrypoint] starting cron..."
# Install the crontab: run routing_updater.sh every minute as root.
echo "* * * * * root /opt/junction/routing_updater.sh" > /etc/cron.d/routing-updater
chmod 644 /etc/cron.d/routing-updater
cron

# ── 6. Start Apache (foreground keeps container alive) ─────────────────────
echo "[entrypoint] starting Apache (foreground)..."
echo "[entrypoint] AM-03 junction7 ready."
echo "  SMTP -> :25   HTTP -> :80   Routing status -> :9001"
echo "  User flag: /root/user.txt"
echo "  Root flag: /root/root.txt"
echo ""

exec apache2ctl -D FOREGROUND
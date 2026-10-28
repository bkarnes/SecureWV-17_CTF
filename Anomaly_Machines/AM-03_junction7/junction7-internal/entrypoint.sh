#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-03 junction7-internal entrypoint.
#
# Writes per-event flags, starts Tomcat, sshd, and cron.
#
# Flags come from env vars (never baked into the image):
#   AM03_INTERNAL_USER_FLAG  -> /home/compliance/user.txt  (chmod 444)
#   AM03_INTERNAL_ROOT_FLAG  -> /root/root.txt               (chmod 400)

set -euo pipefail

: "${AM03_INTERNAL_USER_FLAG:=DZ{internal_user_junction7_PLACEHOLDER}}"
: "${AM03_INTERNAL_ROOT_FLAG:=DZ{internal_root_junction7_PLACEHOLDER}}"

echo "[entrypoint] AM-03 junction7-internal starting..."

# ── 1. Flag placement ──────────────────────────────────────────────────────
printf '%s\n' "$AM03_INTERNAL_USER_FLAG" > /home/compliance/user.txt
chown compliance:compliance /home/compliance/user.txt
chmod 444 /home/compliance/user.txt

printf '%s\n' "$AM03_INTERNAL_ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

# ── 2. SSH (port 34483, key-only — players inject their key after RCE) ─────
# Set a password for compliance so password auth could work if enabled,
# but sshd_config has PasswordAuthentication no — key-only is the way in
# after RCE. The RCE player writes their own key to authorized_keys.
echo "[entrypoint] starting sshd on :34483..."
mkdir -p /run/sshd
# Create .ssh dir so the RCE player can drop authorized_keys
mkdir -p /home/compliance/.ssh
chown compliance:compliance /home/compliance/.ssh
chmod 700 /home/compliance/.ssh
/usr/sbin/sshd

# ── 3. Cron (for the privesc cron job) ─────────────────────────────────────
echo "[entrypoint] starting cron..."
echo "* * * * * root /opt/junction/system_check.sh" > /etc/cron.d/system-check
chmod 644 /etc/cron.d/system-check
cron

# ── 4. Tomcat (foreground keeps container alive) ──────────────────────────
echo "[entrypoint] starting Tomcat on :8080..."
echo "[entrypoint] AM-03 junction7-internal ready."
echo "  Tomcat -> :8080   SSH -> :34483"
echo "  Internal user flag: /home/compliance/user.txt"
echo "  Internal root flag: /root/root.txt"
echo ""

# Use Ubuntu's tomcat9 paths
export CATALINA_HOME=/usr/share/tomcat9
export CATALINA_BASE=/var/lib/tomcat9
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
exec /usr/share/tomcat9/bin/catalina.sh run

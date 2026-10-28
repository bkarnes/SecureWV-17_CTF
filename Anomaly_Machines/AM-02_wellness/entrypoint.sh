#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-02 entrypoint.
#
# Writes the per-event flags to the canonical paths, locks the wellness
# account to key-only auth (no password), then starts vsftpd, sshd, and
# Apache (8080 decoy) in the foreground.
#
# Flags come from env vars (never baked into the image):
#   AM02_USER_FLAG  -> /home/wellness/user.txt   (chmod 444)
#   AM02_ROOT_FLAG  -> /root/root.txt            (chmod 400)

set -euo pipefail

: "${AM02_USER_FLAG:=DZ{user_wellness_PLACEHOLDER}}"
: "${AM02_ROOT_FLAG:=DZ{root_wellness_PLACEHOLDER}}"

echo "[entrypoint] AM-02 Wellness Observation Center starting..."

# ── 1. Flag placement ──────────────────────────────────────────────────────
echo "[entrypoint] writing flags..."
printf '%s\n' "$AM02_USER_FLAG" > /home/wellness/user.txt
chown wellness:wellness /home/wellness/user.txt
chmod 444 /home/wellness/user.txt

printf '%s\n' "$AM02_ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

# ── 2. Lock the wellness account to key-only auth ──────────────────────────
# No password is set; SSH config requires PubkeyAuthentication and disallows
# PasswordAuthentication. The only way in is the stolen id_rsa.
passwd -l wellness >/dev/null 2>&1 || true

# ── 3. Ensure runtime dirs exist ────────────────────────────────────────────
mkdir -p /run/sshd /var/run/vsftpd /run/apache2
chown wellness:wellness /var/run/vsftpd 2>/dev/null || true

# ── 4. Start services ────────────────────────────────────────────────────────
echo "[entrypoint] starting vsftpd..."
vsftpd /etc/vsftpd.conf &

echo "[entrypoint] starting sshd..."
/usr/sbin/sshd

echo "[entrypoint] starting Apache (foreground, port 8080 decoy)..."
echo "[entrypoint] AM-02 Wellness Observation Center ready."
echo "  FTP  -> :21   SSH -> :22   HTTP decoy -> :8080"
echo "  User flag: /home/wellness/user.txt"
echo "  Root flag: /root/root.txt"
echo ""

# Apache in the foreground keeps the container alive.
exec apache2ctl -D FOREGROUND
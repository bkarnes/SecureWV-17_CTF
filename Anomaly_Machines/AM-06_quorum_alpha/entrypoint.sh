#!/usr/bin/env bash
#
# DIRECTIVE ZERO — AM-06 QUORUM Subsystem Alpha entrypoint.
#
# Writes per-event flags, generates the SSH keypair + encrypted crypto
# archive, starts sshd, and launches the vulnerable QUORUM terminal
# binary with ASLR disabled (setarch -R).
#
# Flags come from env vars (never baked into the image):
#   AM06_USER_FLAG  -> /home/operator/user.txt   (chmod 444)
#   AM06_ROOT_FLAG  -> /root/root.txt              (chmod 400)
#
# Event parameterization:
#   CITIZEN_ID  — the crypto key derivation input (default: CTZ-0042-2087)

set -euo pipefail

: "${AM06_USER_FLAG:=DZ{user_quorum_alpha_PLACEHOLDER}}"
: "${AM06_ROOT_FLAG:=DZ{root_quorum_alpha_PLACEHOLDER}}"
: "${CITIZEN_ID:=CTZ-0042-2087}"

echo "[entrypoint] AM-06 QUORUM Subsystem Alpha starting..."

# ── 1. Flag placement ──────────────────────────────────────────────────────
printf '%s\n' "$AM06_USER_FLAG" > /home/operator/user.txt
chown operator:operator /home/operator/user.txt
chmod 444 /home/operator/user.txt

printf '%s\n' "$AM06_ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

# ── 2. Generate the crypto challenge (SSH keypair + encrypted archive) ─────
echo "[entrypoint] generating crypto challenge..."
python3 /opt/quorum/crypto/generate_archive.py "$CITIZEN_ID" /home/operator
chown operator:operator /home/operator/secure_archive.enc /home/operator/citizen_id.txt /home/operator/decrypt.py

# ── 3. SSH ──────────────────────────────────────────────────────────────────
echo "[entrypoint] starting sshd on :22..."
mkdir -p /run/sshd
/usr/sbin/sshd

# ── 4. QUORUM terminal (ASLR disabled, executable stack) ───────────────────
echo "[entrypoint] starting QUORUM terminal on :31337 (ASLR disabled)..."
# setarch -R disables ASLR for this process only (no privileged mode needed).
exec setarch -R /opt/quorum/quorum_terminal
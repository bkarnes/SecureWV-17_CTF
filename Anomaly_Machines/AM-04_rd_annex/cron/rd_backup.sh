#!/bin/sh
# QUORUM R&D backup compressor
# Runs every 5 minutes as root via /etc/cron.d/rd-backup.
#
# VULNERABILITY: the wildcard `*` in the tar command allows tar
# --checkpoint-action exploitation. Files named `--checkpoint=1` and
# `--checkpoint-action=exec=sh shell.sh` in the world-writable
# /home/researcher/backup/ directory are interpreted as tar options,
# executing `shell.sh` as root.
#
# This script is world-readable — players who read it see the vuln.

rm -f /home/researcher/backup/backup.tar.gz
cd /home/researcher/backup
tar cfz /home/researcher/backup/backup.tar.gz *
chown researcher:researcher /home/researcher/backup/backup.tar.gz
rm -f /home/researcher/backup/*.BAK
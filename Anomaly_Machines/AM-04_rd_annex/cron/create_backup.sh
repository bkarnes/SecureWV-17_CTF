#!/bin/bash
# QUORUM R&D artifact backup seeder
# Runs every minute as root via /etc/cron.d/rd-backup.
# Seeds .BAK files into /home/researcher/backup/ so the tar wildcard
# has something to archive. Not readable by www-data (mode 700).

cd /home/researcher/backup
for i in $(seq 1 3); do
  echo "R&D artifact snapshot $(date) - $RANDOM" > "sys-$RANDOM.BAK"
done
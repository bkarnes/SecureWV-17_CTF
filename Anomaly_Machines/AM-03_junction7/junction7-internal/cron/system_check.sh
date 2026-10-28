#!/bin/bash
# QUORUM system integrity checker
# Directors may modify check criteria as infrastructure evolves.
# This script is intentionally world-writable to allow rapid updates.
#
# Runs every minute via /etc/cron.d/system-check (root).

echo "[system_check] integrity scan at $(date)..." >> /var/log/system_check.log
uptime >> /var/log/system_check.log 2>/dev/null || true
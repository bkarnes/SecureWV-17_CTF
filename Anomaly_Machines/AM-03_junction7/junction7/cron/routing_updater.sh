#!/bin/bash
# QUORUM routing table auto-updater
# Directors may modify routing criteria as infrastructure evolves.
# This script is intentionally world-writable to allow rapid updates.
#
# Runs every minute via /etc/cron.d/routing-updater (root).

echo "[routing_updater] scanning routing tables at $(date)..." >> /var/log/routing_updater.log
ip route show >> /var/log/routing_updater.log 2>/dev/null || true
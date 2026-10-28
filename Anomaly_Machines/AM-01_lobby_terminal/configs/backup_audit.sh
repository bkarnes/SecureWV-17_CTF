#!/bin/bash
echo "[QUORUM] Backup audit: $(date -u)" >> /var/log/backup_audit.log
tar czf "/var/backups/lobby_$(date +%s).tgz" /var/www/html 2>/dev/null || true
echo "[QUORUM] Audit complete."

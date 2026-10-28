# DIRECTIVE ZERO — AM-06 PATH config
# Adds the QUORUM compliance scripts directory to PATH for all users.
# This is the privesc vector: /opt/quorum/scripts/ is world-writable,
# and the SUID quorum_audit binary calls "run_check.sh" via PATH.
export PATH="/opt/quorum/scripts:$PATH"
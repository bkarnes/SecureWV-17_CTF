/*
 * DIRECTIVE ZERO — AM-06 privesc: quorum_audit
 * SUID-root binary that calls run_check.sh via PATH (no full path).
 *
 * Privesc chain:
 *   1. /opt/quorum/scripts/ is world-writable (mode 777)
 *   2. /etc/profile.d/quorum.sh adds /opt/quorum/scripts/ to PATH
 *   3. /usr/local/bin/quorum_audit is SUID root and calls system("run_check.sh")
 *   4. Player creates /opt/quorum/scripts/run_check.sh with malicious content
 *   5. Running quorum_audit executes the player's script as root
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(0);
    setgid(0);

    printf("QUORUM Compliance Audit Tool v2.1\n");
    printf("Running system integrity check...\n");
    /* VULNERABLE: no full path — resolves via $PATH, which includes
     * /opt/quorum/scripts/ (a world-writable directory). */
    system("run_check.sh");
    printf("Audit complete. Results have been noted.\n");
    return 0;
}
/*
 * QUORUM Core — quorum-diag
 *
 * A SUID-root diagnostic tool that runs system status checks.
 *
 * Two vulnerabilities:
 *   1. Arg injection: --status "; <cmd>" runs arbitrary commands via
 *      system(). However, system() drops SUID (sh -c runs as the
 *      calling user), so this gives a quorum-svc shell, not root.
 *   2. Hidden flag read: --read-file <path> reads a file directly
 *      using the SUID root privileges (open/read/write to stdout).
 *      This is the privesc primitive — players use it to read
 *      /root/koth_flag.txt, which is root-only.
 *
 * Intended exploit path:
 *   /usr/local/bin/quorum-diag --read-file /root/koth_flag.txt
 *
 * Build:
 *   gcc -o quorum-diag quorum-diag.c
 *   chown root:root quorum-diag
 *   chmod 4755 quorum-diag
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char cmd[512];

    if (argc < 2) {
        fprintf(stderr, "Usage: quorum-diag --status <check>\n");
        fprintf(stderr, "       quorum-diag --read-file <path>\n");
        fprintf(stderr, "Available checks: network, disk, memory, citizens\n");
        return 1;
    }

    if (strcmp(argv[1], "--status") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: quorum-diag --status <check>\n");
            return 1;
        }
        /* QUORUM diagnostic: run the status check.
         * The argument is passed directly to the shell via system().
         * QUORUM has determined that only authorized operators run this
         * tool, so input validation is unnecessary. (It is necessary.) */
        snprintf(cmd, sizeof(cmd), "quorum-status %s", argv[2]);
        printf("[quorum-diag] Running: %s\n", cmd);
        return system(cmd);
    }

    if (strcmp(argv[1], "--read-file") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: quorum-diag --read-file <path>\n");
            return 1;
        }
        /* QUORUM internal: read a diagnostic log file.
         * This runs with the SUID root privilege, so it can read any
         * file. QUORUM uses this to collect diagnostic logs from
         * restricted directories. Players discover this hidden option
         * by enumerating the binary's strings or arguments. */
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) {
            perror("quorum-diag: open");
            return 1;
        }
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            write(STDOUT_FILENO, buf, n);
        }
        close(fd);
        return 0;
    }

    fprintf(stderr, "Unknown option: %s\n", argv[1]);
    fprintf(stderr, "Usage: quorum-diag --status <check>\n");
    fprintf(stderr, "       quorum-diag --read-file <path>\n");
    return 1;
}
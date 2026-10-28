/*
 * DIRECTIVE ZERO — AM-06 QUORUM Subsystem Alpha
 * QUORUM Compliance Terminal — vulnerable TCP service on port 31337.
 *
 * VULNERABILITY: Stack buffer overflow in handle_client().
 *   recv(fd, buf, 256, 0) reads up to 256 bytes into a buffer of
 *   BUFFER_SIZE bytes (default 64). The overflow overwrites the saved
 *   RBP and return address on the stack.
 *
 * COMPILED WITH NO PROTECTIONS:
 *   gcc -fno-stack-protector -no-pie -z execstack \
 *       -DBUFFER_SIZE=64 -o quorum_terminal quorum_terminal.c
 *
 * ASLR is disabled at runtime via setarch -R in the entrypoint.
 * No PIE → fixed binary addresses. Executable stack → shellcode on stack.
 *
 * The binary is downloadable via the 'download' command so players can
 * reverse-engineer it locally and craft their exploit.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <signal.h>

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 64
#endif

#define PORT 31337
#define BINARY_PATH "/opt/quorum/quorum_terminal"

static void send_str(int fd, const char *s) {
    send(fd, s, strlen(s), 0);
}

static void send_file(int fd, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        send_str(fd, "Download failed. File not found.\n");
        return;
    }
    char fbuf[4096];
    size_t n;
    while ((n = fread(fbuf, 1, sizeof(fbuf), f)) > 0)
        send(fd, fbuf, n, 0);
    fclose(f);
}

static void handle_client(int fd) {
    char buf[BUFFER_SIZE];

    send_str(fd, "\n");
    send_str(fd, "  QUORUM SUBSYSTEM ALPHA — COMPLIANCE TERMINAL\n");
    send_str(fd, "  This system is not listed in the administrative index.\n");
    send_str(fd, "  QUORUM has no record of it.\n");
    send_str(fd, "  Players who reach this machine are encouraged to reconsider.\n");
    send_str(fd, "\n  Type 'help' for commands.\n\n> ");

    /*
     * VULNERABLE: recv reads up to 256 bytes into a BUFFER_SIZE buffer.
     * With BUFFER_SIZE=64, this overflows by 192 bytes — enough to
     * overwrite saved RBP (8 bytes) and return address (8 bytes),
     * plus room for shellcode on the executable stack.
     */
    int n = recv(fd, buf, 256, 0);
    if (n <= 0) return;

    /* Null-terminate within bounds (doesn't undo the overflow). */
    if (n < BUFFER_SIZE) buf[n] = '\0';
    else buf[BUFFER_SIZE - 1] = '\0';

    /* Command parsing — only looks at the first few bytes. */
    if (strncmp(buf, "help", 4) == 0) {
        send_str(fd, "Commands: help, status, download, exit\n> ");
    } else if (strncmp(buf, "status", 6) == 0) {
        send_str(fd, "QUORUM Subsystem Alpha: OPERATIONAL\n");
        send_str(fd, "Administrative index: NOT LISTED\n");
        send_str(fd, "Clearance required: IVORY\n> ");
    } else if (strncmp(buf, "download", 8) == 0) {
        send_str(fd, "Sending compliance terminal binary for review...\n");
        send_file(fd, BINARY_PATH);
        send_str(fd, "\nDownload complete. This transfer has been noted.\n> ");
    } else if (strncmp(buf, "exit", 4) == 0) {
        send_str(fd, "Connection terminated. This has been noted.\n");
    } else {
        send_str(fd, "Unknown command. This has been noted.\n> ");
    }
    /* When this function returns, the overwritten return address
     * redirects execution to the player's shellcode. */
}

static void reap(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(void) {
    signal(SIGCHLD, reap);

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    listen(sfd, 5);
    printf("[quorum_terminal] listening on port %d (buffer size: %d)\n", PORT, BUFFER_SIZE);
    fflush(stdout);

    while (1) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        pid_t pid = fork();
        if (pid == 0) {
            close(sfd);
            handle_client(cfd);
            close(cfd);
            _exit(0);
        }
        close(cfd);
    }
}
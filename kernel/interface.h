// #ifndef ROOTKIT_DEVICE_H
// #define ROOTKIT_DEVICE_H

// #include <sys/ioccom.h>

// #define ELEVATE _IOR('R', 1, NULL)

// #ifdef _KERNEL
// int make_rk_dev(void);
// void destroy_rk_dev(void);
// #endif

// #endif

// NOT COMPLETE, CURRENTLY ONLY A TEST IMPLEMENTATION, WAS GOING TO SEE IF COMMUNICATION ACTUALLY WORKS BUT FREEBSD IS FAILING ME

#ifndef ROOTKIT_INTERFACE_H
#define ROOTKIT_INTERFACE_H

#include <sys/ioccom.h>

#define RK_GET_VERSION _IOR('R', 1, int)

#ifdef _KERNEL
int make_rk_dev(void);
void destroy_rk_dev(void);
#endif

#endif
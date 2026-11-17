#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/syscall.h>

void usage();

struct syscall_info {
    char *syscall_name;
    int syscall_num;
};

int detect_syscall_hook(char *syscall_name, int syscall_num) {
    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd;
    struct nlist nl[] = { { NULL }, { NULL }, { NULL }, };

    unsigned long addr;
    int callnum;
    struct sysent call;

    nl[0].n_name = "sysent";
    nl[1].n_name = syscall_name;
    callnum = syscall_num;

    // printf("Checking system call %d: %s\n\n", callnum, syscall_name);

    kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    if (!kd) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(-1);
    }

    /* Find the address of sysent[] and name of syscall */
    if (kvm_nlist(kd, nl) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }

    if (!(nl[0].n_value)) {
        fprintf(stderr, "ERROR: %s not found (very weird...)\n",
            nl[0].n_name);
        exit(-1);
    }

    if (!nl[1].n_value) {
        fprintf(stderr, "ERROR: %s not found\n", nl[1].n_name);
        exit(-1);
    }

    /* Determine the address of sysent[callnum]. */
    addr = nl[0].n_value + callnum * sizeof(struct sysent);
    /* Copy sysent[callnum]. */
    if (kvm_read(kd, addr, &call, sizeof(struct sysent)) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }

    /* Where does sysent[callnum].sy_call point to? */
    printf("current sy_call pointer: %p, ", call.sy_call);

    /* Check if that's correct. */
    printf("expecting to point to 0x%lx. ", nl[1].n_value);
    if ((uintptr_t)call.sy_call != nl[1].n_value) {
        return 1;
    }

    if (kvm_close(kd) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }
    return 0;
}
#define SYSCALLS_SIZE 23
int check_syscalls() {
    struct syscall_info syscalls[SYSCALLS_SIZE] = {
        {.syscall_name = "sys_exit",            .syscall_num = SYS_exit},
        {.syscall_name = "sys_getdirentries",   .syscall_num = SYS_getdirentries},
        {.syscall_name = "sys_fstatfs",         .syscall_num = SYS_fstatfs},
        {.syscall_name = "sys___sysctl",        .syscall_num = SYS___sysctl},
        {.syscall_name = "sys___sysctlbyname",  .syscall_num = SYS___sysctlbyname},
        {.syscall_name = "sys_execve",          .syscall_num = SYS_execve},
        {.syscall_name = "sys_fexecve",         .syscall_num = SYS_fexecve},
        {.syscall_name = "sys_open",            .syscall_num = SYS_open},
        {.syscall_name = "sys_openat",          .syscall_num = SYS_openat},
        {.syscall_name = "sys_read",            .syscall_num = SYS_read}, // sys_read
        {.syscall_name = "sys_write",           .syscall_num = SYS_write}, // sys_write
        {.syscall_name = "sys_ptrace",          .syscall_num = SYS_ptrace}, // sys_ptrace
        {.syscall_name = "sys_kldload",          .syscall_num = SYS_kldload},// sys_kldload
        {.syscall_name = "sys_kldunload",          .syscall_num = SYS_kldunload}, // sys_kldunload
        {.syscall_name = "sys_kldstat",          .syscall_num = SYS_kldstat},// sys_kldstat
        {.syscall_name = "sys_kldnext",          .syscall_num = SYS_kldnext}, // sys_kldnext
        {.syscall_name = "sys_setuid",          .syscall_num = SYS_setuid}, // sys_setuid
        {.syscall_name = "sys_seteuid",          .syscall_num = SYS_seteuid}, // sys_seteuid
        {.syscall_name = "sys_bind",          .syscall_num = SYS_bind}, // sys_bind
        {.syscall_name = "sys_accept",          .syscall_num = SYS_accept}, // sys_accept
        {.syscall_name = "sys_connect",          .syscall_num = SYS_connect}, // sys_connect
        {.syscall_name = "sys_recvfrom",          .syscall_num = SYS_recvfrom}, // sys_recvfrom
        {.syscall_name = "sys_recvmsg",          .syscall_num = SYS_recvmsg}, // sys_recvmsg
    };
    int flag = 0;
    for (int i = 0; i < SYSCALLS_SIZE; i++) {
        printf("Checking %s: ", syscalls[i].syscall_name);
        if (detect_syscall_hook(syscalls[i].syscall_name, 
                syscalls[i].syscall_num)
        ) {
            printf("BAD\n");
            flag = 1;
        } else {
            printf("GOOD\n");
        }
    }

    return flag;
}

int
main(int argc, char *argv[])
{
    if (check_syscalls()) {
        return 1;
    }
    exit(0);
}

void
usage()
{
    fprintf(stderr,"Usage:\ncheckcall [system call function] "
        "[call number] <fix>\n\n");
    fprintf(stderr, "For a list of system call numbers see "
        "/sys/sys/syscall.h\n");
}
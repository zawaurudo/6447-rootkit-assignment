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

* The check is performed on a selected set of system calls.
* On each system call, the name and the number of it are taken into account. 
* An array of `struct nlist` is initialised with the first element's `n_name` set to "sysent" to fetch the address of sysent (system call table); and the second element's `n_name` set to the name of the syscall function that needs checking.
* To start reading the kernel memory, we need to initialise the kd (of type `kvm_t *`) to the file pointer returned by `kvm_openfiles`.
* `kvm_nlist` is then called with `kd` and `nl` to fetch the data relating to the names set in the `struct nlist` array.
* After calling `kvm_nlist`, the `n_value` of the first element contains the pointer to the `sysent` table. This is then be used to calculate the address of the syscall in the table given the syscall number (which is equivalent to the offset in the table).
* The calculated address is then used to access the entry of the table and copy the value to a local `struct sysent` variable.
* The `n_value` of the second element contains the address of the original syscall function implementation. This value can be used to compare with the `sy_call` in `struct sysent` above. If two values are equal, the syscall function pointer is pointing to its supposed function. Otherwise, the syscall has been hooked


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
    - Risk threshold is 10

# PROCESS CONCEALMENT AND DETECTION
- Changes:
    - None

- Concealment:
    - Added hooks for kill, which process detecting uses to check if a hidden process is active
    - Added hooks for sys_ctl

- Detector:
    - Identifies rootkits based on suspicious process names, such as rklog and revshell (each finding adds 1 point to the risk score, but is capped at 4 to avoid false positives)
    - Checks the entire process list by individually querying each PID through sysctl using KERN_PROC_PID
    - Also compares the process list to the kernel's open-file table to check if a PID owns a open file even if the PID is missing from the process list
    - Kill is also used to check if a process exists despite being hidden
    - Process is flagged if it appears in 2 file table snapshots, passes both the initial and final signal checks but remains absent from three process snapshots
    - Risk threshold of 5 -> if there are 5 or more suspicious activity, then it reports back 1

# Overall risk detection
- Each hooked syscall adds 1 point; the syscall check reports 1 at 3 points
- If any detector reports 1, the detector script returns 1
- The script also adds every check's risk score together. If the total reaches 10, it returns 1 even when no individual check reports 1

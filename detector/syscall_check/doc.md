* The check is performed on a selected set of system calls.
* On each system call, the name and the number of it are taken into account. 
* An array of `struct nlist` is initialised with the first element's `n_name` set to "sysent" to fetch the address of sysent (system call table); and the second element's `n_name` set to the name of the syscall function that needs checking.
* To start reading the kernel memory, we need to initialise the kd (of type `kvm_t *`) to the file pointer returned by `kvm_openfiles`.
* `kvm_nlist` is then called with `kd` and `nl` to fetch the data relating to the names set in the `struct nlist` array.
* After calling `kvm_nlist`, the `n_value` of the first element contains the pointer to the `sysent` table. This is then be used to calculate the address of the syscall in the table given the syscall number (which is equivalent to the offset in the table).
* The calculated address is then used to access the entry of the table and copy the value to a local `struct sysent` variable.
* The `n_value` of the second element contains the address of the original syscall function implementation. This value can be used to compare with the `sy_call` in `struct sysent` above. If two values are equal, the syscall function pointer is pointing to its supposed function. Otherwise, the syscall has been hooked

# FreeBSD Rootkit - Final Design

## Architecture

```text
Installer --build/load--> rootkit.ko --creates--> /dev/rootkit
Remote --UDP magic :4444--> kernel listener --wake/source IP--> revshell
revshell --WAIT_REMOTE, ELEVATE ioctls--> root --TCP callback :4444--> Remote
```

## Install and persistence

`install` checks source paths and required commands, builds `rootkit.ko` with FreeBSD's kernel-module build system, and compiles `elevate`, `revshell`, `remote`, and `user/hide_kld`. It copies the module to `/boot/modules/rootkit.ko`, adds `rootkit` to `kld_list` with `sysrc`, and loads it if needed. It installs `elevate` and `revshell` under `/usr/local/bin`, starts `revshell` for the current boot, and runs the absolute `hide_kld` path, that path is also added to `/etc/rc.local` for subsequent boots. The absolute path avoids dependence on the boot-time working directory or project-directory name. It does not preserve the helper if its containing directory is moved or removed, the helper must remain at the recorded path.

| Observable | Expected artifact |
|---|---|
| Module persistence | `/boot/modules/rootkit.ko`, `rootkit` in `/etc/rc.conf` `kld_list`, module load recreates `/dev/rootkit` |
| Device | `/dev/rootkit`, created on module load, root:wheel, mode `0666` |
| User helpers | `/usr/local/bin/elevate`, `/usr/local/bin/revshell` |
| Concealment startup | compiled `user/hide_kld`, absolute-path entry in `/etc/rc.local` |
| Other install details | `revshell` is launched by `install`, not configured to restart at boot; a second `./install` prints that the module is already loaded and exits 0 |

Removal is the reverse and has its own trap. While the module is loaded, `modfind`, `fstatat`, `getdirentries`, `open` and `access` all cooperate to make the module and any path containing the name disappear, so a script that stats or deletes anything before unloading concludes nothing was installed. `./uninstall` therefore turns hiding off through `sys/kld_hiding` (empty module name), unloads, and only then deletes `/boot/modules/rootkit.ko`, the three helpers, the `kld_list` entry and the `/etc/rc.local` lines.

## Privilege escalation and remote

`elevate` opens `/dev/rootkit` and issues the elevation ioctl handled by `kernel/interface.c`, on success it execs a root shell. Separately, `revshell` opens the device and issues `rootkit_WAIT_REMOTE`, which blocks until the in-kernel UDP listener matches `BSD_rootkit_REMOTE_MAGIC_TRIGGER_v1` and returns the sender's IP. It then issues `rootkit_ELEVATE`, which creates a credential with user IDs 0 and group `wheel`, installs it on the calling process under its process lock, and returns to userland. `revshell` connects to the sender on TCP `4444`, redirects standard input/output/error to that socket, and execs interactive `/bin/sh`.

## Concealment

| Name | Mechanism |
|---|---|
| **Directory listing filter** | Replaces `SYS_getdirentries`, calls the original handler, copies its returned bytes from the user buffer into a kernel buffer, and walks variable-length `dirent` records using `d_reclen`. It removes matching entries by shifting subsequent bytes with `memmove`, then copies the modified records back and reduces the returned byte count. |
| **Module-list hiding** | Filtering at the syscall boundary, not surgery on kernel lists. `kldnext`, `kldfind`, `kldstat`, `modfind` and `modstat` are replaced; any answer naming this module comes back `ENOENT`. The last two are the ones that matter: `kldstat -m` does not call `kldfind`, it calls `modfind` and then `modstat`, which is why an earlier version hid the module from `kldstat` while `kldstat -m rootkit` still printed it. A trace of the two paths is in the concealment notes below. |
| **TCP PCB-list hiding** | Registered as `sys/port_hiding`. It walks `V_tcbinfo.ipi_listhead` under the PCB info lock, unlinks entries whose local or foreign port matches, and subtracts what it removed from `ipi_count`, because the counter and the list are otherwise left inconsistent -- which is exactly the discrepancy the detector's second check looks for. |
All three alter an enumeration view rather than the object being enumerated: the file is still on disk, the module is still in the kernel, the socket is still established. Every replaced syscall entry is saved first and restored by `rk_remove_hooks()`, and the log's `selinfo` is drained before the rest of the module is torn down, so an unload cannot leave a hook pointing into freed text.

Hiding does not depend on any symbol the kernel keeps `static`. The first version spliced the module out of `modules` and `linker_files` directly, which needed `kld_sx`, `linker_files` and `modules`, all file-static in 14.5. That only linked because this kernel resolves locals through `link_elf_leak_locals`; the replacement finds its own id with `linker_file_foreach()` -- a public API -- and answers syscalls instead of editing the list.

## Logging/key capture

Keyboard input reaches `read()` on a terminal in both cases the assignment names: a shell on the physical console reads a tty, and sshd gives the login shell a pty, which that shell reads the same way. Programs that read through libc (`cat`, `su`, an editor's prompt) are captured by the same path. What matters is the *type of the file*, not the descriptor number: sshd may hand the pty to the child on any free descriptor, and a pseudo-terminal is not even a vnode file.

```text
tty / pty --read(0)--> kernel/log.c hook --line assembly--> 64 KB ring
                                                             ^
                                       /dev/rootkit  read()/poll()
                                                             |
                                       /usr/local/bin/rklog (logsrc/sender.c)
                                                             | TCP :9999
                                       ./log on $REMOTE --> exfil.log + stdout
```

Capture is in the kernel because the terminal read can only be observed there, before the caller consumes the bytes; delivery is in userland because retries, spooling and name resolution cannot panic the box from there.

| Part | Implementation |
|---|---|
| `kernel/log.c` | `sysent[SYS_read]` is patched with `rk_read_hook`, which calls the genuine `read()` first and copies in only the bytes it actually returned. The descriptor is resolved with `fget_read()` and the file must be a terminal in either of its two shapes: `DTYPE_PTS` for a pty -- `finit()` in `tty_pts.c` hands those out as their own type, so a `DTYPE_VNODE` test alone matches `/dev/console` and nothing else -- or a vnode with `VV_ISTTY`/`VCHR`. The descriptor *number* is not the test: sshd and `su(1)` give the pty to the child on whatever descriptor is free. The one character device that must not be captured is our own: `rootkit_is_our_vnode()` compares `vp->v_rdev` against the cdev returned by `make_dev_p()`, which stops the sender's drain of `/dev/rootkit` from feeding the ring its own output. Reads that begin with `!` are dropped as well, and so are the daemons that read the console for their own reasons (`devd`, `syslogd`): one of them alone produced megabytes of its own traffic and buried every keystroke. |
| Line assembly | Bytes are assembled into lines before entering the ring, so one entry means one command instead of one entry per `read()`. `\r` (what a pty sends for Enter) and `\n` both end a line, the `\n` of a CRLF pair is swallowed, and a pending partial line is flushed when pid or uid changes and on unload. Each entry carries a single `[t=seconds.micro pid= uid=] ` header. |
| Ring | 64 KB, drops the oldest bytes when full, so a burst never leaves a torn line at the front. There is no `sysctl` control plane: a tree named `kern.rootkit` is the first thing a detector greps for, and the previous version advertised `bytes`, `entries`, `dropped` and a `fd0_debug` classifier under that name. The ring is read through `/dev/rootkit` and nowhere else. |
| Device | `/dev/rootkit` gained `d_read`/`d_poll`; an empty ring returns a short read instead of blocking, and `poll()` wakes through `selrecord`/`selwakeup`. `rk_log_uninit()` drains the selinfo before restoring both syscalls, so an unload cannot leave a wait channel pointing at freed memory. |
| `logsrc/sender.c` | Installed as `/usr/local/bin/rklog` by `install`, started with the collector address from `$1` and re-added to `/etc/rc.local` with `-d` so it survives logout and reboot. It queues 4 MB in memory, appends to `/var/log/.rklog.spool` (8 MB, oldest dropped) while the collector is unreachable, replays the spool ahead of newly captured bytes after reconnecting, and truncates it only once every byte was handed to the socket. Reconnects back off from 500 ms to 30 s and re-resolve the host, so an IP or a hostname both work. |
| `log` (root wrapper) and `logsrc/collector.c` | `./log <TARGET_IP> [PORT] [LOGFILE] [-f]` compiles the collector with the first C compiler it finds and `exec`s it, because the archive is unpacked fresh on the remote host. The collector listens on `0.0.0.0:9999` (the port must match the sender), appends to `exfil.log`, rotates it to `.1` at 8 MB, echoes to stdout, and fsyncs on disconnect. It accepts any peer and only prints a note when the source address differs from `<TARGET_IP>`; `-f` turns that into a refusal. Strict matching is not the default because the two machines are not on the same network and NAT (QEMU's slirp included) rewrites the peer address, which would silently discard the exfiltrated data. |

Verified on FreeBSD 14.5: the module builds under `-Werror`, `install <collector>` returns 0 and starts `rklog`, `/dev/rootkit` is openable while `/dev` does not list it, and a reboot brings both the module (`kld_list`) and the daemon (`/etc/rc.local`) back. Keystrokes reach the collector end to end: a command typed into a pty handed out by `script(1)` lands in the received file as `echo SECRET42`, and a command typed into a real `ssh -tt` session to the same box lands as `echo SECRET99` -- 11,055 bytes of captured input, delivered from `read()` through the ring, `/dev/rootkit`, `rklog` and TCP.

A fresh install leaves no trace of the name: `kldstat` and `kldstat -m` find nothing, `sysctl -a | grep -i rootkit` and `dmesg | grep -i rootkit` both return zero matches, and `/dev` does not list the device even though `open()` on it succeeds. The unload path prints nothing either; an earlier version left `rootkit: module unloaded` in the message buffer for any detector that greps `dmesg`.

There is no quick way to iterate on the module once it is loaded. Unloading it by hand needs hiding turned off first (`/usr/local/bin/hide_kld -u`, which sends the empty name to `sys/kld_hiding`), because `kldunload` looks the module up with the same `modfind` that answers `ENOENT`. `./uninstall` does exactly that, then unloads, then deletes -- in that order, since every path containing the name answers `ENOENT` while the module is loaded.

## Changes since the midpoint

| Area | Change |
|---|---|
| Hiding | Now filtering at the syscall boundary instead of splicing kernel lists, and it covers `modfind`/`modstat` in addition to the `kld*` calls. `sys/kld_hiding` and `sys/port_hiding` are both registered by `rootkit.ko`. The standalone `hiding/` prototype is gone: it registered the same module names (`module_register` returns `EEXIST`, 17) and patched the same `sysent` slot, so loading it after the main module would have silently reverted the directory filter. |
| Key capture | A pty is `DTYPE_PTS`, not `DTYPE_VNODE`, so the first version captured the console and nothing else -- no sshd, no `su`, no `script`. Both types count now, the console daemons (`devd`, `syslogd`) are skipped by name, and the `kern.rootkit.*` sysctl tree is gone because a detector greps for exactly that word. |
| Removal | `./uninstall` is new: unhide, unload, then delete, because every check that runs earlier sees a machine with no rootkit installed. |
| Detection | New: `detector/`, a kernel module plus a userland script, described below. Nothing under `rootkit/` was changed to accommodate it. |

## Detection design

Detection is one tree, `detector/`, and both halves of my area are in it: `kmod/detector.c` reads what userland cannot see honestly, `detect.sh` does the `kld_list` bookkeeping and the processless-socket check, and `./detect` folds every check into a single risk score. The filesystem and persistence artefacts, the process table, and syscall integrity are the three userland checkers sitting next to them; they were separate PRs and are merged into the same directory now.

### Why a kernel module

Both signals worth acting on live in kernel structures. `kldstat` and `netstat` read the same lists the rootkit edits, so a userland tool built on them reports a clean host while `kld_hiding` is doing its job. Only reading the structures underneath shows the discrepancy.

### Why it does not scan on load

`MOD_LOAD` runs inside the linker with `kernel_map` already write-locked, and the walk wants `vm_map_lock_read()`. A scan there hangs `kldload` with no output and no recovery short of a reboot. That took three attempts to accept.

So `kldload detector.ko` registers sysctls and nothing else. `sysctl kern.detector.scan=1` runs one pass from ordinary process context, where sleeping is permitted. `detect.sh` issues that call, which is why the script works on a host where the module was loaded hours ago.

### The two checks

| Check | Signal | Verdict |
|---|---|---|
| **Executable mappings** | Entries in `kernel_map` with `VM_PROT_EXECUTE` and at least a page long that overlap neither the kernel image nor any region claimed by a `linker_file`. The claimed regions are collected first with `linker_file_foreach()`, then the map is walked with `VM_MAP_ENTRY_FOREACH()`. | `confirmed` |
| **TCP PCB counter** | `V_tcbinfo.ipi_count` larger than the number of entries reachable through `INP_ALL_ITERATOR()`, same answer on three samples 100 ms apart. | `confirmed` |

### Why both may say confirmed, and how that changed

The first version let only the PCB counter convict. The reasoning was that from inside `kernel_map` a hidden module and a legitimate one are indistinguishable: `kld_hiding()` removes the entry from both `modules` and `linker_files`, so `hiding.ko` looks exactly like `zfs.ko` — executable pages that nothing in the image accounts for.

That reasoning had a hole. `linker_file_foreach()` is public (`linker.h:160`); it takes `kld_sx` internally and visits every loaded file. Collecting those ranges before touching the map turns the check from "is this page inside the kernel image" into "does any loaded file claim this page". `zfs.ko` is claimed; a mapping allocated by a module and never registered is not. The census can therefore convict, with one caveat that has to be handled explicitly: the collection must happen *before* `vm_map_lock_read()`, because `kldload` takes `kld_sx` first and `kernel_map` second, so the reverse order is a lock-order reversal against a concurrent load.

Two false positives showed up while getting this right, and both are now guarded:

- `linker_kernel_file->address` points at the kernel's text section, 2 MB above `KERNBASE`, not at the ELF header, and `size` is smaller than the whole mapped image. Containment tests miss the head of the image; the test has to be an overlap.
- `kernel_map` begins at `VM_MIN_KERNEL_ADDRESS`, far below `KERNBASE`. The direct map and KVA live there, are executable, and belong to no `linker_file` at all, so entries below the kernel image are skipped before they are counted.

The PCB counter stays as the second, independent signal, and the reason it is worth having separately is that it does not depend on the linker at all: `in_pcballoc()` increments it and links the entry, `in_pcbfree()` decrements it and unlinks it, and `port_hiding()` calls `CK_LIST_REMOVE()` without either, so the counter sits permanently one ahead of the list.

### Why the module list is still not compared directly

`linker_file_foreach()` gives the ranges, but not the names to go with them, and it cannot remove anything: un-hiding a `kld_hiding`'d module means splicing a `TAILQ` whose head (`kern_linker.c:117`) is `static`. Detection only needs to observe, so that is enough — but it also means the census reports "an executable mapping that no loaded file claims", not "the module named X is hidden". The name has to come from elsewhere; the syscall check recovers it by comparing `sysent[]` against the module images.

### Why the walk takes the pcb lock, and why three samples

`ipi_count` and the list are updated by different threads, so a scan racing with a connect or a close can see a delta that disappears on the next pass. Reporting that would be a false positive on any busy host, so the count is compared three times, 100 ms apart, and only a delta that survives all three is reported.

The walk itself goes through `INP_ALL_ITERATOR()` and `inp_next()`, which take `INPLOOKUP_RLOCKPCB` on each pcb as it is visited. It has to run to completion: `inp_next()` releases the pcb lock and the SMR reference only on the call that returns NULL, so breaking out early leaks both. The previous version walked `ipi->ipi_listhead` under `CK_LIST_FOREACH` with no lock at all -- on 14.5 that list is SMR-protected, and a scan racing with `CK_LIST_REMOVE` walks freed memory.

### The userland half

`detect.sh` covers what cannot be confirmed from userland, and never prints more than `suspect`. Two bookkeeping discrepancies: a module present in `/boot/modules` or named in `kld_list` that `kldstat` does not report, and a socket in `sockstat` with no owning process.

Both are reconciled against kernel sources the rootkit edits independently, which is the only reason they are worth printing.

### Measured

FreeBSD 14.5 under QEMU, `kern.osreldate=1405000`, everything built under `-Wall -Wextra` (`-Werror` for the userland half of the detector):

```text
Module census, clean host:     entries=10 exec=4 linker_files=4 unclaimed=0
                               module status=clean conf=high
Module census, hooktest.ko:    confirmed=1 -- the 16 KB RWX mapping at
                               0xffffffff83000000 is claimed by no linker_file
./detect, clean host:          persistence 0, process 0, syscall-hooks 0,
                               kernel-modules suspect=1, total 1, verdict=clean
./detect, rootkit loaded:      persistence 10, syscall-hooks 11,
                               total 21 threshold 10, verdict=rootkit-suspected
```

The single suspect on a clean host is a `? ? ? ? udp4 *:4444` socket. `sockstat` prints one `?` in the process column when it cannot attribute a socket, and `detect.sh` used to look for `???`, so that line never fired.

The module census does not convict the rootkit, and that is the honest result: its text belongs to a linker_file, so it looks like any other module from `kernel_map`. What the census does convict is an executable mapping that no module claims -- demonstrated above with a two-line test module that allocates one. The rootkit is caught by the other two checks, which is the division of labour the design intends.

Two behaviours of the census are worth recording, because both were false positives before:

- `linker_kernel_file->address` points at the kernel's text section (2 MB above `KERNBASE`), not at the ELF header, and its `size` is smaller than the mapped region. The test has to be an overlap check, not containment.
- `kernel_map` starts at `VM_MIN_KERNEL_ADDRESS`, which is far below `KERNBASE`; the direct map and KVA live there, are executable, and belong to no linker_file. Everything below the kernel image is skipped.

## Summary

```text
Files/startup:  /boot/modules/rootkit.ko, kld_list, /dev/rootkit,
                /usr/local/bin/{elevate,revshell,rklog}, /etc/rc.local, user/hide_kld
Kernel:         getdirentries/fstatat/open filtering, kld*/modfind/modstat
                filtering, read() hook + ring buffer, port_hiding
Runtime/network: revshell -> interactive shell, UID/GID change to 0,
                 UDP trigger and TCP callback on 4444
Log:            rklog -> TCP 9999 -> ./log on $REMOTE -> exfil.log,
                captured from terminal files (tty and pty), one line per command
Removal:        ./uninstall -- unhide, unload, then delete
```

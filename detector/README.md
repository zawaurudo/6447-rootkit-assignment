# detector

My part is kernel-module concealment and the network side.

| Path | Half |
|---|---|
| `kmod/detector.c` | the kernel module. `kernel_map` census and the TCP pcb counter check. |
| `detect.sh` | userland checks: `kld_list` vs `kldstat`, and sockets with no owning process. |
| `detect` | the single entry point named in the spec. Runs the C checkers and folds `detect.sh`'s summary into the same risk score. |
| `demo.sh` | three-phase demo, transcript-ready. |

Only the module prints `confirmed`. The script stops at `suspect` no matter how convincing the evidence looks, because everything it reads is userland data and the rootkit can fake that.

## Build and run

```sh
cd detector
make                                 # userland checkers, detect and detect.sh
make kmod                            # -> kmod/detector.ko (FreeBSD only)

sudo kldload ./kmod/detector.ko      # registers sysctls, does not scan
sudo sysctl kern.detector.scan=1     # one pass
dmesg | grep DETECTOR | tail -20

sysctl kern.detector.confirmed kern.detector.suspect
sudo kldunload detector
```

`kmod/` is its own directory because `bsd.kmod.mk` takes over the default target and would fight the userland rules if both lived in one Makefile.

`kldload` does not scan by itself. The load path comes in with `kernel_map` already held, and the pass needs the same map. Scanning there deadlocks `kldload` until the box reboots. `detector_modevent()` has the three attempts that led to that conclusion.

`sh detect.sh` prints the full report, `sh detect.sh -q` prints the summary line only. `./detect` runs everything and exits non-zero once the risk score reaches the threshold; it only calls `detect.sh` on FreeBSD (`DETECTOR_SKIP_SCRIPT_CHECKS=1` turns that off). `sh demo.sh` runs phase 1 and changes nothing. `DETECTOR_INSTALL_ROOTKIT=1 sh demo.sh` adds phases 2 and 3, and should only run on a throwaway VM.

## Output

```text
DETECTOR <class> status=<confirmed|suspect> conf=<high|low> evidence="<one sentence>"
DETECTOR summary confirmed=<N> suspect=<M>
```

`class` is `module` or `pcb` when it comes from the module, `module` or `socket` when it comes from `detect.sh`. One line per finding. The evidence field quotes the numbers the verdict was based on, so a reader can check the arithmetic instead of trusting the word.

`kern.detector.confirmed` and `kern.detector.suspect` carry the same two counts for scripting. `kern.detector.verbose=0` suppresses the suspect lines.

## The two checks

| Check | Signal | Verdict |
|---|---|---|
| **module** | `kernel_map` entries with `VM_PROT_EXECUTE`, between `PAGE_SIZE` and 64 MB long, that do not intersect `[linker_kernel_file->address, +size)`. Walked by address through `vm_map_lookup_entry()`, bounded to `ki->end + 64 MB`, own mapping skipped. | `suspect` |
| **pcb** | `V_tcbinfo.ipi_count` larger than the entries reachable from `V_tcbinfo.ipi_listhead` by `CK_LIST_FOREACH`, same delta on three samples 100 ms apart. | `confirmed` |

### module

`kld_hiding()` takes a module out of the `modules` queue and out of `linker_files`. After that `kldstat`, `kldstat -v` and `modfind` all come back empty. What it cannot do is unmap the code.

The pages are still in `kernel_map` with `VM_PROT_EXECUTE` set, and no entry in the module list claims them. The trouble is that a module loaded the normal way looks identical in the map. An address says nothing about who mapped it.

So the check prints one census line, `census entries=N exec=N outside_image=N`, plus up to eight details, and never a verdict. Its value comes from comparing two passes. On a clean host there are two such mappings. After `kldload rootkit.ko` there are three, and the new one is the module's own text (`0xffffffff82822000-0xffffffff82824000`).

### pcb

`port_hiding()` walks `V_tcbinfo.ipi_listhead` and calls `CK_LIST_REMOVE()` on the pcb whose local or foreign port matches. It does not call `in_pcbdrop()`, does not free the pcb, and leaves the hash table alone.

`in_pcballoc()` increments `ipi_count` and links the entry. `in_pcbfree()` decrements it and unlinks it. One unlink without a free therefore leaves the counter permanently one ahead of the list.

The check counts both tables by hand, `V_tcbinfo` and `V_udbinfo`, under `CURVNET_SET(TD_TO_VNET(curthread))`. It takes three samples and reports `confirmed` only if all three agree.

Three samples because pcbs come and go constantly. A single count taken while a connection is being torn down is off by one for reasons that have nothing to do with a rootkit. A real leak does not flicker, so agreement across samples is the discriminator.

Neither table is locked during the walk. The inpcb locks are taken by paths that can sleep, so holding one across `CK_LIST_FOREACH` risks a deadlock. A torn read costs at most one of the three samples. A detector that hangs the box it was supposed to diagnose has already caused more damage than a miss.

### The userland half

`detect.sh` adds a bookkeeping angle to both checks, and marks everything `suspect`.

For modules: a name that `kld_list` asks for, whose `.ko` is sitting in `/boot/modules`, and that neither `kldstat -n` nor `kldstat -m` can resolve. That is the shape `kld_hiding()` leaves behind, because `install` keeps asking for that module at every boot.

For sockets: a listening socket with no owning process in `sockstat`. That is what a `socreate()` from inside a module looks like. Confidence is low on purpose, because the NFS client and netgraph produce the same picture.

## Measured

Clean host, then `rootkit.ko` loaded, then the rootkit's own concealment switched on:

```text
clean:       confirmed=0 suspect=2   census entries=10 exec=4 outside_image=2
             the two are intpm.ko 0xffffffff82818000 and smbus.ko 0xffffffff8281c000, both built in
rootkit.ko:  confirmed=0 suspect=3   census entries=13 exec=5 outside_image=3
             the new line is 0xffffffff82822000-0xffffffff82824000, that module's text
port_hide:   netstat 4444 goes 2 -> 1, next scan confirmed=1
             tcp ipi_count=4 list=3 delta=1 on samples 0, 1 and 2
```

## Clean-host matrix

| # | Configuration | Result |
|---|---|---|
| 1 | Bare install | `confirmed=0 suspect=2`, the two built-in modules, own mapping skipped |
| 1b | Second scan on the same host | same output, nothing carried over |
| 2 | `kldload linux` + `kldload zfs` (526 module entries) | `confirmed=0 suspect=4`, `entries=17 exec=6 outside_image=4` |
| 2b | `kldload ipfw` on top | not measured, `ipfw2 ... default to deny` cuts the host off the network as it loads |
| 3 | `jail -c name=j1 path=... vnet persist` | `confirmed=0 suspect=4` with the jail up |
| 4 | `nc -l 4444` then `./port_hide 4444` | `confirmed=0 -> 1`, `tcp ipi_count=4 list=3 delta=1` on all three samples |
| 5 | 10 x `kldunload` / `kldload` / scan | same summary every cycle, one instance left |
| 6 | `kldload rootkit.ko` | `confirmed=0 suspect=3`, census grows by `0xffffffff82822000-0xffffffff82824000` |
| 7 | 500 connections then scan (`TIME_WAIT` churn) | not run, the three-sample rule is the mitigation, not a measurement yet |

Everything above was measured on 2026-11-16 in a QEMU FreeBSD 14.5 VM (`kern.osreldate=1405000`).

The VM had two vCPUs, but only for compiling. Under TCG the kernel trips its `spin lock held too long` watchdog within a few minutes of SMP load, so every scan ran on one vCPU.

Row 2 is the row that matters for the marking. A host carrying a dozen legitimate modules must not read as compromised, and that is the whole reason the census is `suspect` and nothing more.

## What I found about our own concealment

`remote_listener_thread()` builds a **UDP** socket. `port_hiding()` walks `V_tcbinfo`, which is the **TCP** table. UDP pcbs live in `V_udbinfo` instead.

So `port_hide 4444` on a host with no TCP traffic on port 4444 matches nothing. When it does match, it hides the wrong pcb.

What that looks like in practice: `sockstat -U` still lists the listening UDP socket, with `???` where the process should be, while the TCP counter check stays clean. So the socket gets caught by the processless-socket line, and the code behind it by the census.

Pointing `port_hiding()` at `V_udbinfo` would make the delta check fire. It would also leave a `CK_LIST_REMOVE()` without `in_pcbdrop()`, which is a use-after-free waiting for the socket to close. That defect is not mine to change, and it is written up in `../writeup.md`.

## Porting notes

Two places depend on the release.

`det_kernel_image()` reads `linker_kernel_file->address` and `.size`. That size is set from `__endkernel - __startkernel` (`link_elf.c:482`), so the bounds stay correct across builds without hardcoding anything.

`det_scan_modules()` depends on the map layout. On 14.x `kernel_map` is an rbtree: `struct vm_map_entry` has `left` and `right`, and `map->root` is the root. Following those links from inside a module does not terminate, which cost me an afternoon. The walk goes by address instead, using the kernel's own `vm_map_lookup_entry()` to find the next entry.

## Files

| File | What it is |
|---|---|
| `detector.c` | the module: `det_scan_modules()`, `det_scan_pcbs()` |
| `Makefile` | `bsd.kmod.mk`, nothing else |
| `detect.sh` | userland half: `kld_list` bookkeeping, processless sockets |
| `demo.sh` | phase 1 clean host, phases 2 and 3 rootkit and concealment |
| `port_hide.c` | calls `sys/port_hiding` so the demo can switch concealment on |

`port_hide.c` lives here rather than in `rootkit/` so that `rootkit/` stays byte-identical to what the group handed in.

It also documents the ordering trap. The syscall number comes from `modfind("sys/port_hiding")`, and that only works while the module file is still reachable through `linker_files`. Run it before hiding the module, or pass the number explicitly.

h.md` instead.

## Porting notes

Two places are release-sensitive.

* `det_kernel_image()`: `linker_kernel_file->address` and `.size`. The size
  comes from `__endkernel - __startkernel` (`link_elf.c:482`), so the bounds
  stay right across builds.
* `det_scan_modules()`: on 14.x `kernel_map` is an rbtree, `struct
  vm_map_entry` has `left`/`right` and `map->root` is the root. Following those
  links from inside a module doesn't terminate, which is why the walk goes by
  address through `vm_map_lookup_entry()` instead.

Built and measured on FreeBSD 14.5, the release `../rootkit/writeup.md` records.

## Clean-host matrix

Each row should end in `confirmed=0`.

| # | Configuration | Result |
|---|---|---|
| 1 | Bare install | `confirmed=0 suspect=2`, the two built-in modules (`intpm.ko`, `smbus.ko`); own mapping skipped (measured) |
| 1b | Second `sysctl kern.detector.scan=1` on the same host | same output, nothing carried over (measured) |
| 2 | `kldload linux` + `kldload zfs` (526 module entries) | `confirmed=0 suspect=4`, `entries=17 exec=6 outside_image=4` (measured) |
| 2b | `kldload ipfw` on top | not measured: `ipfw2 … default to deny` cuts the test host off the network as it loads, so the scan can't be collected |
| 3 | `jail -c name=j1 path=… vnet persist` | `confirmed=0 suspect=4` with the jail up (measured) |
| 4 | `nc -l 4444` then `./port_hide 4444` | `confirmed=0 → 1`, `tcp ipi_count=4 list=3 delta=1` on all three samples (measured) |
| 5 | 10 × `kldunload` / `kldload` / scan | same summary every cycle, one instance left (measured) |
| 6 | `kldload rootkit.ko` | `confirmed=0 suspect=3`, census grows by `0xffffffff82822000-0xffffffff82824000` (measured) |
| 7 | 500 connections then scan (`TIME_WAIT` churn) | not run; the three-sample rule is the mitigation, not a measurement yet |

Measured on 2026-11-16 in a QEMU FreeBSD 14.5 VM (`kern.osreldate=1405000`).
The VM used two vCPUs for compiling only: under TCG, SMP trips the kernel's
`spin lock held too long` watchdog within a few minutes, so every scan ran on a
single vCPU.

Row 2 is the one that matters for the marking. With `linux.ko` and `zfs.ko`
loaded the check stays at `confirmed=0` while the census climbs to four. A host
with a dozen legitimate modules must not read as compromised, which is why the
census is `suspect` and nothing more.

## Files

| File | What it is |
|---|---|
| `detector.c` | the module: `det_scan_modules()`, `det_scan_pcbs()` |
| `Makefile` | `bsd.kmod.mk`, nothing else |
| `detect.sh` | userland half: `kld_list` bookkeeping, processless sockets |
| `demo.sh` | phase 1 clean host, phases 2/3 rootkit and concealment |
| `port_hide.c` | calls `sys/port_hiding` so the demo can switch concealment on |
| `README.md` | this file |

`port_hide.c` is here rather than in `rootkit/` so that

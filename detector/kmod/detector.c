/*
 * detector.c - 6447 rootkit assignment, kernel half of the detector.
 *
 * The rootkit lies through every interface you'd normally reach for:
 * readdir (getdirentries is patched), kldstat (entries get unlinked from
 * modules and linker_files), netstat (inpcbs get pulled out of the protocol
 * lists). Asking those interfaces questions only measures how good the
 * hiding is, so this walks the structures underneath them instead and looks
 * for bookkeeping that has stopped adding up.
 *
 * This file covers the two areas I own: kernel modules and the network side.
 * The other areas (filesystem, processes, persistence, device nodes, logs,
 * syscall integrity) are somebody else's PR.
 *
 *   module - everything executable in kernel_map that isn't the kernel image
 *     arrived from a module. The address says nothing about who loaded it, so
 *     this is a census and it only ever says suspect.
 *
 *   pcb - ipi_count vs the number of inpcbs actually reached by walking
 *     ipi_listhead, three samples, all three identical. ipi_count goes up in
 *     in_pcballoc() and down only in in_pcbfree(); port_hiding() does a
 *     CK_LIST_REMOVE() and no free, so the counter stays ahead for good. This
 *     is the one check here that says confirmed.
 *
 * usage:
 *   kldload ./detector.ko
 *   sysctl kern.detector.scan=1
 *   sysctl kern.detector.summary
 *   dmesg | grep DETECTOR
 *
 * detect.sh does all of that; detector/README.md has the longer version.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/libkern.h>
#include <sys/stdarg.h>
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/mbuf.h>
#include <sys/sx.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <sys/sockopt.h>
#include <sys/linker.h>
#include <sys/file.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>
#include <machine/vmparam.h>

#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>

#define DET_WALK_MAX		200000	/* hard stop for the kernel_map walk */
extern void DELAY(int usec);		/* sys/systm.h does not pull it in here */
#define DET_SAMPLES		3
#define DET_MODULE_MAX		(64UL * 1024 * 1024)	/* module text cap */

static int	det_confirmed;
static int	det_suspect;
static int	det_verbose = 1;

SYSCTL_DECL(_kern);
SYSCTL_DECL(_kern_detector);
SYSCTL_NODE(_kern, OID_AUTO, detector, CTLFLAG_RW, 0,
    "6447 rootkit detector");
SYSCTL_INT(_kern_detector, OID_AUTO, confirmed, CTLFLAG_RD,
    &det_confirmed, 0, "confirmed findings from the last pass");
SYSCTL_INT(_kern_detector, OID_AUTO, suspect, CTLFLAG_RD,
    &det_suspect, 0, "suspect findings from the last pass");
SYSCTL_INT(_kern_detector, OID_AUTO, verbose, CTLFLAG_RW,
    &det_verbose, 0, "print suspect findings as well as confirmed ones");

/* helpers */

static void
det_finding(const char *cls, const char *status, const char *conf,
    const char *evfmt, ...)
{
	va_list ap;
	char ev[256];

	if (strcmp(status, "suspect") == 0 && !det_verbose)
		return;

	va_start(ap, evfmt);
	vsnprintf(ev, sizeof(ev), evfmt, ap);
	va_end(ap);

	printf("DETECTOR %s status=%s conf=%s evidence=\"%s\"\n",
	    cls, status, conf, ev);

	if (strcmp(status, "confirmed") == 0)
		det_confirmed++;
	else
		det_suspect++;
}

/* ------------------------------------------------------------------ */
/* check 1: module text mapped but owned by no linker_file             */
/* ------------------------------------------------------------------ */

/*
 * Range of the statically linked kernel. link_elf.c sets
 * linker_kernel_file->size = __endkernel - __startkernel, so anything
 * executable outside this came in later: kldload(), or something pretending
 * to be kldload().
 */
struct det_kimage {
	vm_offset_t	start;
	vm_offset_t	end;
	int		valid;
};

static void
det_kernel_image(struct det_kimage *ki)
{
	linker_file_t	kf;

	ki->valid = 0;
	kf = linker_kernel_file;
	if (kf != NULL && kf->address != NULL && kf->size != 0) {
		ki->start = (vm_offset_t)kf->address;
		ki->end = (vm_offset_t)kf->address + kf->size;
		ki->valid = 1;
	}
}

/*
 * Everything executable in kernel_map came from a module. The address alone
 * can't separate a legitimate module from a hidden one, so this is a census
 * and not a verdict: one quiet line on a clean host, and it only becomes
 * interesting once something has named the code it is counting.
 *
 * vm_map is an rbtree here and following entry->left out of a module doesn't
 * terminate (found that out the hard way), so the walk goes by address
 * through vm_map_lookup_entry(), which is the kernel's own search.
 */

static void
det_scan_modules(const struct det_kimage *ki)
{
	vm_offset_t	 addr, limit;
	vm_map_entry_t	 e;
	int		 outside, listed, total, nexec, guard;

	if (!ki->valid) {
		det_finding("module", "suspect", "low",
		    "linker_kernel_file has no address/size; cannot tell "
		    "kernel text from module text");
		return;
	}

	outside = 0;
	listed = 0;
	total = 0;
	nexec = 0;
	addr = ki->start;
	/* Modules sit right after the image and every step of this is an
	 * rbtree search, so keep the window tight - an unbounded range turns
	 * the check into a minute of emulated kernel work. */
	limit = ki->end + DET_MODULE_MAX;
	if (limit > (vm_offset_t)VM_MAX_KERNEL_ADDRESS)
		limit = (vm_offset_t)VM_MAX_KERNEL_ADDRESS;

	vm_map_lock_read(kernel_map);
	guard = 0;
	while (addr < limit && vm_map_lookup_entry(kernel_map, addr, &e)) {
		if (++guard > DET_WALK_MAX)
			break;			/* never spin on a stale map */
		total++;
		if (e->end <= addr)
			break;			/* corrupt entry, stop */
		if ((e->protection & VM_PROT_EXECUTE) != 0 &&
		    (e->end - e->start) >= PAGE_SIZE &&
		    (e->end - e->start) <= DET_MODULE_MAX) {
			nexec++;
			/* No `continue' here: it would skip the advance at
			 * the bottom of the loop, the entry holding this
			 * very function would come back on the next lookup
			 * and the walk would spin. Costs one indented if,
			 * saves an afternoon. */
			if (!((vm_offset_t)(uintptr_t)&det_scan_modules >=
			    e->start && (vm_offset_t)(uintptr_t)&det_scan_modules
			    < e->end)) {
				if (e->end <= ki->start || e->start >= ki->end) {
					outside++;
					if (listed++ < 8) {
						det_finding("module", "suspect",
						    "low", "executable mapping "
						    "0x%jx-0x%jx (%ju bytes) lies "
						    "outside the kernel image: text "
						    "of a loaded module, or of one "
						    "that unlinked itself from the "
						    "module list",
						    (uintmax_t)e->start,
						    (uintmax_t)e->end,
						    (uintmax_t)(e->end - e->start));
					}
				}
			}
		}
		addr = e->end;
	}
	vm_map_unlock_read(kernel_map);

	if (det_verbose)
		printf("DETECTOR module census entries=%d exec=%d "
		    "outside_image=%d\n", total, nexec, outside);

	if (det_verbose && outside == 0)
		printf("DETECTOR module status=clean conf=high evidence=\"no "
		    "executable mapping outside the kernel image (%d entries "
		    "walked, %d executable)\"\n", total, nexec);
	else if (outside > 8)
		det_finding("module", "suspect", "low",
		    "%d executable mappings outside the kernel image, first 8 "
		    "listed", outside);
}

/* check 2: inpcb lists vs ipi_count */


static int
det_pcb_walk(struct inpcbinfo *ipi)
{
	struct inpcb	*inp;
	int		 n;

	n = 0;
	CK_LIST_FOREACH(inp, &ipi->ipi_listhead, inp_list)
		n++;
	return (n);
}

/*
 * One protocol table: counter against list. Caller sets the vnet.
 */
static void
det_pcb_table(struct inpcbinfo *ipi, const char *proto, int idx,
    int *delta_out)
{
	int		 walked, delta;

	walked = det_pcb_walk(ipi);
	delta = (int)ipi->ipi_count - walked;
	*delta_out = delta;

	if (delta != 0 && det_verbose)
		printf("DETECTOR pcb status=sampling conf=low evidence=\"%s "
		    "ipi_count=%u list=%d delta=%d (sample %d)\"\n",
		    proto, ipi->ipi_count, walked, delta, idx);
}

static void
det_scan_pcbs(void)
{
	int	tcp[DET_SAMPLES], udp[DET_SAMPLES];
	int	i, stable_tcp, stable_udp;

	/*
	 * Unlocked, and no pass over the process table.
	 *
	 * Taking the inpcb read lock used to wedge the box, because the in_pcb
	 * paths that hold it can sleep. Walking every process's fd table to
	 * find out which sockets are user sockets needs allproc_lock plus a
	 * lock per filedesc, and an earlier build that did it got blamed for a
	 * hang that actually lived in det_scan_modules(). Either way the
	 * counter delta already answers the question, so neither is here.
	 *
	 * What is left can't be faked: ipi_count goes up in in_pcballoc() and
	 * down only in in_pcbfree(), while port_hiding() just unlinks. A torn
	 * read costs one sample, and three identical samples are required
	 * before anything is called confirmed.
	 */
	for (i = 0; i < DET_SAMPLES; i++) {
		CURVNET_SET(TD_TO_VNET(curthread));
		det_pcb_table(&V_tcbinfo, "tcp", i, &tcp[i]);
		det_pcb_table(&V_udbinfo, "udp", i, &udp[i]);
		CURVNET_RESTORE();

		if (i + 1 < DET_SAMPLES)
			DELAY(100000);	/* 100 ms; busy-wait, so no sleep to hang in */
	}

	/* One sample isn't enough. pcbs are allocated and freed constantly
	 * and a count taken mid-teardown is off by one for reasons that have
	 * nothing to do with a rootkit. A leak doesn't flicker. */
	stable_tcp = (tcp[0] == tcp[1] && tcp[1] == tcp[2]);
	stable_udp = (udp[0] == udp[1] && udp[1] == udp[2]);

	if (tcp[0] > 0 && stable_tcp)
		det_finding("pcb", "confirmed", "high",
		    "tcp ipi_count exceeds the walkable list by %d, stable "
		    "over %d samples; a pcb was unlinked without being freed",
		    tcp[0], DET_SAMPLES);
	if (udp[0] > 0 && stable_udp)
		det_finding("pcb", "confirmed", "high",
		    "udp ipi_count exceeds the walkable list by %d, stable "
		    "over %d samples; a pcb was unlinked without being freed",
		    udp[0], DET_SAMPLES);
	if (det_verbose && tcp[0] <= 0 && udp[0] <= 0)
		printf("DETECTOR pcb status=clean conf=high evidence=\"tcp and "
		    "udp counters agree with their lists over %d samples\"\n",
		    DET_SAMPLES);
}

/* running a pass */

/*
 * Off switch for the network half, in case a host has something odd going on
 * with its pcb tables and someone wants the module census on its own.
 */
static int	det_pcb_enabled = 1;

static void
det_run_pass(void)
{
	struct det_kimage	ki;

	det_confirmed = 0;
	det_suspect = 0;

	printf("DETECTOR pass begin\n");

	det_kernel_image(&ki);
	det_scan_modules(&ki);
	if (det_pcb_enabled)
		det_scan_pcbs();
	else
		printf("DETECTOR pcb status=skipped conf=low evidence=\"pcb walk "
		    "switched off; set kern.detector.pcb=1 to enable it\"\n");

	printf("DETECTOR summary confirmed=%d suspect=%d\n",
	    det_confirmed, det_suspect);
}

static int
det_scan_sysctl(SYSCTL_HANDLER_ARGS)
{
	int val, err;

	val = 0;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	det_run_pass();
	return (0);
}

SYSCTL_PROC(_kern_detector, OID_AUTO, scan,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0, det_scan_sysctl, "I",
    "run one detector pass");

static int
det_summary_sysctl(SYSCTL_HANDLER_ARGS)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "confirmed=%d suspect=%d", det_confirmed,
	    det_suspect);
	return (sysctl_handle_string(oidp, buf, sizeof(buf), req));
}

SYSCTL_PROC(_kern_detector, OID_AUTO, summary,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, 0, 0, det_summary_sysctl,
    "A", "verdict counts from the last pass");

/* runtime switch for the network half */
SYSCTL_INT(_kern_detector, OID_AUTO, pcb, CTLFLAG_RWTUN, &det_pcb_enabled, 0,
    "run the inpcb list-vs-counter walk (on by default)");

static int
detector_modevent(module_t mod, int what, void *arg)
{
	switch (what) {
	case MOD_LOAD:
		/*
		 * No scan here, on purpose.
		 *
		 * kldload() only returns after the linker has finished mapping
		 * us, and det_scan_modules() takes kernel_map's read lock.
		 * Three attempts at getting the first pass to run:
		 *
		 *   - inline in MOD_LOAD: kldload never returns, the linker
		 *     still holds kernel_map;
		 *   - from a callout: that context may not sleep and rw_rlock()
		 *     can, so the pass wedges - and it wedges holding the msgbuf
		 *     lock, which means even dmesg(8) blocks;
		 *   - from taskqueue_thread: not reliable this early
		 *     (SI_SUB_DRIVERS).
		 *
		 * So the pass runs from the sysctl handler, which is ordinary
		 * process context and may sleep:
		 *     sysctl kern.detector.scan=1
		 * detect.sh already does that and demo.sh checks the result, so
		 * the userland half doesn't have to know about any of this.
		 */
		return (0);
	case MOD_UNLOAD:
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t detector_mod = {
	"detector",
	detector_modevent,
	NULL
};

DECLARE_MODULE(detector, detector_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_VERSION(detector, 1);

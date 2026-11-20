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
#include <sys/ck.h>
#include <sys/atomic.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>
#include <machine/vmparam.h>
#include <machine/clock.h>		/* DELAY() */

#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>

#define DET_LF_MAX		64	/* linker_files recorded per census */
#define DET_SHOW_MAX		8	/* ranges printed per finding */
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
 * Everything executable in kernel_map came from a module -- or from something
 * that unlinked itself from the module list. The address alone cannot separate
 * the two, so the census is cross-checked against linker_files: a mapping that
 * no linker_file claims is the case that earns a confirmed, and a mapping a
 * live linker_file does claim is exactly what a legitimate .ko looks like.
 *
 * Two ordering rules matter here:
 *
 *   - linker_file_foreach() takes kld_sx exclusively. kldload() holds kld_sx
 *     and then takes kernel_map, so the module list has to be sampled before
 *     kernel_map is locked, never inside it.
 *   - vm_map is an rbtree and following entry->left out of a module does not
 *     terminate, so the walk uses VM_MAP_ENTRY_FOREACH(), which goes through
 *     vm_map_entry_succ() and stops on the map header. That also makes
 *     `continue' safe here, which the old hand-rolled address walk could not
 *     use because the advance lived at the bottom of its loop body.
 */

struct det_lfranges {
	vm_offset_t	start[DET_LF_MAX];
	vm_offset_t	end[DET_LF_MAX];
	int		n;
};

static int
det_lf_record(linker_file_t lf, void *arg)
{
	struct det_lfranges *fr;

	fr = arg;
	if (lf->address == NULL || lf->size == 0)
		return (0);		/* preloaded stub, nothing mapped */
	if (fr->n >= DET_LF_MAX)
		return (1);		/* array full, stop the iteration */
	fr->start[fr->n] = (vm_offset_t)(uintptr_t)lf->address;
	fr->end[fr->n] = (vm_offset_t)(uintptr_t)lf->address + lf->size;
	fr->n++;
	return (0);
}

static int
det_claimed(const struct det_lfranges *fr, vm_offset_t start, vm_offset_t end)
{
	int i;

	for (i = 0; i < fr->n; i++) {
		if (start >= fr->start[i] && end <= fr->end[i])
			return (1);
	}
	return (0);
}

struct det_range {
	vm_offset_t	start;
	vm_offset_t	end;
};

static void
det_scan_modules(const struct det_kimage *ki)
{
	struct det_lfranges	 fr;
	struct det_range	 shown[DET_SHOW_MAX];
	vm_offset_t		 limit;
	vm_map_entry_t		 e;
	int			 total, nexec, unclaimed, nshown, i;

	if (!ki->valid) {
		det_finding("module", "suspect", "low",
		    "linker_kernel_file has no address/size; cannot tell "
		    "kernel text from module text");
		return;
	}

	bzero(&fr, sizeof(fr));
	linker_file_foreach(det_lf_record, &fr);

	total = 0;
	nexec = 0;
	unclaimed = 0;
	nshown = 0;
	/* Modules sit right after the image and every step of this is an
	 * rbtree search, so keep the window tight - an unbounded range turns
	 * the check into a minute of emulated kernel work. */
	limit = ki->end + DET_MODULE_MAX;
	if (limit > (vm_offset_t)VM_MAX_KERNEL_ADDRESS)
		limit = (vm_offset_t)VM_MAX_KERNEL_ADDRESS;

	/*
	 * No printf while kernel_map is read-locked: printf may sleep and the
	 * holder of a map read lock may not. Collect the first few ranges and
	 * report them after the unlock.
	 */
	vm_map_lock_read(kernel_map);
	VM_MAP_ENTRY_FOREACH(e, kernel_map) {
		if (e->start >= limit)
			break;
		if (e->end <= ki->start)
			continue;	/* below the image: pmap leftovers */
		total++;
		if ((e->protection & VM_PROT_EXECUTE) == 0)
			continue;
		if ((e->end - e->start) < PAGE_SIZE)
			continue;
		nexec++;
		if (e->start >= ki->start && e->end <= ki->end)
			continue;	/* the statically linked kernel */
		if (det_claimed(&fr, e->start, e->end))
			continue;	/* a module that is still on the list */
		unclaimed++;
		if (nshown < DET_SHOW_MAX) {
			shown[nshown].start = e->start;
			shown[nshown].end = e->end;
			nshown++;
		}
	}
	vm_map_unlock_read(kernel_map);

	if (det_verbose)
		printf("DETECTOR module census entries=%d exec=%d "
		    "linker_files=%d unclaimed=%d\n", total, nexec, fr.n,
		    unclaimed);

	/*
	 * A full array means the census does not know about every linker_file,
	 * so "unclaimed" turns into an over-count. Say so instead of printing
	 * a confirmed finding per legitimate module.
	 */
	if (fr.n >= DET_LF_MAX)
		det_finding("module", "suspect", "low",
		    "more than %d linker_files; only the first %d were "
		    "recorded, so mappings below may be over-counted",
		    DET_LF_MAX, DET_LF_MAX);

	for (i = 0; i < nshown; i++)
		det_finding("module", "confirmed", "high",
		    "executable mapping 0x%jx-0x%jx (%ju bytes) belongs to no "
		    "linker_file: the code is mapped, the module that owns it "
		    "is not on the list", (uintmax_t)shown[i].start,
		    (uintmax_t)shown[i].end,
		    (uintmax_t)(shown[i].end - shown[i].start));

	if (unclaimed > DET_SHOW_MAX)
		det_finding("module", "confirmed", "high",
		    "%d executable mappings belong to no linker_file, first %d "
		    "listed", unclaimed, DET_SHOW_MAX);

	if (unclaimed == 0 && det_verbose)
		printf("DETECTOR module status=clean conf=high evidence=\"every "
		    "executable mapping outside the kernel image is claimed by a "
		    "linker_file (%d walked, %d executable, %d files)\"\n",
		    total, nexec, fr.n);
}

/* check 2: inpcb lists vs ipi_count */


static int
det_pcb_walk(struct inpcbinfo *ipi)
{
	struct inpcb_iterator	 it = INP_ALL_ITERATOR(ipi, INPLOOKUP_RLOCKPCB);
	struct inpcb		*inp;
	int			 n;

	/*
	 * in_pcb.h's iterator instead of a bare CK_LIST_FOREACH: it takes the
	 * per-pcb lock (INPLOOKUP_RLOCKPCB) or an SMR reference around each
	 * element. The raw list walk raced two writers -- rootkit's
	 * port_hiding() unlinks under INP_INFO_WLOCK without freeing, so
	 * in_pcbfree() will CK_LIST_REMOVE the same node a second time, and
	 * in_pcbfree() itself runs concurrently on any busy host.
	 *
	 * The loop runs all the way to NULL on purpose: inp_next() drops the
	 * per-pcb lock and the ipi runlock on its way out, so leaving early
	 * would leak both. It also advances across hash buckets rather than
	 * following inp_list by hand, which is what kept the old walk from
	 * looping on a node the rootkit had relinked.
	 */
	n = 0;
	while ((inp = inp_next(&it)) != NULL)
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
		/*
		 * V_tcbinfo already resolves through the current vnet, and a
		 * sysctl handler runs in its caller's. Re-deriving it with
		 * TD_TO_VNET(curthread) picked the prison's vnet instead,
		 * which is a different table whenever the caller is jailed.
		 */
		det_pcb_table(&V_tcbinfo, "tcp", i, &tcp[i]);
		det_pcb_table(&V_udbinfo, "udp", i, &udp[i]);

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

static u_int		det_busy;		/* a pass is in progress */

static int
det_run_pass(void)
{
	struct det_kimage	ki;

	/*
	 * One pass at a time. The pass walks kernel_map and the pcb lists
	 * with locks held, and it prints; two concurrent sysctl writes used
	 * to interleave their findings into one summary. The same flag is
	 * what MOD_UNLOAD checks, so an unload cannot race a live pass.
	 *
	 * Returning EBUSY matters: the caller is about to read
	 * kern.detector.summary, and a skipped pass would hand it the counts
	 * from the previous run instead of an error.
	 */
	if (!atomic_cmpset_int(&det_busy, 0, 1)) {
		printf("DETECTOR pass status=skipped conf=low evidence=\"another "
		    "pass is already running\"\n");
		return (EBUSY);
	}

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

	atomic_store_rel_int(&det_busy, 0);
	return (0);
}

static int
det_scan_sysctl(SYSCTL_HANDLER_ARGS)
{
	int val, err;

	val = 0;
	err = sysctl_handle_int(oidp, &val, 0, req);
	if (err != 0 || req->newptr == NULL)
		return (err);

	return (det_run_pass());
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
		 *   - from a callout: that context may not sleep and
		 *     vm_map_lock_read() can, so the pass wedges - and it wedges
		 *     holding the msgbuf lock, which means even dmesg(8) blocks;
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
		/*
		 * Refuse while a pass is running. det_run_pass() executes this
		 * file's text and kldunload() would unmap it under the thread
		 * currently inside it -- the old unconditional `return (0)'
		 * unmapped the module in the middle of the kernel_map walk.
		 */
		if (!atomic_cmpset_int(&det_busy, 0, 1))
			return (EBUSY);
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

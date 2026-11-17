#!/bin/sh
# Userland half of my two areas: kernel modules and the network side.
#
# Nothing here claims a detection. Everything this script can see arrives
# through a syscall the rootkit may already be filtering (kldstat, sockstat),
# and both checks have honest look-alikes: a module in kld_list that just isn't
# loaded yet, the kernel's own NFS sockets. A false positive costs -2 and a
# detection is worth +1, so this half only raises suspicion. detector.ko is the
# part that gets to say confirmed.
#
#   kld_list wants a module, its .ko is on disk, kldstat knows neither  -> high
#   sockets with no owning process                                     -> low
#
# ./detect.sh        full report
# ./detect.sh -q     summary line only
#
# Same output contract as the module:
#   DETECTOR <class> status=suspect conf=<high|low> evidence="..."
#   DETECTOR summary confirmed=0 suspect=N
#
# Always exits 0. A detector that exits non-zero on a clean host is a false
# positive with extra steps.
set -u

PATH=/sbin:/usr/sbin:/bin:/usr/bin
export PATH

QUIET=0
[ "${1:-}" = "-q" ] && QUIET=1

confirmed=0
suspect=0

say() {
	_class=$1
	_conf=$2
	_ev=$3
	suspect=$((suspect + 1))
	if [ "$QUIET" -eq 0 ]; then
		printf 'DETECTOR %s status=suspect conf=%s evidence="%s"\n' \
		    "$_class" "$_conf" "$_ev"
	fi
}

# What should be loaded on this box? rc.conf and loader.conf can both carry a
# kld_list and either may use single or double quotes, so peel it with sed
# rather than sourcing the file and hoping.
kld_list_names() {
	for _f in /etc/rc.conf /etc/rc.conf.local /boot/loader.conf; do
		[ -r "$_f" ] || continue
		sed -n 's/^[[:space:]]*kld_list[^=]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$_f"
		sed -n "s/^[[:space:]]*kld_list[^=]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$_f"
	done | tr ' \t' '\n\n' | sed '/^$/d'
}

# modules

# A name kld_list asks for, with a .ko on disk, that kldstat -n cannot resolve
# is exactly the shape kld_hiding() leaves behind: the file is gone from
# linker_files while the install script keeps asking for it at every boot.
for _m in $(kld_list_names); do
	[ -f "/boot/modules/$_m.ko" ] || [ -f "/boot/kernel/$_m.ko" ] || continue
	if kldstat -n "$_m" >/dev/null 2>&1; then
		continue
	fi
	if kldstat -m "$_m" >/dev/null 2>&1; then
		continue
	fi
	say module high "kld_list loads $_m and $_m.ko is present in /boot/modules or /boot/kernel, but kldstat resolves neither the file nor the module"
done

# network

# A socket with no owning process came from the kernel (socreate() inside a
# module). Honest examples exist, NFS client and netgraph among them, which is
# why this is low confidence and why the module's ipi_count check is the one
# that gets to say confirmed.
_orphans=$(sockstat -4 2>/dev/null | awk 'NR > 1 && $1 == "???"' | head -5)
if [ -n "$_orphans" ]; then
	_n=$(printf '%s\n' "$_orphans" | wc -l | tr -d ' ')
	while IFS= read -r _line; do
		[ -n "$_line" ] || continue
		say socket low "processless socket: $_line (kernel-owned, or a listener that hides its owner)"
	done <<EOF
$_orphans
EOF
	[ "$_n" -ge 5 ] && say socket low "5 or more processless sockets; listing stopped"
fi

# kernel half

# If detector.ko is loaded, ask it for one pass and fold its counts into the
# summary. Only the module may say confirmed, since everything above compares
# userland sources and the rootkit can fake those. The pass runs from the
# sysctl because the load path can't run it: kernel_map is still held there.
if sysctl -n kern.detector.scan >/dev/null 2>&1; then
	sysctl kern.detector.scan=1 >/dev/null 2>&1
	_kc=$(sysctl -n kern.detector.confirmed 2>/dev/null || echo 0)
	_ks=$(sysctl -n kern.detector.suspect 2>/dev/null || echo 0)
	confirmed=$((confirmed + ${_kc:-0}))
	suspect=$((suspect + ${_ks:-0}))
	[ "$QUIET" -eq 0 ] && printf 'DETECTOR note kernel pass: confirmed=%s suspect=%s\n' \
	    "${_kc:-0}" "${_ks:-0}"
fi

printf 'DETECTOR summary confirmed=%d suspect=%d\n' "$confirmed" "$suspect"
exit 0

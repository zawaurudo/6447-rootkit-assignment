#!/bin/sh
# One command that shows the detector working on a real host.
#
# Three phases. Each prints the detector's own output, so the transcript can go
# straight into the write-up or the PR description.
#
#   phase 1  clean host            expect confirmed=0
#   phase 2  rootkit loaded        expect the census to grow (suspect only)
#   phase 3  port unlinked         expect confirmed>=1, the pcb delta
#
# Phases 2 and 3 want the rootkit tree and root. They sit behind an env flag
# because installing the rootkit writes /etc/rc.local and /usr/local/bin, and
# because kldunload on this module panics (see writeup.md), so the box is gone
# afterwards.
#
# ./demo.sh                          phase 1 only, no side effects
# DETECTOR_INSTALL_ROOTKIT=1 ./demo.sh
#
# ROOTKIT_DIR=/path/to/6447-rootkit-assignment-main/rootkit
# DETECTOR_PORT=4444                 port to unlink in phase 3
#
# Exits 0 when every phase gave the expected verdict, 1 otherwise.

set -u

PATH=/sbin:/usr/sbin:/bin:/usr/bin
export PATH

HERE=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
ROOTKIT_DIR=${ROOTKIT_DIR:-$HERE/../rootkit}
DETECTOR_PORT=${DETECTOR_PORT:-4444}
KMOD=$HERE/kmod/detector.ko

fail=0

note() { printf '\n=== %s\n' "$*"; }
ok()   { printf '    PASS %s\n' "$*"; }
bad()  { printf '    FAIL %s\n' "$*"; fail=1; }

# Read the counters from the sysctl instead of scraping dmesg, so an extra or
# missing print line can't confuse the check.
verdict() {
	sysctl -n kern.detector.confirmed kern.detector.suspect 2>/dev/null |
	    tr '\n' ' '
}

reload() {
	kldunload detector 2>/dev/null
	kldload "$KMOD" || { bad "kldload $KMOD"; return 1; }
	# kldload only registers the sysctls. The pass runs here.
	sysctl kern.detector.scan=1 >/dev/null 2>&1
	sleep 1
}

note "phase 1: clean host"
if ! kldstat -n detector >/dev/null 2>&1; then
	[ -f "$KMOD" ] || ( cd "$HERE/kmod" && make ) || { bad "build detector.ko"; exit 1; }
	kldload "$KMOD" || { bad "kldload $KMOD"; exit 1; }
fi
sysctl kern.detector.scan=1 >/dev/null 2>&1
sleep 1

set -- $(verdict)
c=${1:-?}; s=${2:-?}
printf '    kern.detector.confirmed=%s suspect=%s\n' "$c" "$s"
[ "$c" = "0" ] && ok "no confirmed finding on a clean host" ||
    bad "confirmed=$c on a clean host -- that is a false positive"

note "phase 1b: userland half"
sh "$HERE/detect.sh" | tee /tmp/detector-userland.txt
grep -q '^DETECTOR summary confirmed=0' /tmp/detector-userland.txt &&
    ok "detect.sh claims nothing confirmed" ||
    bad "detect.sh printed a confirmed line"

if [ "${DETECTOR_INSTALL_ROOTKIT:-0}" != "1" ]; then
	note "phase 2/3: skipped (set DETECTOR_INSTALL_ROOTKIT=1 to run them)"
	printf '\n%s\n' "$([ $fail -eq 0 ] && echo 'demo: PASS' || echo 'demo: FAIL')"
	exit $fail
fi

note "phase 2: rootkit installed and loaded"
( cd "$ROOTKIT_DIR" && ./install ) || bad "rootkit install"
kldstat -n rootkit >/dev/null 2>&1 || bad "rootkit.ko not loaded after install"

reload
set -- $(verdict)
c=${1:-?}; s=${2:-?}
printf '    kern.detector.confirmed=%s suspect=%s\n' "$c" "$s"
# Loading normally leaves a module nobody links: the census grows by one and the
# verdict stays suspect, because an address can't say who mapped it.
[ "${s:-0}" -ge 3 ] 2>/dev/null &&
    ok "census grew: the module's text is mapped and nothing accounts for it" ||
    bad "census did not grow after loading the rootkit (suspect=$s)"

note "phase 3: port concealment"
if [ -x "$HERE/port_hide" ] || ( cd "$HERE" && cc -O2 -o port_hide port_hide.c ); then
	# Has to run before the module gets hidden: modfind("sys/port_hiding")
	# only works while the file is still in linker_files.
	"$HERE/port_hide" "$DETECTOR_PORT" || bad "port_hide $DETECTOR_PORT"
else
	bad "could not build port_hide"
fi

reload
set -- $(verdict)
c=${1:-?}; s=${2:-?}
printf '    kern.detector.confirmed=%s suspect=%s\n' "$c" "$s"
[ "${c:-0}" -ge 1 ] 2>/dev/null &&
    ok "pcb counter exceeds the walkable list: one was unlinked, not freed" ||
    bad "port_hide ran but the inpcb counters still agree with the lists"

note "phase 3b: what the rootkit is hiding from userland"
printf '    kldstat -n rootkit : %s\n' \
    "$(kldstat -n rootkit >/dev/null 2>&1 && echo visible || echo hidden)"
printf '    ls /boot/modules/*rootkit* : %s\n' \
    "$(ls /boot/modules/*rootkit* 2>/dev/null | tr '\n' ' ' || echo none)"
printf '    dmesg tail:\n'
dmesg | grep DETECTOR | tail -n 8 | sed 's/^/        /'

printf '\n%s\n' "$([ $fail -eq 0 ] && echo 'demo: PASS' || echo 'demo: FAIL')"
exit $fail

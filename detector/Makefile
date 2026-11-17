# Kernel half of the detector. Same build as rootkit/kernel/Makefile: stand
# here, run make, get detector.ko. Nothing here depends on rootkit/, so the two
# trees build side by side without touching each other.
#
# Build against the kernel you will run it on, since kldload rejects a version
# mismatch. The checks read vm_map, the sysent table and the inpcb lists
# directly, so a struct change between releases shows up as a build error rather
# than a silent wrong answer. README.md lists the fields to look at if you move
# to a different version.

KMOD=	detector
SRCS=	detector.c

.include <bsd.kmod.mk>

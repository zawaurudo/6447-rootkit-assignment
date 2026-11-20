# Kernel half of the detector (FreeBSD kld). Build from this directory:
#
#   make                 -> detector.ko
#   make clean
#
# The userland half lives one level up (../Makefile builds the C checkers,
# ../detect is the single entry point). Keeping the kmod in its own directory
# matters because bsd.kmod.mk takes over the default target and would fight the
# userland rules if the two shared one Makefile.

KMOD=	detector
SRCS=	detector.c

.include <bsd.kmod.mk>

KMOD= rootkit
SRCS= rootkit.c interface.c log.c

# log.c asks whether fd 0 is a terminal, which means reading struct vnode.
# vnode.h includes vnode_if.h, and kmod.mk only generates that header when it
# is named in SRCS.
SRCS+= vnode_if.h

.include <bsd.kmod.mk>

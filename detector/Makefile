CC?=cc
CFLAGS?=-O2
CFLAGS+=-std=c11 -Wall -Wextra -Werror

# port_hide is a demo helper, not a checker, but it lives here so `make` gives
# you every userland binary this directory owns.
PROGS=persistence_detector process_detector syscall_hook_check port_hide

.PHONY: all clean kmod clean-kmod

all: $(PROGS)

persistence_detector: persistence_detector.c
	$(CC) $(CFLAGS) persistence_detector.c -o $@

process_detector: process_detector.c
	$(CC) $(CFLAGS) process_detector.c -o $@

syscall_hook_check: syscall_hook_check.c
	$(CC) $(CFLAGS) syscall_hook_check.c -lkvm -o $@

port_hide: port_hide.c
	$(CC) $(CFLAGS) port_hide.c -o $@

clean:
	rm -f $(PROGS)

# FreeBSD only: the kernel half of the detector. Kept in kmod/ because
# bsd.kmod.mk owns the default target, which the userland rules above need.
kmod:
	$(MAKE) -C kmod

clean-kmod:
	$(MAKE) -C kmod clean

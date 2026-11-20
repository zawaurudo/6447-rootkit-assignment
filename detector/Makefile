CC?=cc
CFLAGS?=-O2
CFLAGS+=-std=c11 -Wall -Wextra -Werror

.PHONY: all clean test kmod clean-kmod

all: persistence_detector process_detector syscall_hook_check

persistence_detector: persistence_detector.c
	$(CC) $(CFLAGS) persistence_detector.c -o $@

process_detector: process_detector.c
	$(CC) $(CFLAGS) process_detector.c -o $@

syscall_hook_check: syscall_hook_check.c
	$(CC) $(CFLAGS) syscall_hook_check.c -lkvm -o $@

test:
	$(MAKE) -C tests test

clean:
	rm -f persistence_detector process_detector syscall_hook_check
	$(MAKE) -C tests clean

# FreeBSD only: the kernel half of the detector. Kept in kmod/ because
# bsd.kmod.mk owns the default target, which the userland rules above need.
kmod:
	$(MAKE) -C kmod

clean-kmod:
	$(MAKE) -C kmod clean

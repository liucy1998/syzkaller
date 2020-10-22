#ifndef SCLOG_H
#define SCLOG_H
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_sclog(const char *path, const char *mode);
void log_syscall(intptr_t scno, int argn, intptr_t args[], intptr_t rval);
void log_syscall_printf(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
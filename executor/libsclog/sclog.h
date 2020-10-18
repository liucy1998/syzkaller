#ifndef SCLOG_H
#define SCLOG_H
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_sclog(char *path);
void log_syscall(intptr_t scno, int argn, intptr_t args[], intptr_t rval);
void log_syscall_printf(const char *fmt, ...);
void log_syscall_with_index(int idx, intptr_t scno, int argn, intptr_t args[], intptr_t rval);

#ifdef __cplusplus
}
#endif
#ifndef SCLOG_H
#define SCLOG_H
#endif

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_sclog(void);
void log_syscall_with_index(FILE *f, int idx, intptr_t scno, int argn, intptr_t args[], intptr_t rval);
void log_syscall_printf(FILE *f, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
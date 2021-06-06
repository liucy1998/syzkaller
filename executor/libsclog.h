#ifndef SCLOG_H
#define SCLOG_H
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_sclog(void);
void set_log_file(int log_idx, FILE *f);
void log_syscall_with_index(int log_idx, int idx, intptr_t scno, int argn, intptr_t args[], intptr_t rval, intptr_t err, bool entering);
void log_syscall_printf(int log_idx, const char *fmt, ...);
int get_trace_size(int log_idx);

#ifdef __cplusplus
}
#endif
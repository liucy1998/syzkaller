#ifndef SCLOG_H
#define SCLOG_H
#endif

#include <stdint.h>

void init_sclog(char *path);
void log_syscall(intptr_t scno, int argn, intptr_t args[], intptr_t rval);
#define _GNU_SOURCE
#include "sclog.h"
#include <syscall.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
struct Syscall {
    intptr_t scno;
    int argn;
    intptr_t args[8]; 
    intptr_t rval;
};

struct stat statbuf = {
    .st_dev = 123,
    .st_ino = 456,
    .st_uid = 1000,
    .st_gid = 1000
};

struct Syscall test_cases[] = {
    [0] = {
        .scno = SYS_clone,
        .argn = 4,
        .args = {
            CLONE_NEWIPC | CLONE_NEWUSER | SIGCHLD,
            0x12345678,
            0x7654321,
            0 
        },
        .rval = 1234
    }, 
    [1] = {
        .scno = SYS_fstat,
        .argn = 2,
        .args = {
            88,
            (intptr_t) &statbuf
        },
        .rval = 0
    }
};


#define ntest (sizeof(test_cases)/sizeof(struct Syscall))

void run_tests(void) {
    init_sclog("test_log");
    long unsigned i = 0;
    for(; i < ntest; i++) {
        log_syscall(
            test_cases[i].scno, 
            test_cases[i].argn,
            test_cases[i].args,
            test_cases[i].rval
        );
    }
}

int main(void) {
    run_tests();
}
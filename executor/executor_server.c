#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "ipc_shim.h"


#define RUN_EXECUTOR 23
#define KILL_EXECUTOR 98

#define MAX_ARGV 64
#define MAX_ENVP 64

struct ExecReqHead {
    int argv_num;
    int envp_num;
    int shm_size;
};

struct ExecReq {
    struct ExecReqHead head;
    // pointers to actual data
    char *path;
    // argv, envp MUST ends with NULL pointer
    char *argv[MAX_ARGV+1];
    char *envp[MAX_ENVP+1];
};

struct KillReq {
    pid_t pid;
};

struct Req {
    int command;
};

struct Reply {
    int ret;
};

#define IN_PIPE 0
#define OUT_PIPE 1
#define ERR_PIPE 2
#define SHM 0
#define SHM_SIZE 8192

#define debug(...) pprintln(ERR_PIPE, "[debug] executor server: " __VA_ARGS__)
#define fatal(...) pprintln(ERR_PIPE, "[fatal] executor server: " __VA_ARGS__)
#define err(msg) do { fatal(msg ": %s", strerror(errno));} while (0)


static inline char* next_str(char *str) {
    return str+strlen(str)+1; // skip 0
}

int deserialize_execreq(void *msg, struct ExecReq* er) {
    char *data = (char *)msg;
    int i, len;

    if (msg == NULL || er == NULL) {
        fatal("deserialize_execenv receives NULL pointer");
        return -1;
    }

    if (er->head.argv_num > MAX_ARGV || er->head.envp_num > MAX_ENVP) {
        fatal("env head: argv = %d, envp = %d, too large", MAX_ARGV, MAX_ENVP);
        return -2;
    }

    er->path = data;
    data = next_str(data);

    for (i = 0; i < er->head.argv_num; i++, data=next_str(data)) {
        er->argv[i] = data;
    }
    er->argv[i] = NULL;

    for (i = 0; i < er->head.envp_num; i++, data=next_str(data)) {
       er->envp[i] = data;
    }
    er->envp[i] = NULL;

    return 0;
}

void reply(int ret) {
    struct Reply r;

    r.ret = ret;
    write_host_pipe(OUT_PIPE, &r, sizeof(struct Reply));
}

void recv_req(struct Req *r) {
    memset(r, 0, sizeof(struct Req));
    read_host_pipe(IN_PIPE, r, sizeof(struct Req));
}

int recv_execreq(void *data, size_t max_len, struct ExecReq *er) {
    int ret;
    int i;

    memset(er, 0, sizeof(struct ExecReq));
    read_host_pipe(IN_PIPE, &er->head, sizeof(struct ExecReqHead));

    if (er->head.shm_size > max_len) {
        fatal("exec request size > %d", SHM_SIZE);
        return -1;
    }
    memset(data, 0, max_len);
    read_host_shm(SHM, 0, data, er->head.shm_size);

    ret = deserialize_execreq(data, er);
    debug("receiving execute request...");
    debug("path: %s", er->path);
    debug("arg number: %d", er->head.argv_num);
    for(i = 0; i < er->head.argv_num; i++)
        debug("arg#%d: %s\n", i, er->argv[i]);
    debug("env number: %d", er->head.envp_num);
    for(i = 0; i < er->head.envp_num; i++)
        debug("env#%d: %s\n", i, er->envp[i]);
    if (ret < 0) {
        return -2;
    }

    return 0;
}

int recv_killreq(struct KillReq *kr) {

    read_host_pipe(IN_PIPE, &kr, sizeof(struct KillReq));
}

int run_execreq(struct ExecReq *er) {
    int pid;

    pid = fork();
    if (pid == -1) {
        err("run_execenv fork");
        return -1;
    }
    if (pid == 0) {
        execve(er->path, er->argv, er->envp);
        exit(0);
    }
    return pid;
}

static char input[SHM_SIZE];

int main(int argc , char *argv[], char *envp[]) {
    // TODO: pass pipe/shm index using argv 
    int i;
    for (i = 0; i < 1; i++) {
        struct Req r;
        struct ExecReq er;
        struct KillReq qr;
        int env_idx, ret, pid;

        recv_req(&r);
        switch(r.command) {
            case RUN_EXECUTOR:
                ret = recv_execreq(input, SHM_SIZE, &er);
                if (ret < 0) {
                    reply(-1);
                    break;
                }
                pid = run_execreq(&er);
                if (pid < 0) {
                    reply(-2);
                    break;
                }
                reply(pid);
                break;
            case KILL_EXECUTOR:
                recv_killreq(&qr);
                ret = kill(SIGKILL, qr.pid);
                if (ret < 0) {
                    err("kill executor");
                    reply(-1);
                    break;
                }
                reply(0);
                break;
            default:
                break;
        }
    }
    return 0;
}
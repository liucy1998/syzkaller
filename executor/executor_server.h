#ifndef EXECUTOR_SERVER_H
#define EXECUTOR_SERVER_H

enum {
    ES_IN_PIPE = 0,
    ES_OUT_PIPE,
    ES_ERR_PIPE,
    ES_STATUS_PIPE,

    EXECUTOR_PIPE_BASE,
};

enum {
    ES_SHM = 0,

    EXECUTOR_SHM_BASE,
};

#endif

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


rap_int_t
rap_daemon(rap_log_t *log)
{
    int  fd;

    switch (fork()) {
    case -1:
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "fork() failed");
        return RAP_ERROR;

    case 0:
        break;

    default:
        exit(0);
    }

    rap_parent = rap_pid;
    rap_pid = rap_getpid();

    if (setsid() == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "setsid() failed");
        return RAP_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                      "open(\"/dev/null\") failed");
        return RAP_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "dup2(STDIN) failed");
        return RAP_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "dup2(STDOUT) failed");
        return RAP_ERROR;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "dup2(STDERR) failed");
        return RAP_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            rap_log_error(RAP_LOG_EMERG, log, rap_errno, "close() failed");
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}

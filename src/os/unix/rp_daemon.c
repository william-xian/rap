
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


rp_int_t
rp_daemon(rp_log_t *log)
{
    int  fd;

    switch (fork()) {
    case -1:
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "fork() failed");
        return RP_ERROR;

    case 0:
        break;

    default:
        exit(0);
    }

    rp_parent = rp_pid;
    rp_pid = rp_getpid();

    if (setsid() == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "setsid() failed");
        return RP_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno,
                      "open(\"/dev/null\") failed");
        return RP_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "dup2(STDIN) failed");
        return RP_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "dup2(STDOUT) failed");
        return RP_ERROR;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "dup2(STDERR) failed");
        return RP_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            rp_log_error(RP_LOG_EMERG, log, rp_errno, "close() failed");
            return RP_ERROR;
        }
    }

    return RP_OK;
}

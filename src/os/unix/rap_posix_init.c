
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap.h>


rap_int_t   rap_ncpu;
rap_int_t   rap_max_sockets;
rap_uint_t  rap_inherited_nonblocking;
rap_uint_t  rap_tcp_nodelay_and_tcp_nopush;


struct rlimit  rlmt;


rap_os_io_t rap_os_io = {
    rap_unix_recv,
    rap_readv_chain,
    rap_udp_unix_recv,
    rap_unix_send,
    rap_udp_unix_send,
    rap_udp_unix_sendmsg_chain,
    rap_writev_chain,
    0
};


rap_int_t
rap_os_init(rap_log_t *log)
{
    rap_time_t  *tp;
    rap_uint_t   n;
#if (RAP_HAVE_LEVEL1_DCACHE_LINESIZE)
    long         size;
#endif

#if (RAP_HAVE_OS_SPECIFIC_INIT)
    if (rap_os_specific_init(log) != RAP_OK) {
        return RAP_ERROR;
    }
#endif

    if (rap_init_setproctitle(log) != RAP_OK) {
        return RAP_ERROR;
    }

    rap_pagesize = getpagesize();
    rap_cacheline_size = RAP_CPU_CACHE_LINE;

    for (n = rap_pagesize; n >>= 1; rap_pagesize_shift++) { /* void */ }

#if (RAP_HAVE_SC_NPROCESSORS_ONLN)
    if (rap_ncpu == 0) {
        rap_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
#endif

    if (rap_ncpu < 1) {
        rap_ncpu = 1;
    }

#if (RAP_HAVE_LEVEL1_DCACHE_LINESIZE)
    size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (size > 0) {
        rap_cacheline_size = size;
    }
#endif

    rap_cpuinfo();

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed");
        return RAP_ERROR;
    }

    rap_max_sockets = (rap_int_t) rlmt.rlim_cur;

#if (RAP_HAVE_INHERITED_NONBLOCK || RAP_HAVE_ACCEPT4)
    rap_inherited_nonblocking = 1;
#else
    rap_inherited_nonblocking = 0;
#endif

    tp = rap_timeofday();
    srandom(((unsigned) rap_pid << 16) ^ tp->sec ^ tp->msec);

    return RAP_OK;
}


void
rap_os_status(rap_log_t *log)
{
    rap_log_error(RAP_LOG_NOTICE, log, 0, RAP_VER_BUILD);

#ifdef RAP_COMPILER
    rap_log_error(RAP_LOG_NOTICE, log, 0, "built by " RAP_COMPILER);
#endif

#if (RAP_HAVE_OS_SPECIFIC_INIT)
    rap_os_specific_status(log);
#endif

    rap_log_error(RAP_LOG_NOTICE, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %r:%r",
                  rlmt.rlim_cur, rlmt.rlim_max);
}


#if 0

rap_int_t
rap_posix_post_conf_init(rap_log_t *log)
{
    rap_fd_t  pp[2];

    if (pipe(pp) == -1) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno, "pipe() failed");
        return RAP_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        rap_log_error(RAP_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return RAP_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            rap_log_error(RAP_LOG_EMERG, log, errno, "close() failed");
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}

#endif

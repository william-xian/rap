
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rap.h>


rp_int_t   rp_ncpu;
rp_int_t   rp_max_sockets;
rp_uint_t  rp_inherited_nonblocking;
rp_uint_t  rp_tcp_nodelay_and_tcp_nopush;


struct rlimit  rlmt;


rp_os_io_t rp_os_io = {
    rp_unix_recv,
    rp_readv_chain,
    rp_udp_unix_recv,
    rp_unix_send,
    rp_udp_unix_send,
    rp_udp_unix_sendmsg_chain,
    rp_writev_chain,
    0
};


rp_int_t
rp_os_init(rp_log_t *log)
{
    rp_time_t  *tp;
    rp_uint_t   n;
#if (RP_HAVE_LEVEL1_DCACHE_LINESIZE)
    long         size;
#endif

#if (RP_HAVE_OS_SPECIFIC_INIT)
    if (rp_os_specific_init(log) != RP_OK) {
        return RP_ERROR;
    }
#endif

    if (rp_init_setproctitle(log) != RP_OK) {
        return RP_ERROR;
    }

    rp_pagesize = getpagesize();
    rp_cacheline_size = RP_CPU_CACHE_LINE;

    for (n = rp_pagesize; n >>= 1; rp_pagesize_shift++) { /* void */ }

#if (RP_HAVE_SC_NPROCESSORS_ONLN)
    if (rp_ncpu == 0) {
        rp_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
#endif

    if (rp_ncpu < 1) {
        rp_ncpu = 1;
    }

#if (RP_HAVE_LEVEL1_DCACHE_LINESIZE)
    size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (size > 0) {
        rp_cacheline_size = size;
    }
#endif

    rp_cpuinfo();

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        rp_log_error(RP_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed");
        return RP_ERROR;
    }

    rp_max_sockets = (rp_int_t) rlmt.rlim_cur;

#if (RP_HAVE_INHERITED_NONBLOCK || RP_HAVE_ACCEPT4)
    rp_inherited_nonblocking = 1;
#else
    rp_inherited_nonblocking = 0;
#endif

    tp = rp_timeofday();
    srandom(((unsigned) rp_pid << 16) ^ tp->sec ^ tp->msec);

    return RP_OK;
}


void
rp_os_status(rp_log_t *log)
{
    rp_log_error(RP_LOG_NOTICE, log, 0, RAP_VER_BUILD);

#ifdef RP_COMPILER
    rp_log_error(RP_LOG_NOTICE, log, 0, "built by " RP_COMPILER);
#endif

#if (RP_HAVE_OS_SPECIFIC_INIT)
    rp_os_specific_status(log);
#endif

    rp_log_error(RP_LOG_NOTICE, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %r:%r",
                  rlmt.rlim_cur, rlmt.rlim_max);
}


#if 0

rp_int_t
rp_posix_post_conf_init(rp_log_t *log)
{
    rp_fd_t  pp[2];

    if (pipe(pp) == -1) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno, "pipe() failed");
        return RP_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        rp_log_error(RP_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return RP_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            rp_log_error(RP_LOG_EMERG, log, errno, "close() failed");
            return RP_ERROR;
        }
    }

    return RP_OK;
}

#endif

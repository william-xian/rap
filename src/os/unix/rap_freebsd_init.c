
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


/* FreeBSD 3.0 at least */
char    rap_freebsd_kern_ostype[16];
char    rap_freebsd_kern_osrelease[128];
int     rap_freebsd_kern_osreldate;
int     rap_freebsd_hw_ncpu;
int     rap_freebsd_kern_ipc_somaxconn;
u_long  rap_freebsd_net_inet_tcp_sendspace;

/* FreeBSD 4.9 */
int     rap_freebsd_machdep_hlt_logical_cpus;


rap_uint_t  rap_freebsd_sendfile_nbytes_bug;
rap_uint_t  rap_freebsd_use_tcp_nopush;

rap_uint_t  rap_debug_malloc;


static rap_os_io_t rap_freebsd_io = {
    rap_unix_recv,
    rap_readv_chain,
    rap_udp_unix_recv,
    rap_unix_send,
    rap_udp_unix_send,
    rap_udp_unix_sendmsg_chain,
#if (RAP_HAVE_SENDFILE)
    rap_freebsd_sendfile_chain,
    RAP_IO_SENDFILE
#else
    rap_writev_chain,
    0
#endif
};


typedef struct {
    char        *name;
    void        *value;
    size_t       size;
    rap_uint_t   exists;
} sysctl_t;


sysctl_t sysctls[] = {
    { "hw.ncpu",
      &rap_freebsd_hw_ncpu,
      sizeof(rap_freebsd_hw_ncpu), 0 },

    { "machdep.hlt_logical_cpus",
      &rap_freebsd_machdep_hlt_logical_cpus,
      sizeof(rap_freebsd_machdep_hlt_logical_cpus), 0 },

    { "net.inet.tcp.sendspace",
      &rap_freebsd_net_inet_tcp_sendspace,
      sizeof(rap_freebsd_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &rap_freebsd_kern_ipc_somaxconn,
      sizeof(rap_freebsd_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
rap_debug_init(void)
{
#if (RAP_DEBUG_MALLOC)

#if __FreeBSD_version >= 500014 && __FreeBSD_version < 1000011
    _malloc_options = "J";
#elif __FreeBSD_version < 500014
    malloc_options = "J";
#endif

    rap_debug_malloc = 1;

#else
    char  *mo;

    mo = getenv("MALLOC_OPTIONS");

    if (mo && rap_strchr(mo, 'J')) {
        rap_debug_malloc = 1;
    }
#endif
}


rap_int_t
rap_os_specific_init(rap_log_t *log)
{
    int         version;
    size_t      size;
    rap_err_t   err;
    rap_uint_t  i;

    size = sizeof(rap_freebsd_kern_ostype);
    if (sysctlbyname("kern.ostype",
                     rap_freebsd_kern_ostype, &size, NULL, 0) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "sysctlbyname(kern.ostype) failed");

        if (rap_errno != RAP_ENOMEM) {
            return RAP_ERROR;
        }

        rap_freebsd_kern_ostype[size - 1] = '\0';
    }

    size = sizeof(rap_freebsd_kern_osrelease);
    if (sysctlbyname("kern.osrelease",
                     rap_freebsd_kern_osrelease, &size, NULL, 0) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "sysctlbyname(kern.osrelease) failed");

        if (rap_errno != RAP_ENOMEM) {
            return RAP_ERROR;
        }

        rap_freebsd_kern_osrelease[size - 1] = '\0';
    }


    size = sizeof(int);
    if (sysctlbyname("kern.osreldate",
                     &rap_freebsd_kern_osreldate, &size, NULL, 0) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "sysctlbyname(kern.osreldate) failed");
        return RAP_ERROR;
    }

    version = rap_freebsd_kern_osreldate;


#if (RAP_HAVE_SENDFILE)

    /*
     * The determination of the sendfile() "nbytes bug" is complex enough.
     * There are two sendfile() syscalls: a new #393 has no bug while
     * an old #336 has the bug in some versions and has not in others.
     * Besides libc_r wrapper also emulates the bug in some versions.
     * There is no way to say exactly if syscall #336 in FreeBSD circa 4.6
     * has the bug.  We use the algorithm that is correct at least for
     * RELEASEs and for syscalls only (not libc_r wrapper).
     *
     * 4.6.1-RELEASE and below have the bug
     * 4.6.2-RELEASE and above have the new syscall
     *
     * We detect the new sendfile() syscall available at the compile time
     * to allow an old binary to run correctly on an updated FreeBSD system.
     */

#if (__FreeBSD__ == 4 && __FreeBSD_version >= 460102) \
    || __FreeBSD_version == 460002 || __FreeBSD_version >= 500039

    /* a new syscall without the bug */

    rap_freebsd_sendfile_nbytes_bug = 0;

#else

    /* an old syscall that may have the bug */

    rap_freebsd_sendfile_nbytes_bug = 1;

#endif

#endif /* RAP_HAVE_SENDFILE */


    if ((version < 500000 && version >= 440003) || version >= 500017) {
        rap_freebsd_use_tcp_nopush = 1;
    }


    for (i = 0; sysctls[i].name; i++) {
        size = sysctls[i].size;

        if (sysctlbyname(sysctls[i].name, sysctls[i].value, &size, NULL, 0)
            == 0)
        {
            sysctls[i].exists = 1;
            continue;
        }

        err = rap_errno;

        if (err == RAP_ENOENT) {
            continue;
        }

        rap_log_error(RAP_LOG_ALERT, log, err,
                      "sysctlbyname(%s) failed", sysctls[i].name);
        return RAP_ERROR;
    }

    if (rap_freebsd_machdep_hlt_logical_cpus) {
        rap_ncpu = rap_freebsd_hw_ncpu / 2;

    } else {
        rap_ncpu = rap_freebsd_hw_ncpu;
    }

    if (version < 600008 && rap_freebsd_kern_ipc_somaxconn > 32767) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      "sysctl kern.ipc.somaxconn must be less than 32768");
        return RAP_ERROR;
    }

    rap_tcp_nodelay_and_tcp_nopush = 1;

    rap_os_io = rap_freebsd_io;

    return RAP_OK;
}


void
rap_os_specific_status(rap_log_t *log)
{
    u_long      value;
    rap_uint_t  i;

    rap_log_error(RAP_LOG_NOTICE, log, 0, "OS: %s %s",
                  rap_freebsd_kern_ostype, rap_freebsd_kern_osrelease);

#ifdef __DragonFly_version
    rap_log_error(RAP_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  rap_freebsd_kern_osreldate, __DragonFly_version);
#else
    rap_log_error(RAP_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  rap_freebsd_kern_osreldate, __FreeBSD_version);
#endif

    for (i = 0; sysctls[i].name; i++) {
        if (sysctls[i].exists) {
            if (sysctls[i].size == sizeof(long)) {
                value = *(long *) sysctls[i].value;

            } else {
                value = *(int *) sysctls[i].value;
            }

            rap_log_error(RAP_LOG_NOTICE, log, 0, "%s: %l",
                          sysctls[i].name, value);
        }
    }
}

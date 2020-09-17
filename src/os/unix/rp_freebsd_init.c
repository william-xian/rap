
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


/* FreeBSD 3.0 at least */
char    rp_freebsd_kern_ostype[16];
char    rp_freebsd_kern_osrelease[128];
int     rp_freebsd_kern_osreldate;
int     rp_freebsd_hw_ncpu;
int     rp_freebsd_kern_ipc_somaxconn;
u_long  rp_freebsd_net_inet_tcp_sendspace;

/* FreeBSD 4.9 */
int     rp_freebsd_machdep_hlt_logical_cpus;


rp_uint_t  rp_freebsd_sendfile_nbytes_bug;
rp_uint_t  rp_freebsd_use_tcp_nopush;

rp_uint_t  rp_debug_malloc;


static rp_os_io_t rp_freebsd_io = {
    rp_unix_recv,
    rp_readv_chain,
    rp_udp_unix_recv,
    rp_unix_send,
    rp_udp_unix_send,
    rp_udp_unix_sendmsg_chain,
#if (RP_HAVE_SENDFILE)
    rp_freebsd_sendfile_chain,
    RP_IO_SENDFILE
#else
    rp_writev_chain,
    0
#endif
};


typedef struct {
    char        *name;
    void        *value;
    size_t       size;
    rp_uint_t   exists;
} sysctl_t;


sysctl_t sysctls[] = {
    { "hw.ncpu",
      &rp_freebsd_hw_ncpu,
      sizeof(rp_freebsd_hw_ncpu), 0 },

    { "machdep.hlt_logical_cpus",
      &rp_freebsd_machdep_hlt_logical_cpus,
      sizeof(rp_freebsd_machdep_hlt_logical_cpus), 0 },

    { "net.inet.tcp.sendspace",
      &rp_freebsd_net_inet_tcp_sendspace,
      sizeof(rp_freebsd_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &rp_freebsd_kern_ipc_somaxconn,
      sizeof(rp_freebsd_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
rp_debug_init(void)
{
#if (RP_DEBUG_MALLOC)

#if __FreeBSD_version >= 500014 && __FreeBSD_version < 1000011
    _malloc_options = "J";
#elif __FreeBSD_version < 500014
    malloc_options = "J";
#endif

    rp_debug_malloc = 1;

#else
    char  *mo;

    mo = getenv("MALLOC_OPTIONS");

    if (mo && rp_strchr(mo, 'J')) {
        rp_debug_malloc = 1;
    }
#endif
}


rp_int_t
rp_os_specific_init(rp_log_t *log)
{
    int         version;
    size_t      size;
    rp_err_t   err;
    rp_uint_t  i;

    size = sizeof(rp_freebsd_kern_ostype);
    if (sysctlbyname("kern.ostype",
                     rp_freebsd_kern_ostype, &size, NULL, 0) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "sysctlbyname(kern.ostype) failed");

        if (rp_errno != RP_ENOMEM) {
            return RP_ERROR;
        }

        rp_freebsd_kern_ostype[size - 1] = '\0';
    }

    size = sizeof(rp_freebsd_kern_osrelease);
    if (sysctlbyname("kern.osrelease",
                     rp_freebsd_kern_osrelease, &size, NULL, 0) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "sysctlbyname(kern.osrelease) failed");

        if (rp_errno != RP_ENOMEM) {
            return RP_ERROR;
        }

        rp_freebsd_kern_osrelease[size - 1] = '\0';
    }


    size = sizeof(int);
    if (sysctlbyname("kern.osreldate",
                     &rp_freebsd_kern_osreldate, &size, NULL, 0) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "sysctlbyname(kern.osreldate) failed");
        return RP_ERROR;
    }

    version = rp_freebsd_kern_osreldate;


#if (RP_HAVE_SENDFILE)

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

    rp_freebsd_sendfile_nbytes_bug = 0;

#else

    /* an old syscall that may have the bug */

    rp_freebsd_sendfile_nbytes_bug = 1;

#endif

#endif /* RP_HAVE_SENDFILE */


    if ((version < 500000 && version >= 440003) || version >= 500017) {
        rp_freebsd_use_tcp_nopush = 1;
    }


    for (i = 0; sysctls[i].name; i++) {
        size = sysctls[i].size;

        if (sysctlbyname(sysctls[i].name, sysctls[i].value, &size, NULL, 0)
            == 0)
        {
            sysctls[i].exists = 1;
            continue;
        }

        err = rp_errno;

        if (err == RP_ENOENT) {
            continue;
        }

        rp_log_error(RP_LOG_ALERT, log, err,
                      "sysctlbyname(%s) failed", sysctls[i].name);
        return RP_ERROR;
    }

    if (rp_freebsd_machdep_hlt_logical_cpus) {
        rp_ncpu = rp_freebsd_hw_ncpu / 2;

    } else {
        rp_ncpu = rp_freebsd_hw_ncpu;
    }

    if (version < 600008 && rp_freebsd_kern_ipc_somaxconn > 32767) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      "sysctl kern.ipc.somaxconn must be less than 32768");
        return RP_ERROR;
    }

    rp_tcp_nodelay_and_tcp_nopush = 1;

    rp_os_io = rp_freebsd_io;

    return RP_OK;
}


void
rp_os_specific_status(rp_log_t *log)
{
    u_long      value;
    rp_uint_t  i;

    rp_log_error(RP_LOG_NOTICE, log, 0, "OS: %s %s",
                  rp_freebsd_kern_ostype, rp_freebsd_kern_osrelease);

#ifdef __DragonFly_version
    rp_log_error(RP_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  rp_freebsd_kern_osreldate, __DragonFly_version);
#else
    rp_log_error(RP_LOG_NOTICE, log, 0,
                  "kern.osreldate: %d, built on %d",
                  rp_freebsd_kern_osreldate, __FreeBSD_version);
#endif

    for (i = 0; sysctls[i].name; i++) {
        if (sysctls[i].exists) {
            if (sysctls[i].size == sizeof(long)) {
                value = *(long *) sysctls[i].value;

            } else {
                value = *(int *) sysctls[i].value;
            }

            rp_log_error(RP_LOG_NOTICE, log, 0, "%s: %l",
                          sysctls[i].name, value);
        }
    }
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


char    rp_darwin_kern_ostype[16];
char    rp_darwin_kern_osrelease[128];
int     rp_darwin_hw_ncpu;
int     rp_darwin_kern_ipc_somaxconn;
u_long  rp_darwin_net_inet_tcp_sendspace;

rp_uint_t  rp_debug_malloc;


static rp_os_io_t rp_darwin_io = {
    rp_unix_recv,
    rp_readv_chain,
    rp_udp_unix_recv,
    rp_unix_send,
    rp_udp_unix_send,
    rp_udp_unix_sendmsg_chain,
#if (RP_HAVE_SENDFILE)
    rp_darwin_sendfile_chain,
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
      &rp_darwin_hw_ncpu,
      sizeof(rp_darwin_hw_ncpu), 0 },

    { "net.inet.tcp.sendspace",
      &rp_darwin_net_inet_tcp_sendspace,
      sizeof(rp_darwin_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &rp_darwin_kern_ipc_somaxconn,
      sizeof(rp_darwin_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
rp_debug_init(void)
{
#if (RP_DEBUG_MALLOC)

    /*
     * MacOSX 10.6, 10.7:  MallocScribble fills freed memory with 0x55
     *                     and fills allocated memory with 0xAA.
     * MacOSX 10.4, 10.5:  MallocScribble fills freed memory with 0x55,
     *                     MallocPreScribble fills allocated memory with 0xAA.
     * MacOSX 10.3:        MallocScribble fills freed memory with 0x55,
     *                     and no way to fill allocated memory.
     */

    setenv("MallocScribble", "1", 0);

    rp_debug_malloc = 1;

#else

    if (getenv("MallocScribble")) {
        rp_debug_malloc = 1;
    }

#endif
}


rp_int_t
rp_os_specific_init(rp_log_t *log)
{
    size_t      size;
    rp_err_t   err;
    rp_uint_t  i;

    size = sizeof(rp_darwin_kern_ostype);
    if (sysctlbyname("kern.ostype", rp_darwin_kern_ostype, &size, NULL, 0)
        == -1)
    {
        err = rp_errno;

        if (err != RP_ENOENT) {

            rp_log_error(RP_LOG_ALERT, log, err,
                          "sysctlbyname(kern.ostype) failed");

            if (err != RP_ENOMEM) {
                return RP_ERROR;
            }

            rp_darwin_kern_ostype[size - 1] = '\0';
        }
    }

    size = sizeof(rp_darwin_kern_osrelease);
    if (sysctlbyname("kern.osrelease", rp_darwin_kern_osrelease, &size,
                     NULL, 0)
        == -1)
    {
        err = rp_errno;

        if (err != RP_ENOENT) {

            rp_log_error(RP_LOG_ALERT, log, err,
                          "sysctlbyname(kern.osrelease) failed");

            if (err != RP_ENOMEM) {
                return RP_ERROR;
            }

            rp_darwin_kern_osrelease[size - 1] = '\0';
        }
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

    rp_ncpu = rp_darwin_hw_ncpu;

    if (rp_darwin_kern_ipc_somaxconn > 32767) {
        rp_log_error(RP_LOG_ALERT, log, 0,
                      "sysctl kern.ipc.somaxconn must be less than 32768");
        return RP_ERROR;
    }

    rp_tcp_nodelay_and_tcp_nopush = 1;

    rp_os_io = rp_darwin_io;

    return RP_OK;
}


void
rp_os_specific_status(rp_log_t *log)
{
    u_long      value;
    rp_uint_t  i;

    if (rp_darwin_kern_ostype[0]) {
        rp_log_error(RP_LOG_NOTICE, log, 0, "OS: %s %s",
                      rp_darwin_kern_ostype, rp_darwin_kern_osrelease);
    }

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

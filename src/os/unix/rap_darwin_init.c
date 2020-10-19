
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


char    rap_darwin_kern_ostype[16];
char    rap_darwin_kern_osrelease[128];
int     rap_darwin_hw_ncpu;
int     rap_darwin_kern_ipc_somaxconn;
u_long  rap_darwin_net_inet_tcp_sendspace;

rap_uint_t  rap_debug_malloc;


static rap_os_io_t rap_darwin_io = {
    rap_unix_recv,
    rap_readv_chain,
    rap_udp_unix_recv,
    rap_unix_send,
    rap_udp_unix_send,
    rap_udp_unix_sendmsg_chain,
#if (RAP_HAVE_SENDFILE)
    rap_darwin_sendfile_chain,
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
      &rap_darwin_hw_ncpu,
      sizeof(rap_darwin_hw_ncpu), 0 },

    { "net.inet.tcp.sendspace",
      &rap_darwin_net_inet_tcp_sendspace,
      sizeof(rap_darwin_net_inet_tcp_sendspace), 0 },

    { "kern.ipc.somaxconn",
      &rap_darwin_kern_ipc_somaxconn,
      sizeof(rap_darwin_kern_ipc_somaxconn), 0 },

    { NULL, NULL, 0, 0 }
};


void
rap_debug_init(void)
{
#if (RAP_DEBUG_MALLOC)

    /*
     * MacOSX 10.6, 10.7:  MallocScribble fills freed memory with 0x55
     *                     and fills allocated memory with 0xAA.
     * MacOSX 10.4, 10.5:  MallocScribble fills freed memory with 0x55,
     *                     MallocPreScribble fills allocated memory with 0xAA.
     * MacOSX 10.3:        MallocScribble fills freed memory with 0x55,
     *                     and no way to fill allocated memory.
     */

    setenv("MallocScribble", "1", 0);

    rap_debug_malloc = 1;

#else

    if (getenv("MallocScribble")) {
        rap_debug_malloc = 1;
    }

#endif
}


rap_int_t
rap_os_specific_init(rap_log_t *log)
{
    size_t      size;
    rap_err_t   err;
    rap_uint_t  i;

    size = sizeof(rap_darwin_kern_ostype);
    if (sysctlbyname("kern.ostype", rap_darwin_kern_ostype, &size, NULL, 0)
        == -1)
    {
        err = rap_errno;

        if (err != RAP_ENOENT) {

            rap_log_error(RAP_LOG_ALERT, log, err,
                          "sysctlbyname(kern.ostype) failed");

            if (err != RAP_ENOMEM) {
                return RAP_ERROR;
            }

            rap_darwin_kern_ostype[size - 1] = '\0';
        }
    }

    size = sizeof(rap_darwin_kern_osrelease);
    if (sysctlbyname("kern.osrelease", rap_darwin_kern_osrelease, &size,
                     NULL, 0)
        == -1)
    {
        err = rap_errno;

        if (err != RAP_ENOENT) {

            rap_log_error(RAP_LOG_ALERT, log, err,
                          "sysctlbyname(kern.osrelease) failed");

            if (err != RAP_ENOMEM) {
                return RAP_ERROR;
            }

            rap_darwin_kern_osrelease[size - 1] = '\0';
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

        err = rap_errno;

        if (err == RAP_ENOENT) {
            continue;
        }

        rap_log_error(RAP_LOG_ALERT, log, err,
                      "sysctlbyname(%s) failed", sysctls[i].name);
        return RAP_ERROR;
    }

    rap_ncpu = rap_darwin_hw_ncpu;

    if (rap_darwin_kern_ipc_somaxconn > 32767) {
        rap_log_error(RAP_LOG_ALERT, log, 0,
                      "sysctl kern.ipc.somaxconn must be less than 32768");
        return RAP_ERROR;
    }

    rap_tcp_nodelay_and_tcp_nopush = 1;

    rap_os_io = rap_darwin_io;

    return RAP_OK;
}


void
rap_os_specific_status(rap_log_t *log)
{
    u_long      value;
    rap_uint_t  i;

    if (rap_darwin_kern_ostype[0]) {
        rap_log_error(RAP_LOG_NOTICE, log, 0, "OS: %s %s",
                      rap_darwin_kern_ostype, rap_darwin_kern_osrelease);
    }

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

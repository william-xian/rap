
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


u_char  rap_linux_kern_ostype[50];
u_char  rap_linux_kern_osrelease[50];


static rap_os_io_t rap_linux_io = {
    rap_unix_recv,
    rap_readv_chain,
    rap_udp_unix_recv,
    rap_unix_send,
    rap_udp_unix_send,
    rap_udp_unix_sendmsg_chain,
#if (RAP_HAVE_SENDFILE)
    rap_linux_sendfile_chain,
    RAP_IO_SENDFILE
#else
    rap_writev_chain,
    0
#endif
};


rap_int_t
rap_os_specific_init(rap_log_t *log)
{
    struct utsname  u;

    if (uname(&u) == -1) {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno, "uname() failed");
        return RAP_ERROR;
    }

    (void) rap_cpystrn(rap_linux_kern_ostype, (u_char *) u.sysname,
                       sizeof(rap_linux_kern_ostype));

    (void) rap_cpystrn(rap_linux_kern_osrelease, (u_char *) u.release,
                       sizeof(rap_linux_kern_osrelease));

    rap_os_io = rap_linux_io;

    return RAP_OK;
}


void
rap_os_specific_status(rap_log_t *log)
{
    rap_log_error(RAP_LOG_NOTICE, log, 0, "OS: %s %s",
                  rap_linux_kern_ostype, rap_linux_kern_osrelease);
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


u_char  rp_linux_kern_ostype[50];
u_char  rp_linux_kern_osrelease[50];


static rp_os_io_t rp_linux_io = {
    rp_unix_recv,
    rp_readv_chain,
    rp_udp_unix_recv,
    rp_unix_send,
    rp_udp_unix_send,
    rp_udp_unix_sendmsg_chain,
#if (RP_HAVE_SENDFILE)
    rp_linux_sendfile_chain,
    RP_IO_SENDFILE
#else
    rp_writev_chain,
    0
#endif
};


rp_int_t
rp_os_specific_init(rp_log_t *log)
{
    struct utsname  u;

    if (uname(&u) == -1) {
        rp_log_error(RP_LOG_ALERT, log, rp_errno, "uname() failed");
        return RP_ERROR;
    }

    (void) rp_cpystrn(rp_linux_kern_ostype, (u_char *) u.sysname,
                       sizeof(rp_linux_kern_ostype));

    (void) rp_cpystrn(rp_linux_kern_osrelease, (u_char *) u.release,
                       sizeof(rp_linux_kern_osrelease));

    rp_os_io = rp_linux_io;

    return RP_OK;
}


void
rp_os_specific_status(rp_log_t *log)
{
    rp_log_error(RP_LOG_NOTICE, log, 0, "OS: %s %s",
                  rp_linux_kern_ostype, rp_linux_kern_osrelease);
}

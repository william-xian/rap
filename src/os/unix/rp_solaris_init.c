
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


char rp_solaris_sysname[20];
char rp_solaris_release[10];
char rp_solaris_version[50];


static rp_os_io_t rp_solaris_io = {
    rp_unix_recv,
    rp_readv_chain,
    rp_udp_unix_recv,
    rp_unix_send,
    rp_udp_unix_send,
    rp_udp_unix_sendmsg_chain,
#if (RP_HAVE_SENDFILE)
    rp_solaris_sendfilev_chain,
    RP_IO_SENDFILE
#else
    rp_writev_chain,
    0
#endif
};


rp_int_t
rp_os_specific_init(rp_log_t *log)
{
    if (sysinfo(SI_SYSNAME, rp_solaris_sysname, sizeof(rp_solaris_sysname))
        == -1)
    {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return RP_ERROR;
    }

    if (sysinfo(SI_RELEASE, rp_solaris_release, sizeof(rp_solaris_release))
        == -1)
    {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "sysinfo(SI_RELEASE) failed");
        return RP_ERROR;
    }

    if (sysinfo(SI_VERSION, rp_solaris_version, sizeof(rp_solaris_version))
        == -1)
    {
        rp_log_error(RP_LOG_ALERT, log, rp_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return RP_ERROR;
    }


    rp_os_io = rp_solaris_io;

    return RP_OK;
}


void
rp_os_specific_status(rp_log_t *log)
{

    rp_log_error(RP_LOG_NOTICE, log, 0, "OS: %s %s",
                  rp_solaris_sysname, rp_solaris_release);

    rp_log_error(RP_LOG_NOTICE, log, 0, "version: %s",
                  rp_solaris_version);
}

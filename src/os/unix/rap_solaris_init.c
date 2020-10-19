
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


char rap_solaris_sysname[20];
char rap_solaris_release[10];
char rap_solaris_version[50];


static rap_os_io_t rap_solaris_io = {
    rap_unix_recv,
    rap_readv_chain,
    rap_udp_unix_recv,
    rap_unix_send,
    rap_udp_unix_send,
    rap_udp_unix_sendmsg_chain,
#if (RAP_HAVE_SENDFILE)
    rap_solaris_sendfilev_chain,
    RAP_IO_SENDFILE
#else
    rap_writev_chain,
    0
#endif
};


rap_int_t
rap_os_specific_init(rap_log_t *log)
{
    if (sysinfo(SI_SYSNAME, rap_solaris_sysname, sizeof(rap_solaris_sysname))
        == -1)
    {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return RAP_ERROR;
    }

    if (sysinfo(SI_RELEASE, rap_solaris_release, sizeof(rap_solaris_release))
        == -1)
    {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "sysinfo(SI_RELEASE) failed");
        return RAP_ERROR;
    }

    if (sysinfo(SI_VERSION, rap_solaris_version, sizeof(rap_solaris_version))
        == -1)
    {
        rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                      "sysinfo(SI_SYSNAME) failed");
        return RAP_ERROR;
    }


    rap_os_io = rap_solaris_io;

    return RAP_OK;
}


void
rap_os_specific_status(rap_log_t *log)
{

    rap_log_error(RAP_LOG_NOTICE, log, 0, "OS: %s %s",
                  rap_solaris_sysname, rap_solaris_release);

    rap_log_error(RAP_LOG_NOTICE, log, 0, "version: %s",
                  rap_solaris_version);
}

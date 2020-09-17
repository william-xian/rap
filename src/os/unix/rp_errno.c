
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


/*
 * The strerror() messages are copied because:
 *
 * 1) strerror() and strerror_r() functions are not Async-Signal-Safe,
 *    therefore, they cannot be used in signal handlers;
 *
 * 2) a direct sys_errlist[] array may be used instead of these functions,
 *    but Linux linker warns about its usage:
 *
 * warning: `sys_errlist' is deprecated; use `strerror' or `strerror_r' instead
 * warning: `sys_nerr' is deprecated; use `strerror' or `strerror_r' instead
 *
 *    causing false bug reports.
 */


static rp_str_t  *rp_sys_errlist;
static rp_str_t   rp_unknown_error = rp_string("Unknown error");


u_char *
rp_strerror(rp_err_t err, u_char *errstr, size_t size)
{
    rp_str_t  *msg;

    msg = ((rp_uint_t) err < RP_SYS_NERR) ? &rp_sys_errlist[err]:
                                              &rp_unknown_error;
    size = rp_min(size, msg->len);

    return rp_cpymem(errstr, msg->data, size);
}


rp_int_t
rp_strerror_init(void)
{
    char       *msg;
    u_char     *p;
    size_t      len;
    rp_err_t   err;

    /*
     * rp_strerror() is not ready to work at this stage, therefore,
     * malloc() is used and possible errors are logged using strerror().
     */

    len = RP_SYS_NERR * sizeof(rp_str_t);

    rp_sys_errlist = malloc(len);
    if (rp_sys_errlist == NULL) {
        goto failed;
    }

    for (err = 0; err < RP_SYS_NERR; err++) {
        msg = strerror(err);
        len = rp_strlen(msg);

        p = malloc(len);
        if (p == NULL) {
            goto failed;
        }

        rp_memcpy(p, msg, len);
        rp_sys_errlist[err].len = len;
        rp_sys_errlist[err].data = p;
    }

    return RP_OK;

failed:

    err = errno;
    rp_log_stderr(0, "malloc(%uz) failed (%d: %s)", len, err, strerror(err));

    return RP_ERROR;
}

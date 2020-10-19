
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


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


static rap_str_t  *rap_sys_errlist;
static rap_str_t   rap_unknown_error = rap_string("Unknown error");


u_char *
rap_strerror(rap_err_t err, u_char *errstr, size_t size)
{
    rap_str_t  *msg;

    msg = ((rap_uint_t) err < RAP_SYS_NERR) ? &rap_sys_errlist[err]:
                                              &rap_unknown_error;
    size = rap_min(size, msg->len);

    return rap_cpymem(errstr, msg->data, size);
}


rap_int_t
rap_strerror_init(void)
{
    char       *msg;
    u_char     *p;
    size_t      len;
    rap_err_t   err;

    /*
     * rap_strerror() is not ready to work at this stage, therefore,
     * malloc() is used and possible errors are logged using strerror().
     */

    len = RAP_SYS_NERR * sizeof(rap_str_t);

    rap_sys_errlist = malloc(len);
    if (rap_sys_errlist == NULL) {
        goto failed;
    }

    for (err = 0; err < RAP_SYS_NERR; err++) {
        msg = strerror(err);
        len = rap_strlen(msg);

        p = malloc(len);
        if (p == NULL) {
            goto failed;
        }

        rap_memcpy(p, msg, len);
        rap_sys_errlist[err].len = len;
        rap_sys_errlist[err].data = p;
    }

    return RAP_OK;

failed:

    err = errno;
    rap_log_stderr(0, "malloc(%uz) failed (%d: %s)", len, err, strerror(err));

    return RAP_ERROR;
}

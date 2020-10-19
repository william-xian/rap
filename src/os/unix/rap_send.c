
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


ssize_t
rap_unix_send(rap_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rap_err_t     err;
    rap_event_t  *wev;

    wev = c->write;

#if (RAP_HAVE_KQUEUE)

    if ((rap_event_flags & RAP_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) rap_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return RAP_ERROR;
    }

#endif

    for ( ;; ) {
        n = send(c->fd, buf, size, 0);

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "send: fd:%d %z of %uz", c->fd, n, size);

        if (n > 0) {
            if (n < (ssize_t) size) {
                wev->ready = 0;
            }

            c->sent += n;

            return n;
        }

        err = rap_socket_errno;

        if (n == 0) {
            rap_log_error(RAP_LOG_ALERT, c->log, err, "send() returned zero");
            wev->ready = 0;
            return n;
        }

        if (err == RAP_EAGAIN || err == RAP_EINTR) {
            wev->ready = 0;

            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "send() not ready");

            if (err == RAP_EAGAIN) {
                return RAP_AGAIN;
            }

        } else {
            wev->error = 1;
            (void) rap_connection_error(c, err, "send() failed");
            return RAP_ERROR;
        }
    }
}

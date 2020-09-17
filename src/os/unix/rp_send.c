
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


ssize_t
rp_unix_send(rp_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rp_err_t     err;
    rp_event_t  *wev;

    wev = c->write;

#if (RP_HAVE_KQUEUE)

    if ((rp_event_flags & RP_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) rp_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return RP_ERROR;
    }

#endif

    for ( ;; ) {
        n = send(c->fd, buf, size, 0);

        rp_log_debug3(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "send: fd:%d %z of %uz", c->fd, n, size);

        if (n > 0) {
            if (n < (ssize_t) size) {
                wev->ready = 0;
            }

            c->sent += n;

            return n;
        }

        err = rp_socket_errno;

        if (n == 0) {
            rp_log_error(RP_LOG_ALERT, c->log, err, "send() returned zero");
            wev->ready = 0;
            return n;
        }

        if (err == RP_EAGAIN || err == RP_EINTR) {
            wev->ready = 0;

            rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, err,
                           "send() not ready");

            if (err == RP_EAGAIN) {
                return RP_AGAIN;
            }

        } else {
            wev->error = 1;
            (void) rp_connection_error(c, err, "send() failed");
            return RP_ERROR;
        }
    }
}

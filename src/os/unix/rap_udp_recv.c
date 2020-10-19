
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


ssize_t
rap_udp_unix_recv(rap_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rap_err_t     err;
    rap_event_t  *rev;

    rev = c->read;

    do {
        n = recv(c->fd, buf, size, 0);

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n >= 0) {

#if (RAP_HAVE_KQUEUE)

            if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    rev->ready = 0;
                    rev->available = 0;
                }
            }

#endif

            return n;
        }

        err = rap_socket_errno;

        if (err == RAP_EAGAIN || err == RAP_EINTR) {
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "recv() not ready");
            n = RAP_AGAIN;

        } else {
            n = rap_connection_error(c, err, "recv() failed");
            break;
        }

    } while (err == RAP_EINTR);

    rev->ready = 0;

    if (n == RAP_ERROR) {
        rev->error = 1;
    }

    return n;
}

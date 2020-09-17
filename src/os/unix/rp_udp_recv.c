
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


ssize_t
rp_udp_unix_recv(rp_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rp_err_t     err;
    rp_event_t  *rev;

    rev = c->read;

    do {
        n = recv(c->fd, buf, size, 0);

        rp_log_debug3(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n >= 0) {

#if (RP_HAVE_KQUEUE)

            if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
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

        err = rp_socket_errno;

        if (err == RP_EAGAIN || err == RP_EINTR) {
            rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, err,
                           "recv() not ready");
            n = RP_AGAIN;

        } else {
            n = rp_connection_error(c, err, "recv() failed");
            break;
        }

    } while (err == RP_EINTR);

    rev->ready = 0;

    if (n == RP_ERROR) {
        rev->error = 1;
    }

    return n;
}

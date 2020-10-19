
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


ssize_t
rap_udp_unix_send(rap_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rap_err_t     err;
    rap_event_t  *wev;

    wev = c->write;

    for ( ;; ) {
        n = sendto(c->fd, buf, size, 0, c->sockaddr, c->socklen);

        rap_log_debug4(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "sendto: fd:%d %z of %uz to \"%V\"",
                       c->fd, n, size, &c->addr_text);

        if (n >= 0) {
            if ((size_t) n != size) {
                wev->error = 1;
                (void) rap_connection_error(c, 0, "sendto() incomplete");
                return RAP_ERROR;
            }

            c->sent += n;

            return n;
        }

        err = rap_socket_errno;

        if (err == RAP_EAGAIN) {
            wev->ready = 0;
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, RAP_EAGAIN,
                           "sendto() not ready");
            return RAP_AGAIN;
        }

        if (err != RAP_EINTR) {
            wev->error = 1;
            (void) rap_connection_error(c, err, "sendto() failed");
            return RAP_ERROR;
        }
    }
}

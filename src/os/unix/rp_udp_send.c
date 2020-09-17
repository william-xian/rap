
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


ssize_t
rp_udp_unix_send(rp_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rp_err_t     err;
    rp_event_t  *wev;

    wev = c->write;

    for ( ;; ) {
        n = sendto(c->fd, buf, size, 0, c->sockaddr, c->socklen);

        rp_log_debug4(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "sendto: fd:%d %z of %uz to \"%V\"",
                       c->fd, n, size, &c->addr_text);

        if (n >= 0) {
            if ((size_t) n != size) {
                wev->error = 1;
                (void) rp_connection_error(c, 0, "sendto() incomplete");
                return RP_ERROR;
            }

            c->sent += n;

            return n;
        }

        err = rp_socket_errno;

        if (err == RP_EAGAIN) {
            wev->ready = 0;
            rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, RP_EAGAIN,
                           "sendto() not ready");
            return RP_AGAIN;
        }

        if (err != RP_EINTR) {
            wev->error = 1;
            (void) rp_connection_error(c, err, "sendto() failed");
            return RP_ERROR;
        }
    }
}

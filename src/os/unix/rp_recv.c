
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


ssize_t
rp_unix_recv(rp_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rp_err_t     err;
    rp_event_t  *rev;

    rev = c->read;

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
        rp_log_debug3(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    rp_set_socket_errno(rev->kq_errno);

                    return rp_connection_error(c, rev->kq_errno,
                               "kevent() reported about an closed connection");
                }

                return 0;

            } else {
                rev->ready = 0;
                return RP_AGAIN;
            }
        }
    }

#endif

#if (RP_HAVE_EPOLLRDHUP)

    if (rp_event_flags & RP_USE_EPOLL_EVENT) {
        rp_log_debug2(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            rev->ready = 0;
            return RP_AGAIN;
        }
    }

#endif

    do {
        n = recv(c->fd, buf, size, 0);

        rp_log_debug3(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

#if (RP_HAVE_KQUEUE)

            /*
             * on FreeBSD recv() may return 0 on closed socket
             * even if kqueue reported about available data
             */

            if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
                rev->available = 0;
            }

#endif

            return 0;
        }

        if (n > 0) {

#if (RP_HAVE_KQUEUE)

            if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

#if (RP_HAVE_FIONREAD)

            if (rev->available >= 0) {
                rev->available -= n;

                /*
                 * negative rev->available means some additional bytes
                 * were received between kernel notification and recv(),
                 * and therefore ev->ready can be safely reset even for
                 * edge-triggered event methods
                 */

                if (rev->available < 0) {
                    rev->available = 0;
                    rev->ready = 0;
                }

                rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);

            } else if ((size_t) n == size) {

                if (rp_socket_nread(c->fd, &rev->available) == -1) {
                    n = rp_connection_error(c, rp_socket_errno,
                                             rp_socket_nread_n " failed");
                    break;
                }

                rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);
            }

#endif

#if (RP_HAVE_EPOLLRDHUP)

            if ((rp_event_flags & RP_USE_EPOLL_EVENT)
                && rp_use_epoll_rdhup)
            {
                if ((size_t) n < size) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

            if ((size_t) n < size
                && !(rp_event_flags & RP_USE_GREEDY_EVENT))
            {
                rev->ready = 0;
            }

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

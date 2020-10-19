
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


ssize_t
rap_unix_recv(rap_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    rap_err_t     err;
    rap_event_t  *rev;

    rev = c->read;

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
        rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    rap_set_socket_errno(rev->kq_errno);

                    return rap_connection_error(c, rev->kq_errno,
                               "kevent() reported about an closed connection");
                }

                return 0;

            } else {
                rev->ready = 0;
                return RAP_AGAIN;
            }
        }
    }

#endif

#if (RAP_HAVE_EPOLLRDHUP)

    if (rap_event_flags & RAP_USE_EPOLL_EVENT) {
        rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            rev->ready = 0;
            return RAP_AGAIN;
        }
    }

#endif

    do {
        n = recv(c->fd, buf, size, 0);

        rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

#if (RAP_HAVE_KQUEUE)

            /*
             * on FreeBSD recv() may return 0 on closed socket
             * even if kqueue reported about available data
             */

            if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
                rev->available = 0;
            }

#endif

            return 0;
        }

        if (n > 0) {

#if (RAP_HAVE_KQUEUE)

            if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
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

#if (RAP_HAVE_FIONREAD)

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

                rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);

            } else if ((size_t) n == size) {

                if (rap_socket_nread(c->fd, &rev->available) == -1) {
                    n = rap_connection_error(c, rap_socket_errno,
                                             rap_socket_nread_n " failed");
                    break;
                }

                rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);
            }

#endif

#if (RAP_HAVE_EPOLLRDHUP)

            if ((rap_event_flags & RAP_USE_EPOLL_EVENT)
                && rap_use_epoll_rdhup)
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
                && !(rap_event_flags & RAP_USE_GREEDY_EVENT))
            {
                rev->ready = 0;
            }

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

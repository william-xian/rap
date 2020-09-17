
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


ssize_t
rp_readv_chain(rp_connection_t *c, rp_chain_t *chain, off_t limit)
{
    u_char        *prev;
    ssize_t        n, size;
    rp_err_t      err;
    rp_array_t    vec;
    rp_event_t   *rev;
    struct iovec  *iov, iovs[RP_IOVS_PREALLOCATE];

    rev = c->read;

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
        rp_log_debug3(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "readv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                rp_log_error(RP_LOG_INFO, c->log, rev->kq_errno,
                              "kevent() reported about an closed connection");

                if (rev->kq_errno) {
                    rev->error = 1;
                    rp_set_socket_errno(rev->kq_errno);
                    return RP_ERROR;
                }

                return 0;

            } else {
                return RP_AGAIN;
            }
        }
    }

#endif

#if (RP_HAVE_EPOLLRDHUP)

    if (rp_event_flags & RP_USE_EPOLL_EVENT) {
        rp_log_debug2(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "readv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            return RP_AGAIN;
        }
    }

#endif

    prev = NULL;
    iov = NULL;
    size = 0;

    vec.elts = iovs;
    vec.nelts = 0;
    vec.size = sizeof(struct iovec);
    vec.nalloc = RP_IOVS_PREALLOCATE;
    vec.pool = c->pool;

    /* coalesce the neighbouring bufs */

    while (chain) {
        n = chain->buf->end - chain->buf->last;

        if (limit) {
            if (size >= limit) {
                break;
            }

            if (size + n > limit) {
                n = (ssize_t) (limit - size);
            }
        }

        if (prev == chain->buf->last) {
            iov->iov_len += n;

        } else {
            if (vec.nelts >= IOV_MAX) {
                break;
            }

            iov = rp_array_push(&vec);
            if (iov == NULL) {
                return RP_ERROR;
            }

            iov->iov_base = (void *) chain->buf->last;
            iov->iov_len = n;
        }

        size += n;
        prev = chain->buf->end;
        chain = chain->next;
    }

    rp_log_debug2(RP_LOG_DEBUG_EVENT, c->log, 0,
                   "readv: %ui, last:%uz", vec.nelts, iov->iov_len);

    do {
        n = readv(c->fd, (struct iovec *) vec.elts, vec.nelts);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

#if (RP_HAVE_KQUEUE)

            /*
             * on FreeBSD readv() may return 0 on closed socket
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
                 * bytes may be received between kevent() and readv()
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
                 * were received between kernel notification and readv(),
                 * and therefore ev->ready can be safely reset even for
                 * edge-triggered event methods
                 */

                if (rev->available < 0) {
                    rev->available = 0;
                    rev->ready = 0;
                }

                rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, 0,
                               "readv: avail:%d", rev->available);

            } else if (n == size) {

                if (rp_socket_nread(c->fd, &rev->available) == -1) {
                    n = rp_connection_error(c, rp_socket_errno,
                                             rp_socket_nread_n " failed");
                    break;
                }

                rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, 0,
                               "readv: avail:%d", rev->available);
            }

#endif

#if (RP_HAVE_EPOLLRDHUP)

            if ((rp_event_flags & RP_USE_EPOLL_EVENT)
                && rp_use_epoll_rdhup)
            {
                if (n < size) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

            if (n < size && !(rp_event_flags & RP_USE_GREEDY_EVENT)) {
                rev->ready = 0;
            }

            return n;
        }

        err = rp_socket_errno;

        if (err == RP_EAGAIN || err == RP_EINTR) {
            rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, err,
                           "readv() not ready");
            n = RP_AGAIN;

        } else {
            n = rp_connection_error(c, err, "readv() failed");
            break;
        }

    } while (err == RP_EINTR);

    rev->ready = 0;

    if (n == RP_ERROR) {
        c->read->error = 1;
    }

    return n;
}

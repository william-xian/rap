
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


ssize_t
rap_readv_chain(rap_connection_t *c, rap_chain_t *chain, off_t limit)
{
    u_char        *prev;
    ssize_t        n, size;
    rap_err_t      err;
    rap_array_t    vec;
    rap_event_t   *rev;
    struct iovec  *iov, iovs[RAP_IOVS_PREALLOCATE];

    rev = c->read;

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
        rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "readv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                rap_log_error(RAP_LOG_INFO, c->log, rev->kq_errno,
                              "kevent() reported about an closed connection");

                if (rev->kq_errno) {
                    rev->error = 1;
                    rap_set_socket_errno(rev->kq_errno);
                    return RAP_ERROR;
                }

                return 0;

            } else {
                return RAP_AGAIN;
            }
        }
    }

#endif

#if (RAP_HAVE_EPOLLRDHUP)

    if (rap_event_flags & RAP_USE_EPOLL_EVENT) {
        rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "readv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            return RAP_AGAIN;
        }
    }

#endif

    prev = NULL;
    iov = NULL;
    size = 0;

    vec.elts = iovs;
    vec.nelts = 0;
    vec.size = sizeof(struct iovec);
    vec.nalloc = RAP_IOVS_PREALLOCATE;
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

            iov = rap_array_push(&vec);
            if (iov == NULL) {
                return RAP_ERROR;
            }

            iov->iov_base = (void *) chain->buf->last;
            iov->iov_len = n;
        }

        size += n;
        prev = chain->buf->end;
        chain = chain->next;
    }

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "readv: %ui, last:%uz", vec.nelts, iov->iov_len);

    do {
        n = readv(c->fd, (struct iovec *) vec.elts, vec.nelts);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

#if (RAP_HAVE_KQUEUE)

            /*
             * on FreeBSD readv() may return 0 on closed socket
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

#if (RAP_HAVE_FIONREAD)

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

                rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                               "readv: avail:%d", rev->available);

            } else if (n == size) {

                if (rap_socket_nread(c->fd, &rev->available) == -1) {
                    n = rap_connection_error(c, rap_socket_errno,
                                             rap_socket_nread_n " failed");
                    break;
                }

                rap_log_debug1(RAP_LOG_DEBUG_EVENT, c->log, 0,
                               "readv: avail:%d", rev->available);
            }

#endif

#if (RAP_HAVE_EPOLLRDHUP)

            if ((rap_event_flags & RAP_USE_EPOLL_EVENT)
                && rap_use_epoll_rdhup)
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

            if (n < size && !(rap_event_flags & RAP_USE_GREEDY_EVENT)) {
                rev->ready = 0;
            }

            return n;
        }

        err = rap_socket_errno;

        if (err == RAP_EAGAIN || err == RAP_EINTR) {
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "readv() not ready");
            n = RAP_AGAIN;

        } else {
            n = rap_connection_error(c, err, "readv() failed");
            break;
        }

    } while (err == RAP_EINTR);

    rev->ready = 0;

    if (n == RAP_ERROR) {
        c->read->error = 1;
    }

    return n;
}

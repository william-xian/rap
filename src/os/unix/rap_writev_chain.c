
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


rap_chain_t *
rap_writev_chain(rap_connection_t *c, rap_chain_t *in, off_t limit)
{
    ssize_t        n, sent;
    off_t          send, prev_send;
    rap_chain_t   *cl;
    rap_event_t   *wev;
    rap_iovec_t    vec;
    struct iovec   iovs[RAP_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (RAP_HAVE_KQUEUE)

    if ((rap_event_flags & RAP_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) rap_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return RAP_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (RAP_MAX_SIZE_T_VALUE - rap_pagesize)) {
        limit = RAP_MAX_SIZE_T_VALUE - rap_pagesize;
    }

    send = 0;

    vec.iovs = iovs;
    vec.nalloc = RAP_IOVS_PREALLOCATE;

    for ( ;; ) {
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        cl = rap_output_chain_to_iovec(&vec, in, limit - send, c->log);

        if (cl == RAP_CHAIN_ERROR) {
            return RAP_CHAIN_ERROR;
        }

        if (cl && cl->buf->in_file) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "file buf in writev "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            rap_debug_point();

            return RAP_CHAIN_ERROR;
        }

        send += vec.size;

        n = rap_writev(c, &vec);

        if (n == RAP_ERROR) {
            return RAP_CHAIN_ERROR;
        }

        sent = (n == RAP_AGAIN) ? 0 : n;

        c->sent += sent;

        in = rap_chain_update_sent(in, sent);

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


rap_chain_t *
rap_output_chain_to_iovec(rap_iovec_t *vec, rap_chain_t *in, size_t limit,
    rap_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    rap_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    for ( /* void */ ; in && total < limit; in = in->next) {

        if (rap_buf_special(in->buf)) {
            continue;
        }

        if (in->buf->in_file) {
            break;
        }

        if (!rap_buf_in_memory(in->buf)) {
            rap_log_error(RAP_LOG_ALERT, log, 0,
                          "bad buf in output chain "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            rap_debug_point();

            return RAP_CHAIN_ERROR;
        }

        size = in->buf->last - in->buf->pos;

        if (size > limit - total) {
            size = limit - total;
        }

        if (prev == in->buf->pos) {
            iov->iov_len += size;

        } else {
            if (n == vec->nalloc) {
                break;
            }

            iov = &vec->iovs[n++];

            iov->iov_base = (void *) in->buf->pos;
            iov->iov_len = size;
        }

        prev = in->buf->pos + size;
        total += size;
    }

    vec->count = n;
    vec->size = total;

    return in;
}


ssize_t
rap_writev(rap_connection_t *c, rap_iovec_t *vec)
{
    ssize_t    n;
    rap_err_t  err;

eintr:

    n = writev(c->fd, vec->iovs, vec->count);

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "writev: %z of %uz", n, vec->size);

    if (n == -1) {
        err = rap_errno;

        switch (err) {
        case RAP_EAGAIN:
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "writev() not ready");
            return RAP_AGAIN;

        case RAP_EINTR:
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "writev() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            rap_connection_error(c, err, "writev() failed");
            return RAP_ERROR;
        }
    }

    return n;
}

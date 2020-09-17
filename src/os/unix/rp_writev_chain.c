
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


rp_chain_t *
rp_writev_chain(rp_connection_t *c, rp_chain_t *in, off_t limit)
{
    ssize_t        n, sent;
    off_t          send, prev_send;
    rp_chain_t   *cl;
    rp_event_t   *wev;
    rp_iovec_t    vec;
    struct iovec   iovs[RP_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }

#if (RP_HAVE_KQUEUE)

    if ((rp_event_flags & RP_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) rp_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return RP_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    if (limit == 0 || limit > (off_t) (RP_MAX_SIZE_T_VALUE - rp_pagesize)) {
        limit = RP_MAX_SIZE_T_VALUE - rp_pagesize;
    }

    send = 0;

    vec.iovs = iovs;
    vec.nalloc = RP_IOVS_PREALLOCATE;

    for ( ;; ) {
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        cl = rp_output_chain_to_iovec(&vec, in, limit - send, c->log);

        if (cl == RP_CHAIN_ERROR) {
            return RP_CHAIN_ERROR;
        }

        if (cl && cl->buf->in_file) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
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

            rp_debug_point();

            return RP_CHAIN_ERROR;
        }

        send += vec.size;

        n = rp_writev(c, &vec);

        if (n == RP_ERROR) {
            return RP_CHAIN_ERROR;
        }

        sent = (n == RP_AGAIN) ? 0 : n;

        c->sent += sent;

        in = rp_chain_update_sent(in, sent);

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


rp_chain_t *
rp_output_chain_to_iovec(rp_iovec_t *vec, rp_chain_t *in, size_t limit,
    rp_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    rp_uint_t     n;
    struct iovec  *iov;

    iov = NULL;
    prev = NULL;
    total = 0;
    n = 0;

    for ( /* void */ ; in && total < limit; in = in->next) {

        if (rp_buf_special(in->buf)) {
            continue;
        }

        if (in->buf->in_file) {
            break;
        }

        if (!rp_buf_in_memory(in->buf)) {
            rp_log_error(RP_LOG_ALERT, log, 0,
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

            rp_debug_point();

            return RP_CHAIN_ERROR;
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
rp_writev(rp_connection_t *c, rp_iovec_t *vec)
{
    ssize_t    n;
    rp_err_t  err;

eintr:

    n = writev(c->fd, vec->iovs, vec->count);

    rp_log_debug2(RP_LOG_DEBUG_EVENT, c->log, 0,
                   "writev: %z of %uz", n, vec->size);

    if (n == -1) {
        err = rp_errno;

        switch (err) {
        case RP_EAGAIN:
            rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, err,
                           "writev() not ready");
            return RP_AGAIN;

        case RP_EINTR:
            rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, err,
                           "writev() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            rp_connection_error(c, err, "writev() failed");
            return RP_ERROR;
        }
    }

    return n;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


/*
 * It seems that Darwin 9.4 (Mac OS X 1.5) sendfile() has the same
 * old bug as early FreeBSD sendfile() syscall:
 * http://bugs.freebsd.org/33771
 *
 * Besides sendfile() has another bug: if one calls sendfile()
 * with both a header and a trailer, then sendfile() ignores a file part
 * at all and sends only the header and the trailer together.
 * For this reason we send a trailer only if there is no a header.
 *
 * Although sendfile() allows to pass a header or a trailer,
 * it may send the header or the trailer and a part of the file
 * in different packets.  And FreeBSD workaround (TCP_NOPUSH option)
 * does not help.
 */


rp_chain_t *
rp_darwin_sendfile_chain(rp_connection_t *c, rp_chain_t *in, off_t limit)
{
    int              rc;
    off_t            send, prev_send, sent;
    off_t            file_size;
    ssize_t          n;
    rp_uint_t       eintr;
    rp_err_t        err;
    rp_buf_t       *file;
    rp_event_t     *wev;
    rp_chain_t     *cl;
    rp_iovec_t      header, trailer;
    struct sf_hdtr   hdtr;
    struct iovec     headers[RP_IOVS_PREALLOCATE];
    struct iovec     trailers[RP_IOVS_PREALLOCATE];

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

    header.iovs = headers;
    header.nalloc = RP_IOVS_PREALLOCATE;

    trailer.iovs = trailers;
    trailer.nalloc = RP_IOVS_PREALLOCATE;

    for ( ;; ) {
        eintr = 0;
        prev_send = send;

        /* create the header iovec and coalesce the neighbouring bufs */

        cl = rp_output_chain_to_iovec(&header, in, limit - send, c->log);

        if (cl == RP_CHAIN_ERROR) {
            return RP_CHAIN_ERROR;
        }

        send += header.size;

        if (cl && cl->buf->in_file && send < limit) {
            file = cl->buf;

            /* coalesce the neighbouring file bufs */

            file_size = rp_chain_coalesce_file(&cl, limit - send);

            send += file_size;

            if (header.count == 0 && send < limit) {

                /*
                 * create the trailer iovec and coalesce the neighbouring bufs
                 */

                cl = rp_output_chain_to_iovec(&trailer, cl, limit - send,
                                               c->log);
                if (cl == RP_CHAIN_ERROR) {
                    return RP_CHAIN_ERROR;
                }

                send += trailer.size;

            } else {
                trailer.count = 0;
            }

            /*
             * sendfile() returns EINVAL if sf_hdtr's count is 0,
             * but corresponding pointer is not NULL
             */

            hdtr.headers = header.count ? header.iovs : NULL;
            hdtr.hdr_cnt = header.count;
            hdtr.trailers = trailer.count ? trailer.iovs : NULL;
            hdtr.trl_cnt = trailer.count;

            sent = header.size + file_size;

            rp_log_debug3(RP_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: @%O %O h:%uz",
                           file->file_pos, sent, header.size);

            rc = sendfile(file->file->fd, c->fd, file->file_pos,
                          &sent, &hdtr, 0);

            if (rc == -1) {
                err = rp_errno;

                switch (err) {
                case RP_EAGAIN:
                    break;

                case RP_EINTR:
                    eintr = 1;
                    break;

                default:
                    wev->error = 1;
                    (void) rp_connection_error(c, err, "sendfile() failed");
                    return RP_CHAIN_ERROR;
                }

                rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, err,
                               "sendfile() sent only %O bytes", sent);
            }

            if (rc == 0 && sent == 0) {

                /*
                 * if rc and sent equal to zero, then someone
                 * has truncated the file, so the offset became beyond
                 * the end of the file
                 */

                rp_log_error(RP_LOG_ALERT, c->log, 0,
                              "sendfile() reported that \"%s\" was truncated",
                              file->file->name.data);

                return RP_CHAIN_ERROR;
            }

            rp_log_debug4(RP_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: %d, @%O %O:%O",
                           rc, file->file_pos, sent, file_size + header.size);

        } else {
            n = rp_writev(c, &header);

            if (n == RP_ERROR) {
                return RP_CHAIN_ERROR;
            }

            sent = (n == RP_AGAIN) ? 0 : n;
        }

        c->sent += sent;

        in = rp_chain_update_sent(in, sent);

        if (eintr) {
            send = prev_send + sent;
            continue;
        }

        if (send - prev_send != sent) {
            wev->ready = 0;
            return in;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}

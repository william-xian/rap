
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


/*
 * Although FreeBSD sendfile() allows to pass a header and a trailer,
 * it cannot send a header with a part of the file in one packet until
 * FreeBSD 5.3.  Besides, over the fast ethernet connection sendfile()
 * may send the partially filled packets, i.e. the 8 file pages may be sent
 * as the 11 full 1460-bytes packets, then one incomplete 324-bytes packet,
 * and then again the 11 full 1460-bytes packets.
 *
 * Therefore we use the TCP_NOPUSH option (similar to Linux's TCP_CORK)
 * to postpone the sending - it not only sends a header and the first part of
 * the file in one packet, but also sends the file pages in the full packets.
 *
 * But until FreeBSD 4.5 turning TCP_NOPUSH off does not flush a pending
 * data that less than MSS, so that data may be sent with 5 second delay.
 * So we do not use TCP_NOPUSH on FreeBSD prior to 4.5, although it can be used
 * for non-keepalive HTTP connections.
 */


rp_chain_t *
rp_freebsd_sendfile_chain(rp_connection_t *c, rp_chain_t *in, off_t limit)
{
    int               rc, flags;
    off_t             send, prev_send, sent;
    size_t            file_size;
    ssize_t           n;
    rp_uint_t        eintr, eagain;
    rp_err_t         err;
    rp_buf_t        *file;
    rp_event_t      *wev;
    rp_chain_t      *cl;
    rp_iovec_t       header, trailer;
    struct sf_hdtr    hdtr;
    struct iovec      headers[RP_IOVS_PREALLOCATE];
    struct iovec      trailers[RP_IOVS_PREALLOCATE];
#if (RP_HAVE_AIO_SENDFILE)
    rp_uint_t        ebusy;
    rp_event_aio_t  *aio;
#endif

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
    eagain = 0;
    flags = 0;

#if (RP_HAVE_AIO_SENDFILE && RP_SUPPRESS_WARN)
    aio = NULL;
    file = NULL;
#endif

    header.iovs = headers;
    header.nalloc = RP_IOVS_PREALLOCATE;

    trailer.iovs = trailers;
    trailer.nalloc = RP_IOVS_PREALLOCATE;

    for ( ;; ) {
        eintr = 0;
#if (RP_HAVE_AIO_SENDFILE)
        ebusy = 0;
#endif
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

            file_size = (size_t) rp_chain_coalesce_file(&cl, limit - send);

            send += file_size;

            if (send < limit) {

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

            if (rp_freebsd_use_tcp_nopush
                && c->tcp_nopush == RP_TCP_NOPUSH_UNSET)
            {
                if (rp_tcp_nopush(c->fd) == -1) {
                    err = rp_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing without the TCP_NOPUSH
                     */

                    if (err != RP_EINTR) {
                        wev->error = 1;
                        (void) rp_connection_error(c, err,
                                                    rp_tcp_nopush_n " failed");
                        return RP_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nopush = RP_TCP_NOPUSH_SET;

                    rp_log_debug0(RP_LOG_DEBUG_EVENT, c->log, 0,
                                   "tcp_nopush");
                }
            }

            /*
             * sendfile() does unneeded work if sf_hdtr's count is 0,
             * but corresponding pointer is not NULL
             */

            hdtr.headers = header.count ? header.iovs : NULL;
            hdtr.hdr_cnt = header.count;
            hdtr.trailers = trailer.count ? trailer.iovs : NULL;
            hdtr.trl_cnt = trailer.count;

            /*
             * the "nbytes bug" of the old sendfile() syscall:
             * http://bugs.freebsd.org/33771
             */

            if (!rp_freebsd_sendfile_nbytes_bug) {
                header.size = 0;
            }

            sent = 0;

#if (RP_HAVE_AIO_SENDFILE)
            aio = file->file->aio;
            flags = (aio && aio->preload_handler) ? SF_NODISKIO : 0;
#endif

            rc = sendfile(file->file->fd, c->fd, file->file_pos,
                          file_size + header.size, &hdtr, &sent, flags);

            if (rc == -1) {
                err = rp_errno;

                switch (err) {
                case RP_EAGAIN:
                    eagain = 1;
                    break;

                case RP_EINTR:
                    eintr = 1;
                    break;

#if (RP_HAVE_AIO_SENDFILE)
                case RP_EBUSY:
                    ebusy = 1;
                    break;
#endif

                default:
                    wev->error = 1;
                    (void) rp_connection_error(c, err, "sendfile() failed");
                    return RP_CHAIN_ERROR;
                }

                rp_log_debug1(RP_LOG_DEBUG_EVENT, c->log, err,
                               "sendfile() sent only %O bytes", sent);

            /*
             * sendfile() in FreeBSD 3.x-4.x may return value >= 0
             * on success, although only 0 is documented
             */

            } else if (rc >= 0 && sent == 0) {

                /*
                 * if rc is OK and sent equal to zero, then someone
                 * has truncated the file, so the offset became beyond
                 * the end of the file
                 */

                rp_log_error(RP_LOG_ALERT, c->log, 0,
                         "sendfile() reported that \"%s\" was truncated at %O",
                         file->file->name.data, file->file_pos);

                return RP_CHAIN_ERROR;
            }

            rp_log_debug4(RP_LOG_DEBUG_EVENT, c->log, 0,
                           "sendfile: %d, @%O %O:%uz",
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

#if (RP_HAVE_AIO_SENDFILE)

        if (ebusy) {
            if (aio->event.active) {
                /*
                 * tolerate duplicate calls; they can happen due to subrequests
                 * or multiple calls of the next body filter from a filter
                 */

                if (sent) {
                    c->busy_count = 0;
                }

                return in;
            }

            if (sent == 0) {
                c->busy_count++;

                if (c->busy_count > 2) {
                    rp_log_error(RP_LOG_ALERT, c->log, 0,
                                  "sendfile(%V) returned busy again",
                                  &file->file->name);

                    c->busy_count = 0;
                    aio->preload_handler = NULL;

                    send = prev_send;
                    continue;
                }

            } else {
                c->busy_count = 0;
            }

            n = aio->preload_handler(file);

            if (n > 0) {
                send = prev_send + sent;
                continue;
            }

            return in;
        }

        if (flags == SF_NODISKIO) {
            c->busy_count = 0;
        }

#endif

        if (eagain) {

            /*
             * sendfile() may return EAGAIN, even if it has sent a whole file
             * part, it indicates that the successive sendfile() call would
             * return EAGAIN right away and would not send anything.
             * We use it as a hint.
             */

            wev->ready = 0;
            return in;
        }

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

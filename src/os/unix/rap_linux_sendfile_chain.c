
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


static ssize_t rap_linux_sendfile(rap_connection_t *c, rap_buf_t *file,
    size_t size);

#if (RAP_THREADS)
#include <rap_thread_pool.h>

#if !(RAP_HAVE_SENDFILE64)
#error sendfile64() is required!
#endif

static ssize_t rap_linux_sendfile_thread(rap_connection_t *c, rap_buf_t *file,
    size_t size);
static void rap_linux_sendfile_thread_handler(void *data, rap_log_t *log);
#endif


/*
 * On Linux up to 2.4.21 sendfile() (syscall #187) works with 32-bit
 * offsets only, and the including <sys/sendfile.h> breaks the compiling,
 * if off_t is 64 bit wide.  So we use own sendfile() definition, where offset
 * parameter is int32_t, and use sendfile() for the file parts below 2G only,
 * see src/os/unix/rap_linux_config.h
 *
 * Linux 2.4.21 has the new sendfile64() syscall #239.
 *
 * On Linux up to 2.6.16 sendfile() does not allow to pass the count parameter
 * more than 2G-1 bytes even on 64-bit platforms: it returns EINVAL,
 * so we limit it to 2G-1 bytes.
 */

#define RAP_SENDFILE_MAXSIZE  2147483647L


rap_chain_t *
rap_linux_sendfile_chain(rap_connection_t *c, rap_chain_t *in, off_t limit)
{
    int            tcp_nodelay;
    off_t          send, prev_send;
    size_t         file_size, sent;
    ssize_t        n;
    rap_err_t      err;
    rap_buf_t     *file;
    rap_event_t   *wev;
    rap_chain_t   *cl;
    rap_iovec_t    header;
    struct iovec   headers[RAP_IOVS_PREALLOCATE];

    wev = c->write;

    if (!wev->ready) {
        return in;
    }


    /* the maximum limit size is 2G-1 - the page size */

    if (limit == 0 || limit > (off_t) (RAP_SENDFILE_MAXSIZE - rap_pagesize)) {
        limit = RAP_SENDFILE_MAXSIZE - rap_pagesize;
    }


    send = 0;

    header.iovs = headers;
    header.nalloc = RAP_IOVS_PREALLOCATE;

    for ( ;; ) {
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        cl = rap_output_chain_to_iovec(&header, in, limit - send, c->log);

        if (cl == RAP_CHAIN_ERROR) {
            return RAP_CHAIN_ERROR;
        }

        send += header.size;

        /* set TCP_CORK if there is a header before a file */

        if (c->tcp_nopush == RAP_TCP_NOPUSH_UNSET
            && header.count != 0
            && cl
            && cl->buf->in_file)
        {
            /* the TCP_CORK and TCP_NODELAY are mutually exclusive */

            if (c->tcp_nodelay == RAP_TCP_NODELAY_SET) {

                tcp_nodelay = 0;

                if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                               (const void *) &tcp_nodelay, sizeof(int)) == -1)
                {
                    err = rap_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing with the TCP_NODELAY
                     * and without the TCP_CORK
                     */

                    if (err != RAP_EINTR) {
                        wev->error = 1;
                        rap_connection_error(c, err,
                                             "setsockopt(TCP_NODELAY) failed");
                        return RAP_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nodelay = RAP_TCP_NODELAY_UNSET;

                    rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                                   "no tcp_nodelay");
                }
            }

            if (c->tcp_nodelay == RAP_TCP_NODELAY_UNSET) {

                if (rap_tcp_nopush(c->fd) == -1) {
                    err = rap_socket_errno;

                    /*
                     * there is a tiny chance to be interrupted, however,
                     * we continue a processing without the TCP_CORK
                     */

                    if (err != RAP_EINTR) {
                        wev->error = 1;
                        rap_connection_error(c, err,
                                             rap_tcp_nopush_n " failed");
                        return RAP_CHAIN_ERROR;
                    }

                } else {
                    c->tcp_nopush = RAP_TCP_NOPUSH_SET;

                    rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, 0,
                                   "tcp_nopush");
                }
            }
        }

        /* get the file buf */

        if (header.count == 0 && cl && cl->buf->in_file && send < limit) {
            file = cl->buf;

            /* coalesce the neighbouring file bufs */

            file_size = (size_t) rap_chain_coalesce_file(&cl, limit - send);

            send += file_size;
#if 1
            if (file_size == 0) {
                rap_debug_point();
                return RAP_CHAIN_ERROR;
            }
#endif

            n = rap_linux_sendfile(c, file, file_size);

            if (n == RAP_ERROR) {
                return RAP_CHAIN_ERROR;
            }

            if (n == RAP_DONE) {
                /* thread task posted */
                return in;
            }

            sent = (n == RAP_AGAIN) ? 0 : n;

        } else {
            n = rap_writev(c, &header);

            if (n == RAP_ERROR) {
                return RAP_CHAIN_ERROR;
            }

            sent = (n == RAP_AGAIN) ? 0 : n;
        }

        c->sent += sent;

        in = rap_chain_update_sent(in, sent);

        if (n == RAP_AGAIN) {
            wev->ready = 0;
            return in;
        }

        if ((size_t) (send - prev_send) != sent) {

            /*
             * sendfile() on Linux 4.3+ might be interrupted at any time,
             * and provides no indication if it was interrupted or not,
             * so we have to retry till an explicit EAGAIN
             *
             * sendfile() in threads can also report less bytes written
             * than we are prepared to send now, since it was started in
             * some point in the past, so we again have to retry
             */

            send = prev_send + sent;
            continue;
        }

        if (send >= limit || in == NULL) {
            return in;
        }
    }
}


static ssize_t
rap_linux_sendfile(rap_connection_t *c, rap_buf_t *file, size_t size)
{
#if (RAP_HAVE_SENDFILE64)
    off_t      offset;
#else
    int32_t    offset;
#endif
    ssize_t    n;
    rap_err_t  err;

#if (RAP_THREADS)

    if (file->file->thread_handler) {
        return rap_linux_sendfile_thread(c, file, size);
    }

#endif

#if (RAP_HAVE_SENDFILE64)
    offset = file->file_pos;
#else
    offset = (int32_t) file->file_pos;
#endif

eintr:

    rap_log_debug2(RAP_LOG_DEBUG_EVENT, c->log, 0,
                   "sendfile: @%O %uz", file->file_pos, size);

    n = sendfile(c->fd, file->file->fd, &offset, size);

    if (n == -1) {
        err = rap_errno;

        switch (err) {
        case RAP_EAGAIN:
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "sendfile() is not ready");
            return RAP_AGAIN;

        case RAP_EINTR:
            rap_log_debug0(RAP_LOG_DEBUG_EVENT, c->log, err,
                           "sendfile() was interrupted");
            goto eintr;

        default:
            c->write->error = 1;
            rap_connection_error(c, err, "sendfile() failed");
            return RAP_ERROR;
        }
    }

    if (n == 0) {
        /*
         * if sendfile returns zero, then someone has truncated the file,
         * so the offset became beyond the end of the file
         */

        rap_log_error(RAP_LOG_ALERT, c->log, 0,
                      "sendfile() reported that \"%s\" was truncated at %O",
                      file->file->name.data, file->file_pos);

        return RAP_ERROR;
    }

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, c->log, 0, "sendfile: %z of %uz @%O",
                   n, size, file->file_pos);

    return n;
}


#if (RAP_THREADS)

typedef struct {
    rap_buf_t     *file;
    rap_socket_t   socket;
    size_t         size;

    size_t         sent;
    rap_err_t      err;
} rap_linux_sendfile_ctx_t;


static ssize_t
rap_linux_sendfile_thread(rap_connection_t *c, rap_buf_t *file, size_t size)
{
    rap_event_t               *wev;
    rap_thread_task_t         *task;
    rap_linux_sendfile_ctx_t  *ctx;

    rap_log_debug3(RAP_LOG_DEBUG_CORE, c->log, 0,
                   "linux sendfile thread: %d, %uz, %O",
                   file->file->fd, size, file->file_pos);

    task = c->sendfile_task;

    if (task == NULL) {
        task = rap_thread_task_alloc(c->pool, sizeof(rap_linux_sendfile_ctx_t));
        if (task == NULL) {
            return RAP_ERROR;
        }

        task->handler = rap_linux_sendfile_thread_handler;

        c->sendfile_task = task;
    }

    ctx = task->ctx;
    wev = c->write;

    if (task->event.complete) {
        task->event.complete = 0;

        if (ctx->err == RAP_EAGAIN) {
            /*
             * if wev->complete is set, this means that a write event
             * happened while we were waiting for the thread task, so
             * we have to retry sending even on EAGAIN
             */

            if (wev->complete) {
                return 0;
            }

            return RAP_AGAIN;
        }

        if (ctx->err) {
            wev->error = 1;
            rap_connection_error(c, ctx->err, "sendfile() failed");
            return RAP_ERROR;
        }

        if (ctx->sent == 0) {
            /*
             * if sendfile returns zero, then someone has truncated the file,
             * so the offset became beyond the end of the file
             */

            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "sendfile() reported that \"%s\" was truncated at %O",
                          file->file->name.data, file->file_pos);

            return RAP_ERROR;
        }

        return ctx->sent;
    }

    if (task->event.active && ctx->file == file) {
        /*
         * tolerate duplicate calls; they can happen due to subrequests
         * or multiple calls of the next body filter from a filter
         */

        return RAP_DONE;
    }

    ctx->file = file;
    ctx->socket = c->fd;
    ctx->size = size;

    wev->complete = 0;

    if (file->file->thread_handler(task, file->file) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_DONE;
}


static void
rap_linux_sendfile_thread_handler(void *data, rap_log_t *log)
{
    rap_linux_sendfile_ctx_t *ctx = data;

    off_t       offset;
    ssize_t     n;
    rap_buf_t  *file;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, log, 0, "linux sendfile thread handler");

    file = ctx->file;
    offset = file->file_pos;

again:

    n = sendfile(ctx->socket, file->file->fd, &offset, ctx->size);

    if (n == -1) {
        ctx->err = rap_errno;

    } else {
        ctx->sent = n;
        ctx->err = 0;
    }

#if 0
    rap_time_update();
#endif

    rap_log_debug4(RAP_LOG_DEBUG_EVENT, log, 0,
                   "sendfile: %z (err: %d) of %uz @%O",
                   n, ctx->err, ctx->size, file->file_pos);

    if (ctx->err == RAP_EINTR) {
        goto again;
    }
}

#endif /* RAP_THREADS */

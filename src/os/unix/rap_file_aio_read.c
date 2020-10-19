
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


/*
 * FreeBSD file AIO features and quirks:
 *
 *    if an asked data are already in VM cache, then aio_error() returns 0,
 *    and the data are already copied in buffer;
 *
 *    aio_read() preread in VM cache as minimum 16K (probably BKVASIZE);
 *    the first AIO preload may be up to 128K;
 *
 *    aio_read/aio_error() may return EINPROGRESS for just written data;
 *
 *    kqueue EVFILT_AIO filter is level triggered only: an event repeats
 *    until aio_return() will be called;
 *
 *    aio_cancel() cannot cancel file AIO: it returns AIO_NOTCANCELED always.
 */


extern int  rap_kqueue;


static ssize_t rap_file_aio_result(rap_file_t *file, rap_event_aio_t *aio,
    rap_event_t *ev);
static void rap_file_aio_event_handler(rap_event_t *ev);


rap_int_t
rap_file_aio_init(rap_file_t *file, rap_pool_t *pool)
{
    rap_event_aio_t  *aio;

    aio = rap_pcalloc(pool, sizeof(rap_event_aio_t));
    if (aio == NULL) {
        return RAP_ERROR;
    }

    aio->file = file;
    aio->fd = file->fd;
    aio->event.data = aio;
    aio->event.ready = 1;
    aio->event.log = file->log;

    file->aio = aio;

    return RAP_OK;
}


ssize_t
rap_file_aio_read(rap_file_t *file, u_char *buf, size_t size, off_t offset,
    rap_pool_t *pool)
{
    int               n;
    rap_event_t      *ev;
    rap_event_aio_t  *aio;

    if (!rap_file_aio) {
        return rap_read_file(file, buf, size, offset);
    }

    if (file->aio == NULL && rap_file_aio_init(file, pool) != RAP_OK) {
        return RAP_ERROR;
    }

    aio = file->aio;
    ev = &aio->event;

    if (!ev->ready) {
        rap_log_error(RAP_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return RAP_AGAIN;
    }

    rap_log_debug4(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->complete = 0;
        rap_set_errno(aio->err);

        if (aio->err == 0) {
            return aio->nbytes;
        }

        rap_log_error(RAP_LOG_CRIT, file->log, rap_errno,
                      "aio read \"%s\" failed", file->name.data);

        return RAP_ERROR;
    }

    rap_memzero(&aio->aiocb, sizeof(struct aiocb));

    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_buf = buf;
    aio->aiocb.aio_nbytes = size;
#if (RAP_HAVE_KQUEUE)
    aio->aiocb.aio_sigevent.sigev_notify_kqueue = rap_kqueue;
    aio->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    aio->aiocb.aio_sigevent.sigev_value.sival_ptr = ev;
#endif
    ev->handler = rap_file_aio_event_handler;

    n = aio_read(&aio->aiocb);

    if (n == -1) {
        n = rap_errno;

        if (n == RAP_EAGAIN) {
            return rap_read_file(file, buf, size, offset);
        }

        rap_log_error(RAP_LOG_CRIT, file->log, n,
                      "aio_read(\"%V\") failed", &file->name);

        if (n == RAP_ENOSYS) {
            rap_file_aio = 0;
            return rap_read_file(file, buf, size, offset);
        }

        return RAP_ERROR;
    }

    rap_log_debug2(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "aio_read: fd:%d %d", file->fd, n);

    ev->active = 1;
    ev->ready = 0;
    ev->complete = 0;

    return rap_file_aio_result(aio->file, aio, ev);
}


static ssize_t
rap_file_aio_result(rap_file_t *file, rap_event_aio_t *aio, rap_event_t *ev)
{
    int        n;
    rap_err_t  err;

    n = aio_error(&aio->aiocb);

    rap_log_debug2(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "aio_error: fd:%d %d", file->fd, n);

    if (n == -1) {
        err = rap_errno;
        aio->err = err;

        rap_log_error(RAP_LOG_ALERT, file->log, err,
                      "aio_error(\"%V\") failed", &file->name);
        return RAP_ERROR;
    }

    if (n == RAP_EINPROGRESS) {
        if (ev->ready) {
            ev->ready = 0;
            rap_log_error(RAP_LOG_ALERT, file->log, n,
                          "aio_read(\"%V\") still in progress",
                          &file->name);
        }

        return RAP_AGAIN;
    }

    n = aio_return(&aio->aiocb);

    if (n == -1) {
        err = rap_errno;
        aio->err = err;
        ev->ready = 1;

        rap_log_error(RAP_LOG_CRIT, file->log, err,
                      "aio_return(\"%V\") failed", &file->name);
        return RAP_ERROR;
    }

    aio->err = 0;
    aio->nbytes = n;
    ev->ready = 1;
    ev->active = 0;

    rap_log_debug2(RAP_LOG_DEBUG_CORE, file->log, 0,
                   "aio_return: fd:%d %d", file->fd, n);

    return n;
}


static void
rap_file_aio_event_handler(rap_event_t *ev)
{
    rap_event_aio_t  *aio;

    aio = ev->data;

    rap_log_debug2(RAP_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    if (rap_file_aio_result(aio->file, aio, ev) != RAP_AGAIN) {
        aio->handler(ev);
    }
}

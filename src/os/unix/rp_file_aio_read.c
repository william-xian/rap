
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


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


extern int  rp_kqueue;


static ssize_t rp_file_aio_result(rp_file_t *file, rp_event_aio_t *aio,
    rp_event_t *ev);
static void rp_file_aio_event_handler(rp_event_t *ev);


rp_int_t
rp_file_aio_init(rp_file_t *file, rp_pool_t *pool)
{
    rp_event_aio_t  *aio;

    aio = rp_pcalloc(pool, sizeof(rp_event_aio_t));
    if (aio == NULL) {
        return RP_ERROR;
    }

    aio->file = file;
    aio->fd = file->fd;
    aio->event.data = aio;
    aio->event.ready = 1;
    aio->event.log = file->log;

    file->aio = aio;

    return RP_OK;
}


ssize_t
rp_file_aio_read(rp_file_t *file, u_char *buf, size_t size, off_t offset,
    rp_pool_t *pool)
{
    int               n;
    rp_event_t      *ev;
    rp_event_aio_t  *aio;

    if (!rp_file_aio) {
        return rp_read_file(file, buf, size, offset);
    }

    if (file->aio == NULL && rp_file_aio_init(file, pool) != RP_OK) {
        return RP_ERROR;
    }

    aio = file->aio;
    ev = &aio->event;

    if (!ev->ready) {
        rp_log_error(RP_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return RP_AGAIN;
    }

    rp_log_debug4(RP_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%uz %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->complete = 0;
        rp_set_errno(aio->err);

        if (aio->err == 0) {
            return aio->nbytes;
        }

        rp_log_error(RP_LOG_CRIT, file->log, rp_errno,
                      "aio read \"%s\" failed", file->name.data);

        return RP_ERROR;
    }

    rp_memzero(&aio->aiocb, sizeof(struct aiocb));

    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_buf = buf;
    aio->aiocb.aio_nbytes = size;
#if (RP_HAVE_KQUEUE)
    aio->aiocb.aio_sigevent.sigev_notify_kqueue = rp_kqueue;
    aio->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    aio->aiocb.aio_sigevent.sigev_value.sival_ptr = ev;
#endif
    ev->handler = rp_file_aio_event_handler;

    n = aio_read(&aio->aiocb);

    if (n == -1) {
        n = rp_errno;

        if (n == RP_EAGAIN) {
            return rp_read_file(file, buf, size, offset);
        }

        rp_log_error(RP_LOG_CRIT, file->log, n,
                      "aio_read(\"%V\") failed", &file->name);

        if (n == RP_ENOSYS) {
            rp_file_aio = 0;
            return rp_read_file(file, buf, size, offset);
        }

        return RP_ERROR;
    }

    rp_log_debug2(RP_LOG_DEBUG_CORE, file->log, 0,
                   "aio_read: fd:%d %d", file->fd, n);

    ev->active = 1;
    ev->ready = 0;
    ev->complete = 0;

    return rp_file_aio_result(aio->file, aio, ev);
}


static ssize_t
rp_file_aio_result(rp_file_t *file, rp_event_aio_t *aio, rp_event_t *ev)
{
    int        n;
    rp_err_t  err;

    n = aio_error(&aio->aiocb);

    rp_log_debug2(RP_LOG_DEBUG_CORE, file->log, 0,
                   "aio_error: fd:%d %d", file->fd, n);

    if (n == -1) {
        err = rp_errno;
        aio->err = err;

        rp_log_error(RP_LOG_ALERT, file->log, err,
                      "aio_error(\"%V\") failed", &file->name);
        return RP_ERROR;
    }

    if (n == RP_EINPROGRESS) {
        if (ev->ready) {
            ev->ready = 0;
            rp_log_error(RP_LOG_ALERT, file->log, n,
                          "aio_read(\"%V\") still in progress",
                          &file->name);
        }

        return RP_AGAIN;
    }

    n = aio_return(&aio->aiocb);

    if (n == -1) {
        err = rp_errno;
        aio->err = err;
        ev->ready = 1;

        rp_log_error(RP_LOG_CRIT, file->log, err,
                      "aio_return(\"%V\") failed", &file->name);
        return RP_ERROR;
    }

    aio->err = 0;
    aio->nbytes = n;
    ev->ready = 1;
    ev->active = 0;

    rp_log_debug2(RP_LOG_DEBUG_CORE, file->log, 0,
                   "aio_return: fd:%d %d", file->fd, n);

    return n;
}


static void
rp_file_aio_event_handler(rp_event_t *ev)
{
    rp_event_aio_t  *aio;

    aio = ev->data;

    rp_log_debug2(RP_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    if (rp_file_aio_result(aio->file, aio, ev) != RP_AGAIN) {
        aio->handler(ev);
    }
}

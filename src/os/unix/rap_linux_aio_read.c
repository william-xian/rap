
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


extern int            rap_eventfd;
extern aio_context_t  rap_aio_ctx;


static void rap_file_aio_event_handler(rap_event_t *ev);


static int
io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}


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
    rap_err_t         err;
    struct iocb      *piocb[1];
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
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            rap_set_errno(0);
            return aio->res;
        }

        rap_set_errno(-aio->res);

        rap_log_error(RAP_LOG_CRIT, file->log, rap_errno,
                      "aio read \"%s\" failed", file->name.data);

        return RAP_ERROR;
    }

    rap_memzero(&aio->aiocb, sizeof(struct iocb));

    aio->aiocb.aio_data = (uint64_t) (uintptr_t) ev;
    aio->aiocb.aio_lio_opcode = IOCB_CMD_PREAD;
    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_buf = (uint64_t) (uintptr_t) buf;
    aio->aiocb.aio_nbytes = size;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_flags = IOCB_FLAG_RESFD;
    aio->aiocb.aio_resfd = rap_eventfd;

    ev->handler = rap_file_aio_event_handler;

    piocb[0] = &aio->aiocb;

    if (io_submit(rap_aio_ctx, 1, piocb) == 1) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return RAP_AGAIN;
    }

    err = rap_errno;

    if (err == RAP_EAGAIN) {
        return rap_read_file(file, buf, size, offset);
    }

    rap_log_error(RAP_LOG_CRIT, file->log, err,
                  "io_submit(\"%V\") failed", &file->name);

    if (err == RAP_ENOSYS) {
        rap_file_aio = 0;
        return rap_read_file(file, buf, size, offset);
    }

    return RAP_ERROR;
}


static void
rap_file_aio_event_handler(rap_event_t *ev)
{
    rap_event_aio_t  *aio;

    aio = ev->data;

    rap_log_debug2(RAP_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    aio->handler(ev);
}

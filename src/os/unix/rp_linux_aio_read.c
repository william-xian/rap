
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


extern int            rp_eventfd;
extern aio_context_t  rp_aio_ctx;


static void rp_file_aio_event_handler(rp_event_t *ev);


static int
io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}


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
    rp_err_t         err;
    struct iocb      *piocb[1];
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
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            rp_set_errno(0);
            return aio->res;
        }

        rp_set_errno(-aio->res);

        rp_log_error(RP_LOG_CRIT, file->log, rp_errno,
                      "aio read \"%s\" failed", file->name.data);

        return RP_ERROR;
    }

    rp_memzero(&aio->aiocb, sizeof(struct iocb));

    aio->aiocb.aio_data = (uint64_t) (uintptr_t) ev;
    aio->aiocb.aio_lio_opcode = IOCB_CMD_PREAD;
    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_buf = (uint64_t) (uintptr_t) buf;
    aio->aiocb.aio_nbytes = size;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_flags = IOCB_FLAG_RESFD;
    aio->aiocb.aio_resfd = rp_eventfd;

    ev->handler = rp_file_aio_event_handler;

    piocb[0] = &aio->aiocb;

    if (io_submit(rp_aio_ctx, 1, piocb) == 1) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return RP_AGAIN;
    }

    err = rp_errno;

    if (err == RP_EAGAIN) {
        return rp_read_file(file, buf, size, offset);
    }

    rp_log_error(RP_LOG_CRIT, file->log, err,
                  "io_submit(\"%V\") failed", &file->name);

    if (err == RP_ENOSYS) {
        rp_file_aio = 0;
        return rp_read_file(file, buf, size, offset);
    }

    return RP_ERROR;
}


static void
rp_file_aio_event_handler(rp_event_t *ev)
{
    rp_event_aio_t  *aio;

    aio = ev->data;

    rp_log_debug2(RP_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    aio->handler(ev);
}

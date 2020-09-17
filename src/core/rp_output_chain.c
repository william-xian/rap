
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#if 0
#define RP_SENDFILE_LIMIT  4096
#endif

/*
 * When DIRECTIO is enabled FreeBSD, Solaris, and MacOSX read directly
 * to an application memory from a device if parameters are aligned
 * to device sector boundary (512 bytes).  They fallback to usual read
 * operation if the parameters are not aligned.
 * Linux allows DIRECTIO only if the parameters are aligned to a filesystem
 * sector boundary, otherwise it returns EINVAL.  The sector size is
 * usually 512 bytes, however, on XFS it may be 4096 bytes.
 */

#define RP_NONE            1


static rp_inline rp_int_t
    rp_output_chain_as_is(rp_output_chain_ctx_t *ctx, rp_buf_t *buf);
#if (RP_HAVE_AIO_SENDFILE)
static rp_int_t rp_output_chain_aio_setup(rp_output_chain_ctx_t *ctx,
    rp_file_t *file);
#endif
static rp_int_t rp_output_chain_add_copy(rp_pool_t *pool,
    rp_chain_t **chain, rp_chain_t *in);
static rp_int_t rp_output_chain_align_file_buf(rp_output_chain_ctx_t *ctx,
    off_t bsize);
static rp_int_t rp_output_chain_get_buf(rp_output_chain_ctx_t *ctx,
    off_t bsize);
static rp_int_t rp_output_chain_copy_buf(rp_output_chain_ctx_t *ctx);


rp_int_t
rp_output_chain(rp_output_chain_ctx_t *ctx, rp_chain_t *in)
{
    off_t         bsize;
    rp_int_t     rc, last;
    rp_chain_t  *cl, *out, **last_out;

    if (ctx->in == NULL && ctx->busy == NULL
#if (RP_HAVE_FILE_AIO || RP_THREADS)
        && !ctx->aio
#endif
       )
    {
        /*
         * the short path for the case when the ctx->in and ctx->busy chains
         * are empty, the incoming chain is empty too or has the single buf
         * that does not require the copy
         */

        if (in == NULL) {
            return ctx->output_filter(ctx->filter_ctx, in);
        }

        if (in->next == NULL
#if (RP_SENDFILE_LIMIT)
            && !(in->buf->in_file && in->buf->file_last > RP_SENDFILE_LIMIT)
#endif
            && rp_output_chain_as_is(ctx, in->buf))
        {
            return ctx->output_filter(ctx->filter_ctx, in);
        }
    }

    /* add the incoming buf to the chain ctx->in */

    if (in) {
        if (rp_output_chain_add_copy(ctx->pool, &ctx->in, in) == RP_ERROR) {
            return RP_ERROR;
        }
    }

    out = NULL;
    last_out = &out;
    last = RP_NONE;

    for ( ;; ) {

#if (RP_HAVE_FILE_AIO || RP_THREADS)
        if (ctx->aio) {
            return RP_AGAIN;
        }
#endif

        while (ctx->in) {

            /*
             * cycle while there are the ctx->in bufs
             * and there are the free output bufs to copy in
             */

            bsize = rp_buf_size(ctx->in->buf);

            if (bsize == 0 && !rp_buf_special(ctx->in->buf)) {

                rp_log_error(RP_LOG_ALERT, ctx->pool->log, 0,
                              "zero size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                rp_debug_point();

                ctx->in = ctx->in->next;

                continue;
            }

            if (bsize < 0) {

                rp_log_error(RP_LOG_ALERT, ctx->pool->log, 0,
                              "negative size buf in output "
                              "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                              ctx->in->buf->temporary,
                              ctx->in->buf->recycled,
                              ctx->in->buf->in_file,
                              ctx->in->buf->start,
                              ctx->in->buf->pos,
                              ctx->in->buf->last,
                              ctx->in->buf->file,
                              ctx->in->buf->file_pos,
                              ctx->in->buf->file_last);

                rp_debug_point();

                return RP_ERROR;
            }

            if (rp_output_chain_as_is(ctx, ctx->in->buf)) {

                /* move the chain link to the output chain */

                cl = ctx->in;
                ctx->in = cl->next;

                *last_out = cl;
                last_out = &cl->next;
                cl->next = NULL;

                continue;
            }

            if (ctx->buf == NULL) {

                rc = rp_output_chain_align_file_buf(ctx, bsize);

                if (rc == RP_ERROR) {
                    return RP_ERROR;
                }

                if (rc != RP_OK) {

                    if (ctx->free) {

                        /* get the free buf */

                        cl = ctx->free;
                        ctx->buf = cl->buf;
                        ctx->free = cl->next;

                        rp_free_chain(ctx->pool, cl);

                    } else if (out || ctx->allocated == ctx->bufs.num) {

                        break;

                    } else if (rp_output_chain_get_buf(ctx, bsize) != RP_OK) {
                        return RP_ERROR;
                    }
                }
            }

            rc = rp_output_chain_copy_buf(ctx);

            if (rc == RP_ERROR) {
                return rc;
            }

            if (rc == RP_AGAIN) {
                if (out) {
                    break;
                }

                return rc;
            }

            /* delete the completed buf from the ctx->in chain */

            if (rp_buf_size(ctx->in->buf) == 0) {
                ctx->in = ctx->in->next;
            }

            cl = rp_alloc_chain_link(ctx->pool);
            if (cl == NULL) {
                return RP_ERROR;
            }

            cl->buf = ctx->buf;
            cl->next = NULL;
            *last_out = cl;
            last_out = &cl->next;
            ctx->buf = NULL;
        }

        if (out == NULL && last != RP_NONE) {

            if (ctx->in) {
                return RP_AGAIN;
            }

            return last;
        }

        last = ctx->output_filter(ctx->filter_ctx, out);

        if (last == RP_ERROR || last == RP_DONE) {
            return last;
        }

        rp_chain_update_chains(ctx->pool, &ctx->free, &ctx->busy, &out,
                                ctx->tag);
        last_out = &out;
    }
}


static rp_inline rp_int_t
rp_output_chain_as_is(rp_output_chain_ctx_t *ctx, rp_buf_t *buf)
{
    rp_uint_t  sendfile;

    if (rp_buf_special(buf)) {
        return 1;
    }

#if (RP_THREADS)
    if (buf->in_file) {
        buf->file->thread_handler = ctx->thread_handler;
        buf->file->thread_ctx = ctx->filter_ctx;
    }
#endif

    if (buf->in_file && buf->file->directio) {
        return 0;
    }

    sendfile = ctx->sendfile;

#if (RP_SENDFILE_LIMIT)

    if (buf->in_file && buf->file_pos >= RP_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

    if (!sendfile) {

        if (!rp_buf_in_memory(buf)) {
            return 0;
        }

        buf->in_file = 0;
    }

#if (RP_HAVE_AIO_SENDFILE)
    if (ctx->aio_preload && buf->in_file) {
        (void) rp_output_chain_aio_setup(ctx, buf->file);
    }
#endif

    if (ctx->need_in_memory && !rp_buf_in_memory(buf)) {
        return 0;
    }

    if (ctx->need_in_temp && (buf->memory || buf->mmap)) {
        return 0;
    }

    return 1;
}


#if (RP_HAVE_AIO_SENDFILE)

static rp_int_t
rp_output_chain_aio_setup(rp_output_chain_ctx_t *ctx, rp_file_t *file)
{
    rp_event_aio_t  *aio;

    if (file->aio == NULL && rp_file_aio_init(file, ctx->pool) != RP_OK) {
        return RP_ERROR;
    }

    aio = file->aio;

    aio->data = ctx->filter_ctx;
    aio->preload_handler = ctx->aio_preload;

    return RP_OK;
}

#endif


static rp_int_t
rp_output_chain_add_copy(rp_pool_t *pool, rp_chain_t **chain,
    rp_chain_t *in)
{
    rp_chain_t  *cl, **ll;
#if (RP_SENDFILE_LIMIT)
    rp_buf_t    *b, *buf;
#endif

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {

        cl = rp_alloc_chain_link(pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

#if (RP_SENDFILE_LIMIT)

        buf = in->buf;

        if (buf->in_file
            && buf->file_pos < RP_SENDFILE_LIMIT
            && buf->file_last > RP_SENDFILE_LIMIT)
        {
            /* split a file buf on two bufs by the sendfile limit */

            b = rp_calloc_buf(pool);
            if (b == NULL) {
                return RP_ERROR;
            }

            rp_memcpy(b, buf, sizeof(rp_buf_t));

            if (rp_buf_in_memory(buf)) {
                buf->pos += (ssize_t) (RP_SENDFILE_LIMIT - buf->file_pos);
                b->last = buf->pos;
            }

            buf->file_pos = RP_SENDFILE_LIMIT;
            b->file_last = RP_SENDFILE_LIMIT;

            cl->buf = b;

        } else {
            cl->buf = buf;
            in = in->next;
        }

#else
        cl->buf = in->buf;
        in = in->next;

#endif

        cl->next = NULL;
        *ll = cl;
        ll = &cl->next;
    }

    return RP_OK;
}


static rp_int_t
rp_output_chain_align_file_buf(rp_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t      size;
    rp_buf_t  *in;

    in = ctx->in->buf;

    if (in->file == NULL || !in->file->directio) {
        return RP_DECLINED;
    }

    ctx->directio = 1;

    size = (size_t) (in->file_pos - (in->file_pos & ~(ctx->alignment - 1)));

    if (size == 0) {

        if (bsize >= (off_t) ctx->bufs.size) {
            return RP_DECLINED;
        }

        size = (size_t) bsize;

    } else {
        size = (size_t) ctx->alignment - size;

        if ((off_t) size > bsize) {
            size = (size_t) bsize;
        }
    }

    ctx->buf = rp_create_temp_buf(ctx->pool, size);
    if (ctx->buf == NULL) {
        return RP_ERROR;
    }

    /*
     * we do not set ctx->buf->tag, because we do not want
     * to reuse the buf via ctx->free list
     */

#if (RP_HAVE_ALIGNED_DIRECTIO)
    ctx->unaligned = 1;
#endif

    return RP_OK;
}


static rp_int_t
rp_output_chain_get_buf(rp_output_chain_ctx_t *ctx, off_t bsize)
{
    size_t       size;
    rp_buf_t   *b, *in;
    rp_uint_t   recycled;

    in = ctx->in->buf;
    size = ctx->bufs.size;
    recycled = 1;

    if (in->last_in_chain) {

        if (bsize < (off_t) size) {

            /*
             * allocate a small temp buf for a small last buf
             * or its small last part
             */

            size = (size_t) bsize;
            recycled = 0;

        } else if (!ctx->directio
                   && ctx->bufs.num == 1
                   && (bsize < (off_t) (size + size / 4)))
        {
            /*
             * allocate a temp buf that equals to a last buf,
             * if there is no directio, the last buf size is lesser
             * than 1.25 of bufs.size and the temp buf is single
             */

            size = (size_t) bsize;
            recycled = 0;
        }
    }

    b = rp_calloc_buf(ctx->pool);
    if (b == NULL) {
        return RP_ERROR;
    }

    if (ctx->directio) {

        /*
         * allocate block aligned to a disk sector size to enable
         * userland buffer direct usage conjunctly with directio
         */

        b->start = rp_pmemalign(ctx->pool, size, (size_t) ctx->alignment);
        if (b->start == NULL) {
            return RP_ERROR;
        }

    } else {
        b->start = rp_palloc(ctx->pool, size);
        if (b->start == NULL) {
            return RP_ERROR;
        }
    }

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;
    b->tag = ctx->tag;
    b->recycled = recycled;

    ctx->buf = b;
    ctx->allocated++;

    return RP_OK;
}


static rp_int_t
rp_output_chain_copy_buf(rp_output_chain_ctx_t *ctx)
{
    off_t        size;
    ssize_t      n;
    rp_buf_t   *src, *dst;
    rp_uint_t   sendfile;

    src = ctx->in->buf;
    dst = ctx->buf;

    size = rp_buf_size(src);
    size = rp_min(size, dst->end - dst->pos);

    sendfile = ctx->sendfile && !ctx->directio;

#if (RP_SENDFILE_LIMIT)

    if (src->in_file && src->file_pos >= RP_SENDFILE_LIMIT) {
        sendfile = 0;
    }

#endif

    if (rp_buf_in_memory(src)) {
        rp_memcpy(dst->pos, src->pos, (size_t) size);
        src->pos += (size_t) size;
        dst->last += (size_t) size;

        if (src->in_file) {

            if (sendfile) {
                dst->in_file = 1;
                dst->file = src->file;
                dst->file_pos = src->file_pos;
                dst->file_last = src->file_pos + size;

            } else {
                dst->in_file = 0;
            }

            src->file_pos += size;

        } else {
            dst->in_file = 0;
        }

        if (src->pos == src->last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }

    } else {

#if (RP_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            if (rp_directio_off(src->file->fd) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_ALERT, ctx->pool->log, rp_errno,
                              rp_directio_off_n " \"%s\" failed",
                              src->file->name.data);
            }
        }

#endif

#if (RP_HAVE_FILE_AIO)
        if (ctx->aio_handler) {
            n = rp_file_aio_read(src->file, dst->pos, (size_t) size,
                                  src->file_pos, ctx->pool);
            if (n == RP_AGAIN) {
                ctx->aio_handler(ctx, src->file);
                return RP_AGAIN;
            }

        } else
#endif
#if (RP_THREADS)
        if (ctx->thread_handler) {
            src->file->thread_task = ctx->thread_task;
            src->file->thread_handler = ctx->thread_handler;
            src->file->thread_ctx = ctx->filter_ctx;

            n = rp_thread_read(src->file, dst->pos, (size_t) size,
                                src->file_pos, ctx->pool);
            if (n == RP_AGAIN) {
                ctx->thread_task = src->file->thread_task;
                return RP_AGAIN;
            }

        } else
#endif
        {
            n = rp_read_file(src->file, dst->pos, (size_t) size,
                              src->file_pos);
        }

#if (RP_HAVE_ALIGNED_DIRECTIO)

        if (ctx->unaligned) {
            rp_err_t  err;

            err = rp_errno;

            if (rp_directio_on(src->file->fd) == RP_FILE_ERROR) {
                rp_log_error(RP_LOG_ALERT, ctx->pool->log, rp_errno,
                              rp_directio_on_n " \"%s\" failed",
                              src->file->name.data);
            }

            rp_set_errno(err);

            ctx->unaligned = 0;
        }

#endif

        if (n == RP_ERROR) {
            return (rp_int_t) n;
        }

        if (n != size) {
            rp_log_error(RP_LOG_ALERT, ctx->pool->log, 0,
                          rp_read_file_n " read only %z of %O from \"%s\"",
                          n, size, src->file->name.data);
            return RP_ERROR;
        }

        dst->last += n;

        if (sendfile) {
            dst->in_file = 1;
            dst->file = src->file;
            dst->file_pos = src->file_pos;
            dst->file_last = src->file_pos + n;

        } else {
            dst->in_file = 0;
        }

        src->file_pos += n;

        if (src->file_pos == src->file_last) {
            dst->flush = src->flush;
            dst->last_buf = src->last_buf;
            dst->last_in_chain = src->last_in_chain;
        }
    }

    return RP_OK;
}


rp_int_t
rp_chain_writer(void *data, rp_chain_t *in)
{
    rp_chain_writer_ctx_t *ctx = data;

    off_t              size;
    rp_chain_t       *cl, *ln, *chain;
    rp_connection_t  *c;

    c = ctx->connection;

    for (size = 0; in; in = in->next) {

        if (rp_buf_size(in->buf) == 0 && !rp_buf_special(in->buf)) {

            rp_log_error(RP_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
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

            continue;
        }

        if (rp_buf_size(in->buf) < 0) {

            rp_log_error(RP_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
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

            return RP_ERROR;
        }

        size += rp_buf_size(in->buf);

        rp_log_debug2(RP_LOG_DEBUG_CORE, c->log, 0,
                       "chain writer buf fl:%d s:%uO",
                       in->buf->flush, rp_buf_size(in->buf));

        cl = rp_alloc_chain_link(ctx->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        cl->buf = in->buf;
        cl->next = NULL;
        *ctx->last = cl;
        ctx->last = &cl->next;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer in: %p", ctx->out);

    for (cl = ctx->out; cl; cl = cl->next) {

        if (rp_buf_size(cl->buf) == 0 && !rp_buf_special(cl->buf)) {

            rp_log_error(RP_LOG_ALERT, ctx->pool->log, 0,
                          "zero size buf in chain writer "
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

            continue;
        }

        if (rp_buf_size(cl->buf) < 0) {

            rp_log_error(RP_LOG_ALERT, ctx->pool->log, 0,
                          "negative size buf in chain writer "
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

            return RP_ERROR;
        }

        size += rp_buf_size(cl->buf);
    }

    if (size == 0 && !c->buffered) {
        return RP_OK;
    }

    chain = c->send_chain(c, ctx->out, ctx->limit);

    rp_log_debug1(RP_LOG_DEBUG_CORE, c->log, 0,
                   "chain writer out: %p", chain);

    if (chain == RP_CHAIN_ERROR) {
        return RP_ERROR;
    }

    for (cl = ctx->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        rp_free_chain(ctx->pool, ln);
    }

    ctx->out = chain;

    if (ctx->out == NULL) {
        ctx->last = &ctx->out;

        if (!c->buffered) {
            return RP_OK;
        }
    }

    return RP_AGAIN;
}

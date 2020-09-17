
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    rp_chain_t  *from_upstream;
    rp_chain_t  *from_downstream;
} rp_stream_write_filter_ctx_t;


static rp_int_t rp_stream_write_filter(rp_stream_session_t *s,
    rp_chain_t *in, rp_uint_t from_upstream);
static rp_int_t rp_stream_write_filter_init(rp_conf_t *cf);


static rp_stream_module_t  rp_stream_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_stream_write_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rp_module_t  rp_stream_write_filter_module = {
    RP_MODULE_V1,
    &rp_stream_write_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
    RP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_stream_write_filter(rp_stream_session_t *s, rp_chain_t *in,
    rp_uint_t from_upstream)
{
    off_t                           size;
    rp_uint_t                      last, flush, sync;
    rp_chain_t                    *cl, *ln, **ll, **out, *chain;
    rp_connection_t               *c;
    rp_stream_write_filter_ctx_t  *ctx;

    ctx = rp_stream_get_module_ctx(s, rp_stream_write_filter_module);

    if (ctx == NULL) {
        ctx = rp_pcalloc(s->connection->pool,
                          sizeof(rp_stream_write_filter_ctx_t));
        if (ctx == NULL) {
            return RP_ERROR;
        }

        rp_stream_set_ctx(s, ctx, rp_stream_write_filter_module);
    }

    if (from_upstream) {
        c = s->connection;
        out = &ctx->from_upstream;

    } else {
        c = s->upstream->peer.connection;
        out = &ctx->from_downstream;
    }

    if (c->error) {
        return RP_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = *out; cl; cl = cl->next) {
        ll = &cl->next;

        rp_log_debug7(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rp_buf_size(cl->buf) == 0 && !rp_buf_special(cl->buf)) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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

        if (rp_buf_size(cl->buf) < 0) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        cl = rp_alloc_chain_link(c->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        rp_log_debug7(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rp_buf_size(cl->buf) == 0 && !rp_buf_special(cl->buf)) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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

        if (rp_buf_size(cl->buf) < 0) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    rp_log_debug3(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter: l:%ui f:%ui s:%O", last, flush, size);

    if (size == 0
        && !(c->buffered & RP_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush || sync) {
            for (cl = *out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                rp_free_chain(c->pool, ln);
            }

            *out = NULL;
            c->buffered &= ~RP_STREAM_WRITE_BUFFERED;

            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, c->log, 0,
                      "the stream output chain is empty");

        rp_debug_point();

        return RP_ERROR;
    }

    chain = c->send_chain(c, *out, 0);

    rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter %p", chain);

    if (chain == RP_CHAIN_ERROR) {
        c->error = 1;
        return RP_ERROR;
    }

    for (cl = *out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        rp_free_chain(c->pool, ln);
    }

    *out = chain;

    if (chain) {
        if (c->shared) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
                          "shared connection is busy");
            return RP_ERROR;
        }

        c->buffered |= RP_STREAM_WRITE_BUFFERED;
        return RP_AGAIN;
    }

    c->buffered &= ~RP_STREAM_WRITE_BUFFERED;

    if (c->buffered & RP_LOWLEVEL_BUFFERED) {
        return RP_AGAIN;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_write_filter_init(rp_conf_t *cf)
{
    rp_stream_top_filter = rp_stream_write_filter;

    return RP_OK;
}

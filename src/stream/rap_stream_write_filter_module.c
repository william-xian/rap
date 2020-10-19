
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    rap_chain_t  *from_upstream;
    rap_chain_t  *from_downstream;
} rap_stream_write_filter_ctx_t;


static rap_int_t rap_stream_write_filter(rap_stream_session_t *s,
    rap_chain_t *in, rap_uint_t from_upstream);
static rap_int_t rap_stream_write_filter_init(rap_conf_t *cf);


static rap_stream_module_t  rap_stream_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_stream_write_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rap_module_t  rap_stream_write_filter_module = {
    RAP_MODULE_V1,
    &rap_stream_write_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
    RAP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_stream_write_filter(rap_stream_session_t *s, rap_chain_t *in,
    rap_uint_t from_upstream)
{
    off_t                           size;
    rap_uint_t                      last, flush, sync;
    rap_chain_t                    *cl, *ln, **ll, **out, *chain;
    rap_connection_t               *c;
    rap_stream_write_filter_ctx_t  *ctx;

    ctx = rap_stream_get_module_ctx(s, rap_stream_write_filter_module);

    if (ctx == NULL) {
        ctx = rap_pcalloc(s->connection->pool,
                          sizeof(rap_stream_write_filter_ctx_t));
        if (ctx == NULL) {
            return RAP_ERROR;
        }

        rap_stream_set_ctx(s, ctx, rap_stream_write_filter_module);
    }

    if (from_upstream) {
        c = s->connection;
        out = &ctx->from_upstream;

    } else {
        c = s->upstream->peer.connection;
        out = &ctx->from_downstream;
    }

    if (c->error) {
        return RAP_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = *out; cl; cl = cl->next) {
        ll = &cl->next;

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rap_buf_size(cl->buf) == 0 && !rap_buf_special(cl->buf)) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
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

            rap_debug_point();
            return RAP_ERROR;
        }

        if (rap_buf_size(cl->buf) < 0) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
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

            rap_debug_point();
            return RAP_ERROR;
        }

        size += rap_buf_size(cl->buf);

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
        cl = rap_alloc_chain_link(c->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rap_buf_size(cl->buf) == 0 && !rap_buf_special(cl->buf)) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
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

            rap_debug_point();
            return RAP_ERROR;
        }

        if (rap_buf_size(cl->buf) < 0) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
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

            rap_debug_point();
            return RAP_ERROR;
        }

        size += rap_buf_size(cl->buf);

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

    rap_log_debug3(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter: l:%ui f:%ui s:%O", last, flush, size);

    if (size == 0
        && !(c->buffered & RAP_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush || sync) {
            for (cl = *out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                rap_free_chain(c->pool, ln);
            }

            *out = NULL;
            c->buffered &= ~RAP_STREAM_WRITE_BUFFERED;

            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ALERT, c->log, 0,
                      "the stream output chain is empty");

        rap_debug_point();

        return RAP_ERROR;
    }

    chain = c->send_chain(c, *out, 0);

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream write filter %p", chain);

    if (chain == RAP_CHAIN_ERROR) {
        c->error = 1;
        return RAP_ERROR;
    }

    for (cl = *out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        rap_free_chain(c->pool, ln);
    }

    *out = chain;

    if (chain) {
        if (c->shared) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "shared connection is busy");
            return RAP_ERROR;
        }

        c->buffered |= RAP_STREAM_WRITE_BUFFERED;
        return RAP_AGAIN;
    }

    c->buffered &= ~RAP_STREAM_WRITE_BUFFERED;

    if (c->buffered & RAP_LOWLEVEL_BUFFERED) {
        return RAP_AGAIN;
    }

    return RAP_OK;
}


static rap_int_t
rap_stream_write_filter_init(rap_conf_t *cf)
{
    rap_stream_top_filter = rap_stream_write_filter;

    return RAP_OK;
}

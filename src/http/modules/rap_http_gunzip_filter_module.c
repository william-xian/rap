
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>

#include <zlib.h>


typedef struct {
    rap_flag_t           enable;
    rap_bufs_t           bufs;
} rap_http_gunzip_conf_t;


typedef struct {
    rap_chain_t         *in;
    rap_chain_t         *free;
    rap_chain_t         *busy;
    rap_chain_t         *out;
    rap_chain_t        **last_out;

    rap_buf_t           *in_buf;
    rap_buf_t           *out_buf;
    rap_int_t            bufs;

    unsigned             started:1;
    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;

    z_stream             zstream;
    rap_http_request_t  *request;
} rap_http_gunzip_ctx_t;


static rap_int_t rap_http_gunzip_filter_inflate_start(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx);
static rap_int_t rap_http_gunzip_filter_add_data(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx);
static rap_int_t rap_http_gunzip_filter_get_buf(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx);
static rap_int_t rap_http_gunzip_filter_inflate(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx);
static rap_int_t rap_http_gunzip_filter_inflate_end(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx);

static void *rap_http_gunzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void rap_http_gunzip_filter_free(void *opaque, void *address);

static rap_int_t rap_http_gunzip_filter_init(rap_conf_t *cf);
static void *rap_http_gunzip_create_conf(rap_conf_t *cf);
static char *rap_http_gunzip_merge_conf(rap_conf_t *cf,
    void *parent, void *child);


static rap_command_t  rap_http_gunzip_filter_commands[] = {

    { rap_string("gunzip"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gunzip_conf_t, enable),
      NULL },

    { rap_string("gunzip_buffers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_bufs_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gunzip_conf_t, bufs),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_gunzip_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_gunzip_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_gunzip_create_conf,           /* create location configuration */
    rap_http_gunzip_merge_conf             /* merge location configuration */
};


rap_module_t  rap_http_gunzip_filter_module = {
    RAP_MODULE_V1,
    &rap_http_gunzip_filter_module_ctx,    /* module context */
    rap_http_gunzip_filter_commands,       /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_http_output_header_filter_pt  rap_http_next_header_filter;
static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_int_t
rap_http_gunzip_header_filter(rap_http_request_t *r)
{
    rap_http_gunzip_ctx_t   *ctx;
    rap_http_gunzip_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r, rap_http_gunzip_filter_module);

    /* TODO support multiple content-codings */
    /* TODO always gunzip - due to configuration or module request */
    /* TODO ignore content encoding? */

    if (!conf->enable
        || r->headers_out.content_encoding == NULL
        || r->headers_out.content_encoding->value.len != 4
        || rap_strncasecmp(r->headers_out.content_encoding->value.data,
                           (u_char *) "gzip", 4) != 0)
    {
        return rap_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    if (!r->gzip_tested) {
        if (rap_http_gzip_ok(r) == RAP_OK) {
            return rap_http_next_header_filter(r);
        }

    } else if (r->gzip_ok) {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_gunzip_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_gunzip_filter_module);

    ctx->request = r;

    r->filter_need_in_memory = 1;

    r->headers_out.content_encoding->hash = 0;
    r->headers_out.content_encoding = NULL;

    rap_http_clear_content_length(r);
    rap_http_clear_accept_ranges(r);
    rap_http_weak_etag(r);

    return rap_http_next_header_filter(r);
}


static rap_int_t
rap_http_gunzip_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    int                     rc;
    rap_uint_t              flush;
    rap_chain_t            *cl;
    rap_http_gunzip_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_gunzip_filter_module);

    if (ctx == NULL || ctx->done) {
        return rap_http_next_body_filter(r, in);
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http gunzip filter");

    if (!ctx->started) {
        if (rap_http_gunzip_filter_inflate_start(r, ctx) != RAP_OK) {
            goto failed;
        }
    }

    if (in) {
        if (rap_chain_add_copy(r->pool, &ctx->in, in) != RAP_OK) {
            goto failed;
        }
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (rap_http_next_body_filter(r, NULL) == RAP_ERROR) {
            goto failed;
        }

        cl = NULL;

        rap_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (rap_buf_tag_t) &rap_http_gunzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = rap_http_gunzip_filter_add_data(r, ctx);

            if (rc == RAP_DECLINED) {
                break;
            }

            if (rc == RAP_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = rap_http_gunzip_filter_get_buf(r, ctx);

            if (rc == RAP_DECLINED) {
                break;
            }

            if (rc == RAP_ERROR) {
                goto failed;
            }

            rc = rap_http_gunzip_filter_inflate(r, ctx);

            if (rc == RAP_OK) {
                break;
            }

            if (rc == RAP_ERROR) {
                goto failed;
            }

            /* rc == RAP_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? RAP_AGAIN : RAP_OK;
        }

        rc = rap_http_next_body_filter(r, ctx->out);

        if (rc == RAP_ERROR) {
            goto failed;
        }

        rap_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (rap_buf_tag_t) &rap_http_gunzip_filter_module);
        ctx->last_out = &ctx->out;

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "gunzip out: %p", ctx->out);

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    return RAP_ERROR;
}


static rap_int_t
rap_http_gunzip_filter_inflate_start(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx)
{
    int  rc;

    ctx->zstream.next_in = Z_NULL;
    ctx->zstream.avail_in = 0;

    ctx->zstream.zalloc = rap_http_gunzip_filter_alloc;
    ctx->zstream.zfree = rap_http_gunzip_filter_free;
    ctx->zstream.opaque = ctx;

    /* windowBits +16 to decode gzip, zlib 1.2.0.4+ */
    rc = inflateInit2(&ctx->zstream, MAX_WBITS + 16);

    if (rc != Z_OK) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "inflateInit2() failed: %d", rc);
        return RAP_ERROR;
    }

    ctx->started = 1;

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return RAP_OK;
}


static rap_int_t
rap_http_gunzip_filter_add_data(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx)
{
    if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return RAP_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return RAP_DECLINED;
    }

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf || ctx->in_buf->last_in_chain) {
        ctx->flush = Z_FINISH;

    } else if (ctx->in_buf->flush) {
        ctx->flush = Z_SYNC_FLUSH;

    } else if (ctx->zstream.avail_in == 0) {
        /* ctx->flush == Z_NO_FLUSH */
        return RAP_AGAIN;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_gunzip_filter_get_buf(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx)
{
    rap_http_gunzip_conf_t  *conf;

    if (ctx->zstream.avail_out) {
        return RAP_OK;
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_gunzip_filter_module);

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

        ctx->out_buf->flush = 0;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = rap_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return RAP_ERROR;
        }

        ctx->out_buf->tag = (rap_buf_tag_t) &rap_http_gunzip_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return RAP_DECLINED;
    }

    ctx->zstream.next_out = ctx->out_buf->pos;
    ctx->zstream.avail_out = conf->bufs.size;

    return RAP_OK;
}


static rap_int_t
rap_http_gunzip_filter_inflate(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx)
{
    int           rc;
    rap_buf_t    *b;
    rap_chain_t  *cl;

    rap_log_debug6(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   ctx->flush, ctx->redo);

    rc = inflate(&ctx->zstream, ctx->flush);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "inflate() failed: %d, %d", ctx->flush, rc);
        return RAP_ERROR;
    }

    rap_log_debug5(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   rc);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    if (ctx->zstream.next_in) {
        ctx->in_buf->pos = ctx->zstream.next_in;

        if (ctx->zstream.avail_in == 0) {
            ctx->zstream.next_in = NULL;
        }
    }

    ctx->out_buf->last = ctx->zstream.next_out;

    if (ctx->zstream.avail_out == 0) {

        /* zlib wants to output some more data */

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        ctx->redo = 1;

        return RAP_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == Z_SYNC_FLUSH) {

        ctx->flush = Z_NO_FLUSH;

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        b = ctx->out_buf;

        if (rap_buf_size(b) == 0) {

            b = rap_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return RAP_ERROR;
            }

        } else {
            ctx->zstream.avail_out = 0;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return RAP_OK;
    }

    if (ctx->flush == Z_FINISH && ctx->zstream.avail_in == 0) {

        if (rc != Z_STREAM_END) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "inflate() returned %d on response end", rc);
            return RAP_ERROR;
        }

        if (rap_http_gunzip_filter_inflate_end(r, ctx) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_OK;
    }

    if (rc == Z_STREAM_END && ctx->zstream.avail_in > 0) {

        rc = inflateReset(&ctx->zstream);

        if (rc != Z_OK) {
            rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                          "inflateReset() failed: %d", rc);
            return RAP_ERROR;
        }

        ctx->redo = 1;

        return RAP_AGAIN;
    }

    if (ctx->in == NULL) {

        b = ctx->out_buf;

        if (rap_buf_size(b) == 0) {
            return RAP_OK;
        }

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        ctx->zstream.avail_out = 0;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return RAP_OK;
    }

    return RAP_AGAIN;
}


static rap_int_t
rap_http_gunzip_filter_inflate_end(rap_http_request_t *r,
    rap_http_gunzip_ctx_t *ctx)
{
    int           rc;
    rap_buf_t    *b;
    rap_chain_t  *cl;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip inflate end");

    rc = inflateEnd(&ctx->zstream);

    if (rc != Z_OK) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "inflateEnd() failed: %d", rc);
        return RAP_ERROR;
    }

    b = ctx->out_buf;

    if (rap_buf_size(b) == 0) {

        b = rap_calloc_buf(ctx->request->pool);
        if (b == NULL) {
            return RAP_ERROR;
        }
    }

    cl = rap_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = 1;

    ctx->done = 1;

    return RAP_OK;
}


static void *
rap_http_gunzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    rap_http_gunzip_ctx_t *ctx = opaque;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gunzip alloc: n:%ud s:%ud",
                   items, size);

    return rap_palloc(ctx->request->pool, items * size);
}


static void
rap_http_gunzip_filter_free(void *opaque, void *address)
{
#if 0
    rap_http_gunzip_ctx_t *ctx = opaque;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gunzip free: %p", address);
#endif
}


static void *
rap_http_gunzip_create_conf(rap_conf_t *cf)
{
    rap_http_gunzip_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_gunzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->bufs.num = 0;
     */

    conf->enable = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_gunzip_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_gunzip_conf_t *prev = parent;
    rap_http_gunzip_conf_t *conf = child;

    rap_conf_merge_value(conf->enable, prev->enable, 0);

    rap_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / rap_pagesize, rap_pagesize);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_gunzip_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_gunzip_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_gunzip_body_filter;

    return RAP_OK;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>

#include <zlib.h>


typedef struct {
    rp_flag_t           enable;
    rp_bufs_t           bufs;
} rp_http_gunzip_conf_t;


typedef struct {
    rp_chain_t         *in;
    rp_chain_t         *free;
    rp_chain_t         *busy;
    rp_chain_t         *out;
    rp_chain_t        **last_out;

    rp_buf_t           *in_buf;
    rp_buf_t           *out_buf;
    rp_int_t            bufs;

    unsigned             started:1;
    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;

    z_stream             zstream;
    rp_http_request_t  *request;
} rp_http_gunzip_ctx_t;


static rp_int_t rp_http_gunzip_filter_inflate_start(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx);
static rp_int_t rp_http_gunzip_filter_add_data(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx);
static rp_int_t rp_http_gunzip_filter_get_buf(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx);
static rp_int_t rp_http_gunzip_filter_inflate(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx);
static rp_int_t rp_http_gunzip_filter_inflate_end(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx);

static void *rp_http_gunzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void rp_http_gunzip_filter_free(void *opaque, void *address);

static rp_int_t rp_http_gunzip_filter_init(rp_conf_t *cf);
static void *rp_http_gunzip_create_conf(rp_conf_t *cf);
static char *rp_http_gunzip_merge_conf(rp_conf_t *cf,
    void *parent, void *child);


static rp_command_t  rp_http_gunzip_filter_commands[] = {

    { rp_string("gunzip"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gunzip_conf_t, enable),
      NULL },

    { rp_string("gunzip_buffers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_conf_set_bufs_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gunzip_conf_t, bufs),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_gunzip_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_gunzip_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_gunzip_create_conf,           /* create location configuration */
    rp_http_gunzip_merge_conf             /* merge location configuration */
};


rp_module_t  rp_http_gunzip_filter_module = {
    RP_MODULE_V1,
    &rp_http_gunzip_filter_module_ctx,    /* module context */
    rp_http_gunzip_filter_commands,       /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_gunzip_header_filter(rp_http_request_t *r)
{
    rp_http_gunzip_ctx_t   *ctx;
    rp_http_gunzip_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r, rp_http_gunzip_filter_module);

    /* TODO support multiple content-codings */
    /* TODO always gunzip - due to configuration or module request */
    /* TODO ignore content encoding? */

    if (!conf->enable
        || r->headers_out.content_encoding == NULL
        || r->headers_out.content_encoding->value.len != 4
        || rp_strncasecmp(r->headers_out.content_encoding->value.data,
                           (u_char *) "gzip", 4) != 0)
    {
        return rp_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    if (!r->gzip_tested) {
        if (rp_http_gzip_ok(r) == RP_OK) {
            return rp_http_next_header_filter(r);
        }

    } else if (r->gzip_ok) {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_gunzip_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_gunzip_filter_module);

    ctx->request = r;

    r->filter_need_in_memory = 1;

    r->headers_out.content_encoding->hash = 0;
    r->headers_out.content_encoding = NULL;

    rp_http_clear_content_length(r);
    rp_http_clear_accept_ranges(r);
    rp_http_weak_etag(r);

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_gunzip_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    int                     rc;
    rp_uint_t              flush;
    rp_chain_t            *cl;
    rp_http_gunzip_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_gunzip_filter_module);

    if (ctx == NULL || ctx->done) {
        return rp_http_next_body_filter(r, in);
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http gunzip filter");

    if (!ctx->started) {
        if (rp_http_gunzip_filter_inflate_start(r, ctx) != RP_OK) {
            goto failed;
        }
    }

    if (in) {
        if (rp_chain_add_copy(r->pool, &ctx->in, in) != RP_OK) {
            goto failed;
        }
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (rp_http_next_body_filter(r, NULL) == RP_ERROR) {
            goto failed;
        }

        cl = NULL;

        rp_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (rp_buf_tag_t) &rp_http_gunzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = rp_http_gunzip_filter_add_data(r, ctx);

            if (rc == RP_DECLINED) {
                break;
            }

            if (rc == RP_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = rp_http_gunzip_filter_get_buf(r, ctx);

            if (rc == RP_DECLINED) {
                break;
            }

            if (rc == RP_ERROR) {
                goto failed;
            }

            rc = rp_http_gunzip_filter_inflate(r, ctx);

            if (rc == RP_OK) {
                break;
            }

            if (rc == RP_ERROR) {
                goto failed;
            }

            /* rc == RP_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? RP_AGAIN : RP_OK;
        }

        rc = rp_http_next_body_filter(r, ctx->out);

        if (rc == RP_ERROR) {
            goto failed;
        }

        rp_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (rp_buf_tag_t) &rp_http_gunzip_filter_module);
        ctx->last_out = &ctx->out;

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

    return RP_ERROR;
}


static rp_int_t
rp_http_gunzip_filter_inflate_start(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx)
{
    int  rc;

    ctx->zstream.next_in = Z_NULL;
    ctx->zstream.avail_in = 0;

    ctx->zstream.zalloc = rp_http_gunzip_filter_alloc;
    ctx->zstream.zfree = rp_http_gunzip_filter_free;
    ctx->zstream.opaque = ctx;

    /* windowBits +16 to decode gzip, zlib 1.2.0.4+ */
    rc = inflateInit2(&ctx->zstream, MAX_WBITS + 16);

    if (rc != Z_OK) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "inflateInit2() failed: %d", rc);
        return RP_ERROR;
    }

    ctx->started = 1;

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return RP_OK;
}


static rp_int_t
rp_http_gunzip_filter_add_data(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx)
{
    if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return RP_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return RP_DECLINED;
    }

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf || ctx->in_buf->last_in_chain) {
        ctx->flush = Z_FINISH;

    } else if (ctx->in_buf->flush) {
        ctx->flush = Z_SYNC_FLUSH;

    } else if (ctx->zstream.avail_in == 0) {
        /* ctx->flush == Z_NO_FLUSH */
        return RP_AGAIN;
    }

    return RP_OK;
}


static rp_int_t
rp_http_gunzip_filter_get_buf(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx)
{
    rp_http_gunzip_conf_t  *conf;

    if (ctx->zstream.avail_out) {
        return RP_OK;
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_gunzip_filter_module);

    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;

        ctx->out_buf->flush = 0;

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = rp_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return RP_ERROR;
        }

        ctx->out_buf->tag = (rp_buf_tag_t) &rp_http_gunzip_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return RP_DECLINED;
    }

    ctx->zstream.next_out = ctx->out_buf->pos;
    ctx->zstream.avail_out = conf->bufs.size;

    return RP_OK;
}


static rp_int_t
rp_http_gunzip_filter_inflate(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx)
{
    int           rc;
    rp_buf_t    *b;
    rp_chain_t  *cl;

    rp_log_debug6(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   ctx->flush, ctx->redo);

    rc = inflate(&ctx->zstream, ctx->flush);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "inflate() failed: %d, %d", ctx->flush, rc);
        return RP_ERROR;
    }

    rp_log_debug5(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "inflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   rc);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

        cl = rp_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        ctx->redo = 1;

        return RP_AGAIN;
    }

    ctx->redo = 0;

    if (ctx->flush == Z_SYNC_FLUSH) {

        ctx->flush = Z_NO_FLUSH;

        cl = rp_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        b = ctx->out_buf;

        if (rp_buf_size(b) == 0) {

            b = rp_calloc_buf(ctx->request->pool);
            if (b == NULL) {
                return RP_ERROR;
            }

        } else {
            ctx->zstream.avail_out = 0;
        }

        b->flush = 1;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return RP_OK;
    }

    if (ctx->flush == Z_FINISH && ctx->zstream.avail_in == 0) {

        if (rc != Z_STREAM_END) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "inflate() returned %d on response end", rc);
            return RP_ERROR;
        }

        if (rp_http_gunzip_filter_inflate_end(r, ctx) != RP_OK) {
            return RP_ERROR;
        }

        return RP_OK;
    }

    if (rc == Z_STREAM_END && ctx->zstream.avail_in > 0) {

        rc = inflateReset(&ctx->zstream);

        if (rc != Z_OK) {
            rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                          "inflateReset() failed: %d", rc);
            return RP_ERROR;
        }

        ctx->redo = 1;

        return RP_AGAIN;
    }

    if (ctx->in == NULL) {

        b = ctx->out_buf;

        if (rp_buf_size(b) == 0) {
            return RP_OK;
        }

        cl = rp_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        ctx->zstream.avail_out = 0;

        cl->buf = b;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return RP_OK;
    }

    return RP_AGAIN;
}


static rp_int_t
rp_http_gunzip_filter_inflate_end(rp_http_request_t *r,
    rp_http_gunzip_ctx_t *ctx)
{
    int           rc;
    rp_buf_t    *b;
    rp_chain_t  *cl;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip inflate end");

    rc = inflateEnd(&ctx->zstream);

    if (rc != Z_OK) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "inflateEnd() failed: %d", rc);
        return RP_ERROR;
    }

    b = ctx->out_buf;

    if (rp_buf_size(b) == 0) {

        b = rp_calloc_buf(ctx->request->pool);
        if (b == NULL) {
            return RP_ERROR;
        }
    }

    cl = rp_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RP_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;
    b->sync = 1;

    ctx->done = 1;

    return RP_OK;
}


static void *
rp_http_gunzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    rp_http_gunzip_ctx_t *ctx = opaque;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gunzip alloc: n:%ud s:%ud",
                   items, size);

    return rp_palloc(ctx->request->pool, items * size);
}


static void
rp_http_gunzip_filter_free(void *opaque, void *address)
{
#if 0
    rp_http_gunzip_ctx_t *ctx = opaque;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gunzip free: %p", address);
#endif
}


static void *
rp_http_gunzip_create_conf(rp_conf_t *cf)
{
    rp_http_gunzip_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_gunzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->bufs.num = 0;
     */

    conf->enable = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_gunzip_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_gunzip_conf_t *prev = parent;
    rp_http_gunzip_conf_t *conf = child;

    rp_conf_merge_value(conf->enable, prev->enable, 0);

    rp_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / rp_pagesize, rp_pagesize);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_gunzip_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_gunzip_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_gunzip_body_filter;

    return RP_OK;
}

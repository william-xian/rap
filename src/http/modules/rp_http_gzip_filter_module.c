
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>

#include <zlib.h>


typedef struct {
    rp_flag_t           enable;
    rp_flag_t           no_buffer;

    rp_hash_t           types;

    rp_bufs_t           bufs;

    size_t               postpone_gzipping;
    rp_int_t            level;
    size_t               wbits;
    size_t               memlevel;
    ssize_t              min_length;

    rp_array_t         *types_keys;
} rp_http_gzip_conf_t;


typedef struct {
    rp_chain_t         *in;
    rp_chain_t         *free;
    rp_chain_t         *busy;
    rp_chain_t         *out;
    rp_chain_t        **last_out;

    rp_chain_t         *copied;
    rp_chain_t         *copy_buf;

    rp_buf_t           *in_buf;
    rp_buf_t           *out_buf;
    rp_int_t            bufs;

    void                *preallocated;
    char                *free_mem;
    rp_uint_t           allocated;

    int                  wbits;
    int                  memlevel;

    unsigned             flush:4;
    unsigned             redo:1;
    unsigned             done:1;
    unsigned             nomem:1;
    unsigned             buffering:1;
    unsigned             intel:1;

    size_t               zin;
    size_t               zout;

    z_stream             zstream;
    rp_http_request_t  *request;
} rp_http_gzip_ctx_t;


static void rp_http_gzip_filter_memory(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx);
static rp_int_t rp_http_gzip_filter_buffer(rp_http_gzip_ctx_t *ctx,
    rp_chain_t *in);
static rp_int_t rp_http_gzip_filter_deflate_start(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx);
static rp_int_t rp_http_gzip_filter_add_data(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx);
static rp_int_t rp_http_gzip_filter_get_buf(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx);
static rp_int_t rp_http_gzip_filter_deflate(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx);
static rp_int_t rp_http_gzip_filter_deflate_end(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx);

static void *rp_http_gzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void rp_http_gzip_filter_free(void *opaque, void *address);
static void rp_http_gzip_filter_free_copy_buf(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx);

static rp_int_t rp_http_gzip_add_variables(rp_conf_t *cf);
static rp_int_t rp_http_gzip_ratio_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_gzip_filter_init(rp_conf_t *cf);
static void *rp_http_gzip_create_conf(rp_conf_t *cf);
static char *rp_http_gzip_merge_conf(rp_conf_t *cf,
    void *parent, void *child);
static char *rp_http_gzip_window(rp_conf_t *cf, void *post, void *data);
static char *rp_http_gzip_hash(rp_conf_t *cf, void *post, void *data);


static rp_conf_num_bounds_t  rp_http_gzip_comp_level_bounds = {
    rp_conf_check_num_bounds, 1, 9
};

static rp_conf_post_handler_pt  rp_http_gzip_window_p = rp_http_gzip_window;
static rp_conf_post_handler_pt  rp_http_gzip_hash_p = rp_http_gzip_hash;


static rp_command_t  rp_http_gzip_filter_commands[] = {

    { rp_string("gzip"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, enable),
      NULL },

    { rp_string("gzip_buffers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_conf_set_bufs_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, bufs),
      NULL },

    { rp_string("gzip_types"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_types_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, types_keys),
      &rp_http_html_default_types[0] },

    { rp_string("gzip_comp_level"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, level),
      &rp_http_gzip_comp_level_bounds },

    { rp_string("gzip_window"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, wbits),
      &rp_http_gzip_window_p },

    { rp_string("gzip_hash"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, memlevel),
      &rp_http_gzip_hash_p },

    { rp_string("postpone_gzipping"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, postpone_gzipping),
      NULL },

    { rp_string("gzip_no_buffer"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, no_buffer),
      NULL },

    { rp_string("gzip_min_length"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_conf_t, min_length),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_gzip_filter_module_ctx = {
    rp_http_gzip_add_variables,           /* preconfiguration */
    rp_http_gzip_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_gzip_create_conf,             /* create location configuration */
    rp_http_gzip_merge_conf               /* merge location configuration */
};


rp_module_t  rp_http_gzip_filter_module = {
    RP_MODULE_V1,
    &rp_http_gzip_filter_module_ctx,      /* module context */
    rp_http_gzip_filter_commands,         /* module directives */
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


static rp_str_t  rp_http_gzip_ratio = rp_string("gzip_ratio");

static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;

static rp_uint_t  rp_http_gzip_assume_intel;


static rp_int_t
rp_http_gzip_header_filter(rp_http_request_t *r)
{
    rp_table_elt_t       *h;
    rp_http_gzip_ctx_t   *ctx;
    rp_http_gzip_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r, rp_http_gzip_filter_module);

    if (!conf->enable
        || (r->headers_out.status != RP_HTTP_OK
            && r->headers_out.status != RP_HTTP_FORBIDDEN
            && r->headers_out.status != RP_HTTP_NOT_FOUND)
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || (r->headers_out.content_length_n != -1
            && r->headers_out.content_length_n < conf->min_length)
        || rp_http_test_content_type(r, &conf->types) == NULL
        || r->header_only)
    {
        return rp_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

#if (RP_HTTP_DEGRADATION)
    {
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->gzip_disable_degradation && rp_http_degraded(r)) {
        return rp_http_next_header_filter(r);
    }
    }
#endif

    if (!r->gzip_tested) {
        if (rp_http_gzip_ok(r) != RP_OK) {
            return rp_http_next_header_filter(r);
        }

    } else if (!r->gzip_ok) {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_gzip_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_gzip_filter_module);

    ctx->request = r;
    ctx->buffering = (conf->postpone_gzipping != 0);

    rp_http_gzip_filter_memory(r, ctx);

    h = rp_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return RP_ERROR;
    }

    h->hash = 1;
    rp_str_set(&h->key, "Content-Encoding");
    rp_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    rp_http_clear_content_length(r);
    rp_http_clear_accept_ranges(r);
    rp_http_weak_etag(r);

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_gzip_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    int                   rc;
    rp_uint_t            flush;
    rp_chain_t          *cl;
    rp_http_gzip_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_gzip_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return rp_http_next_body_filter(r, in);
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http gzip filter");

    if (ctx->buffering) {

        /*
         * With default memory settings zlib starts to output gzipped data
         * only after it has got about 90K, so it makes sense to allocate
         * zlib memory (200-400K) only after we have enough data to compress.
         * Although we copy buffers, nevertheless for not big responses
         * this allows to allocate zlib memory, to compress and to output
         * the response in one step using hot CPU cache.
         */

        if (in) {
            switch (rp_http_gzip_filter_buffer(ctx, in)) {

            case RP_OK:
                return RP_OK;

            case RP_DONE:
                in = NULL;
                break;

            default:  /* RP_ERROR */
                goto failed;
            }

        } else {
            ctx->buffering = 0;
        }
    }

    if (ctx->preallocated == NULL) {
        if (rp_http_gzip_filter_deflate_start(r, ctx) != RP_OK) {
            goto failed;
        }
    }

    if (in) {
        if (rp_chain_add_copy(r->pool, &ctx->in, in) != RP_OK) {
            goto failed;
        }

        r->connection->buffered |= RP_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (rp_http_next_body_filter(r, NULL) == RP_ERROR) {
            goto failed;
        }

        cl = NULL;

        rp_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (rp_buf_tag_t) &rp_http_gzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = rp_http_gzip_filter_add_data(r, ctx);

            if (rc == RP_DECLINED) {
                break;
            }

            if (rc == RP_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = rp_http_gzip_filter_get_buf(r, ctx);

            if (rc == RP_DECLINED) {
                break;
            }

            if (rc == RP_ERROR) {
                goto failed;
            }


            rc = rp_http_gzip_filter_deflate(r, ctx);

            if (rc == RP_OK) {
                break;
            }

            if (rc == RP_ERROR) {
                goto failed;
            }

            /* rc == RP_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            rp_http_gzip_filter_free_copy_buf(r, ctx);

            return ctx->busy ? RP_AGAIN : RP_OK;
        }

        rc = rp_http_next_body_filter(r, ctx->out);

        if (rc == RP_ERROR) {
            goto failed;
        }

        rp_http_gzip_filter_free_copy_buf(r, ctx);

        rp_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (rp_buf_tag_t) &rp_http_gzip_filter_module);
        ctx->last_out = &ctx->out;

        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            return rc;
        }
    }

    /* unreachable */

failed:

    ctx->done = 1;

    if (ctx->preallocated) {
        deflateEnd(&ctx->zstream);

        rp_pfree(r->pool, ctx->preallocated);
    }

    rp_http_gzip_filter_free_copy_buf(r, ctx);

    return RP_ERROR;
}


static void
rp_http_gzip_filter_memory(rp_http_request_t *r, rp_http_gzip_ctx_t *ctx)
{
    int                    wbits, memlevel;
    rp_http_gzip_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r, rp_http_gzip_filter_module);

    wbits = conf->wbits;
    memlevel = conf->memlevel;

    if (r->headers_out.content_length_n > 0) {

        /* the actual zlib window size is smaller by 262 bytes */

        while (r->headers_out.content_length_n < ((1 << (wbits - 1)) - 262)) {
            wbits--;
            memlevel--;
        }

        if (memlevel < 1) {
            memlevel = 1;
        }
    }

    ctx->wbits = wbits;
    ctx->memlevel = memlevel;

    /*
     * We preallocate a memory for zlib in one buffer (200K-400K), this
     * decreases a number of malloc() and free() calls and also probably
     * decreases a number of syscalls (sbrk()/mmap() and so on).
     * Besides we free the memory as soon as a gzipping will complete
     * and do not wait while a whole response will be sent to a client.
     *
     * 8K is for zlib deflate_state, it takes
     *  *) 5816 bytes on i386 and sparc64 (32-bit mode)
     *  *) 5920 bytes on amd64 and sparc64
     */

    if (!rp_http_gzip_assume_intel) {
        ctx->allocated = 8192 + (1 << (wbits + 2)) + (1 << (memlevel + 9));

    } else {
        /*
         * A zlib variant from Intel, https://github.com/jtkukunas/zlib.
         * It can force window bits to 13 for fast compression level,
         * on processors with SSE 4.2 it uses 64K hash instead of scaling
         * it from the specified memory level, and also introduces
         * 16-byte padding in one out of the two window-sized buffers.
         */

        if (conf->level == 1) {
            wbits = rp_max(wbits, 13);
        }

        ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
                         + (1 << (rp_max(memlevel, 8) + 8))
                         + (1 << (memlevel + 8));
        ctx->intel = 1;
    }
}


static rp_int_t
rp_http_gzip_filter_buffer(rp_http_gzip_ctx_t *ctx, rp_chain_t *in)
{
    size_t                 size, buffered;
    rp_buf_t             *b, *buf;
    rp_chain_t           *cl, **ll;
    rp_http_request_t    *r;
    rp_http_gzip_conf_t  *conf;

    r = ctx->request;

    r->connection->buffered |= RP_HTTP_GZIP_BUFFERED;

    buffered = 0;
    ll = &ctx->in;

    for (cl = ctx->in; cl; cl = cl->next) {
        buffered += cl->buf->last - cl->buf->pos;
        ll = &cl->next;
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_gzip_filter_module);

    while (in) {
        cl = rp_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        b = in->buf;

        size = b->last - b->pos;
        buffered += size;

        if (b->flush || b->last_buf || buffered > conf->postpone_gzipping) {
            ctx->buffering = 0;
        }

        if (ctx->buffering && size) {

            buf = rp_create_temp_buf(r->pool, size);
            if (buf == NULL) {
                return RP_ERROR;
            }

            buf->last = rp_cpymem(buf->pos, b->pos, size);
            b->pos = b->last;

            buf->last_buf = b->last_buf;
            buf->tag = (rp_buf_tag_t) &rp_http_gzip_filter_module;

            cl->buf = buf;

        } else {
            cl->buf = b;
        }

        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return ctx->buffering ? RP_OK : RP_DONE;
}


static rp_int_t
rp_http_gzip_filter_deflate_start(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx)
{
    int                    rc;
    rp_http_gzip_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r, rp_http_gzip_filter_module);

    ctx->preallocated = rp_palloc(r->pool, ctx->allocated);
    if (ctx->preallocated == NULL) {
        return RP_ERROR;
    }

    ctx->free_mem = ctx->preallocated;

    ctx->zstream.zalloc = rp_http_gzip_filter_alloc;
    ctx->zstream.zfree = rp_http_gzip_filter_free;
    ctx->zstream.opaque = ctx;

    rc = deflateInit2(&ctx->zstream, (int) conf->level, Z_DEFLATED,
                      ctx->wbits + 16, ctx->memlevel, Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "deflateInit2() failed: %d", rc);
        return RP_ERROR;
    }

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return RP_OK;
}


static rp_int_t
rp_http_gzip_filter_add_data(rp_http_request_t *r, rp_http_gzip_ctx_t *ctx)
{
    rp_chain_t  *cl;

    if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return RP_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return RP_DECLINED;
    }

    if (ctx->copy_buf) {

        /*
         * to avoid CPU cache trashing we do not free() just quit buf,
         * but postpone free()ing after zlib compressing and data output
         */

        ctx->copy_buf->next = ctx->copied;
        ctx->copied = ctx->copy_buf;
        ctx->copy_buf = NULL;
    }

    cl = ctx->in;
    ctx->in_buf = cl->buf;
    ctx->in = cl->next;

    if (ctx->in_buf->tag == (rp_buf_tag_t) &rp_http_gzip_filter_module) {
        ctx->copy_buf = cl;

    } else {
        rp_free_chain(r->pool, cl);
    }

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf) {
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
rp_http_gzip_filter_get_buf(rp_http_request_t *r, rp_http_gzip_ctx_t *ctx)
{
    rp_chain_t           *cl;
    rp_http_gzip_conf_t  *conf;

    if (ctx->zstream.avail_out) {
        return RP_OK;
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_gzip_filter_module);

    if (ctx->free) {

        cl = ctx->free;
        ctx->out_buf = cl->buf;
        ctx->free = cl->next;

        rp_free_chain(r->pool, cl);

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = rp_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return RP_ERROR;
        }

        ctx->out_buf->tag = (rp_buf_tag_t) &rp_http_gzip_filter_module;
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
rp_http_gzip_filter_deflate(rp_http_request_t *r, rp_http_gzip_ctx_t *ctx)
{
    int                    rc;
    rp_buf_t             *b;
    rp_chain_t           *cl;
    rp_http_gzip_conf_t  *conf;

    rp_log_debug6(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "deflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                 ctx->zstream.next_in, ctx->zstream.next_out,
                 ctx->zstream.avail_in, ctx->zstream.avail_out,
                 ctx->flush, ctx->redo);

    rc = deflate(&ctx->zstream, ctx->flush);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "deflate() failed: %d, %d", ctx->flush, rc);
        return RP_ERROR;
    }

    rp_log_debug5(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   rc);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in_buf:%p pos:%p",
                   ctx->in_buf, ctx->in_buf->pos);

    if (ctx->zstream.next_in) {
        ctx->in_buf->pos = ctx->zstream.next_in;

        if (ctx->zstream.avail_in == 0) {
            ctx->zstream.next_in = NULL;
        }
    }

    ctx->out_buf->last = ctx->zstream.next_out;

    if (ctx->zstream.avail_out == 0 && rc != Z_STREAM_END) {

        /* zlib wants to output some more gzipped data */

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

        r->connection->buffered &= ~RP_HTTP_GZIP_BUFFERED;

        return RP_OK;
    }

    if (rc == Z_STREAM_END) {

        if (rp_http_gzip_filter_deflate_end(r, ctx) != RP_OK) {
            return RP_ERROR;
        }

        return RP_OK;
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_gzip_filter_module);

    if (conf->no_buffer && ctx->in == NULL) {

        cl = rp_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return RP_OK;
    }

    return RP_AGAIN;
}


static rp_int_t
rp_http_gzip_filter_deflate_end(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx)
{
    int           rc;
    rp_buf_t    *b;
    rp_chain_t  *cl;

    ctx->zin = ctx->zstream.total_in;
    ctx->zout = ctx->zstream.total_out;

    rc = deflateEnd(&ctx->zstream);

    if (rc != Z_OK) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "deflateEnd() failed: %d", rc);
        return RP_ERROR;
    }

    rp_pfree(r->pool, ctx->preallocated);

    cl = rp_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RP_ERROR;
    }

    b = ctx->out_buf;

    if (rp_buf_size(b) == 0) {
        b->temporary = 0;
    }

    b->last_buf = 1;

    cl->buf = b;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    ctx->zstream.avail_in = 0;
    ctx->zstream.avail_out = 0;

    ctx->done = 1;

    r->connection->buffered &= ~RP_HTTP_GZIP_BUFFERED;

    return RP_OK;
}


static void *
rp_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    rp_http_gzip_ctx_t *ctx = opaque;

    void        *p;
    rp_uint_t   alloc;

    alloc = items * size;

    if (items == 1 && alloc % 512 != 0 && alloc < 8192) {

        /*
         * The zlib deflate_state allocation, it takes about 6K,
         * we allocate 8K.  Other allocations are divisible by 512.
         */

        alloc = 8192;
    }

    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;

        rp_log_debug4(RP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                       "gzip alloc: n:%ud s:%ud a:%ui p:%p",
                       items, size, alloc, p);

        return p;
    }

    if (ctx->intel) {
        rp_log_error(RP_LOG_ALERT, ctx->request->connection->log, 0,
                      "gzip filter failed to use preallocated memory: "
                      "%ud of %ui", items * size, ctx->allocated);

    } else {
        rp_http_gzip_assume_intel = 1;
    }

    p = rp_palloc(ctx->request->pool, items * size);

    return p;
}


static void
rp_http_gzip_filter_free(void *opaque, void *address)
{
#if 0
    rp_http_gzip_ctx_t *ctx = opaque;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gzip free: %p", address);
#endif
}


static void
rp_http_gzip_filter_free_copy_buf(rp_http_request_t *r,
    rp_http_gzip_ctx_t *ctx)
{
    rp_chain_t  *cl;

    for (cl = ctx->copied; cl; cl = cl->next) {
        rp_pfree(r->pool, cl->buf->start);
    }

    ctx->copied = NULL;
}


static rp_int_t
rp_http_gzip_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var;

    var = rp_http_add_variable(cf, &rp_http_gzip_ratio, RP_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_gzip_ratio_variable;

    return RP_OK;
}


static rp_int_t
rp_http_gzip_ratio_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_uint_t            zint, zfrac;
    rp_http_gzip_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_gzip_filter_module);

    if (ctx == NULL || ctx->zout == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rp_pnalloc(r->pool, RP_INT32_LEN + 3);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    zint = (rp_uint_t) (ctx->zin / ctx->zout);
    zfrac = (rp_uint_t) ((ctx->zin * 100 / ctx->zout) % 100);

    if ((ctx->zin * 1000 / ctx->zout) % 10 > 4) {

        /* the rounding, e.g., 2.125 to 2.13 */

        zfrac++;

        if (zfrac > 99) {
            zint++;
            zfrac = 0;
        }
    }

    v->len = rp_sprintf(v->data, "%ui.%02ui", zint, zfrac) - v->data;

    return RP_OK;
}


static void *
rp_http_gzip_create_conf(rp_conf_t *cf)
{
    rp_http_gzip_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_gzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    conf->enable = RP_CONF_UNSET;
    conf->no_buffer = RP_CONF_UNSET;

    conf->postpone_gzipping = RP_CONF_UNSET_SIZE;
    conf->level = RP_CONF_UNSET;
    conf->wbits = RP_CONF_UNSET_SIZE;
    conf->memlevel = RP_CONF_UNSET_SIZE;
    conf->min_length = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_gzip_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_gzip_conf_t *prev = parent;
    rp_http_gzip_conf_t *conf = child;

    rp_conf_merge_value(conf->enable, prev->enable, 0);
    rp_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    rp_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / rp_pagesize, rp_pagesize);

    rp_conf_merge_size_value(conf->postpone_gzipping, prev->postpone_gzipping,
                              0);
    rp_conf_merge_value(conf->level, prev->level, 1);
    rp_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    rp_conf_merge_size_value(conf->memlevel, prev->memlevel,
                              MAX_MEM_LEVEL - 1);
    rp_conf_merge_value(conf->min_length, prev->min_length, 20);

    if (rp_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rp_http_html_default_types)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_gzip_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_gzip_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_gzip_body_filter;

    return RP_OK;
}


static char *
rp_http_gzip_window(rp_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  wbits, wsize;

    wbits = 15;

    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return RP_CONF_OK;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
}


static char *
rp_http_gzip_hash(rp_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  memlevel, hsize;

    memlevel = 9;

    for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {

        if (hsize == *np) {
            *np = memlevel;

            return RP_CONF_OK;
        }

        memlevel--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
}

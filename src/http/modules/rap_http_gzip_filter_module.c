
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>

#include <zlib.h>


typedef struct {
    rap_flag_t           enable;
    rap_flag_t           no_buffer;

    rap_hash_t           types;

    rap_bufs_t           bufs;

    size_t               postpone_gzipping;
    rap_int_t            level;
    size_t               wbits;
    size_t               memlevel;
    ssize_t              min_length;

    rap_array_t         *types_keys;
} rap_http_gzip_conf_t;


typedef struct {
    rap_chain_t         *in;
    rap_chain_t         *free;
    rap_chain_t         *busy;
    rap_chain_t         *out;
    rap_chain_t        **last_out;

    rap_chain_t         *copied;
    rap_chain_t         *copy_buf;

    rap_buf_t           *in_buf;
    rap_buf_t           *out_buf;
    rap_int_t            bufs;

    void                *preallocated;
    char                *free_mem;
    rap_uint_t           allocated;

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
    rap_http_request_t  *request;
} rap_http_gzip_ctx_t;


static void rap_http_gzip_filter_memory(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx);
static rap_int_t rap_http_gzip_filter_buffer(rap_http_gzip_ctx_t *ctx,
    rap_chain_t *in);
static rap_int_t rap_http_gzip_filter_deflate_start(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx);
static rap_int_t rap_http_gzip_filter_add_data(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx);
static rap_int_t rap_http_gzip_filter_get_buf(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx);
static rap_int_t rap_http_gzip_filter_deflate(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx);
static rap_int_t rap_http_gzip_filter_deflate_end(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx);

static void *rap_http_gzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void rap_http_gzip_filter_free(void *opaque, void *address);
static void rap_http_gzip_filter_free_copy_buf(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx);

static rap_int_t rap_http_gzip_add_variables(rap_conf_t *cf);
static rap_int_t rap_http_gzip_ratio_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_gzip_filter_init(rap_conf_t *cf);
static void *rap_http_gzip_create_conf(rap_conf_t *cf);
static char *rap_http_gzip_merge_conf(rap_conf_t *cf,
    void *parent, void *child);
static char *rap_http_gzip_window(rap_conf_t *cf, void *post, void *data);
static char *rap_http_gzip_hash(rap_conf_t *cf, void *post, void *data);


static rap_conf_num_bounds_t  rap_http_gzip_comp_level_bounds = {
    rap_conf_check_num_bounds, 1, 9
};

static rap_conf_post_handler_pt  rap_http_gzip_window_p = rap_http_gzip_window;
static rap_conf_post_handler_pt  rap_http_gzip_hash_p = rap_http_gzip_hash;


static rap_command_t  rap_http_gzip_filter_commands[] = {

    { rap_string("gzip"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, enable),
      NULL },

    { rap_string("gzip_buffers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_bufs_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, bufs),
      NULL },

    { rap_string("gzip_types"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_types_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, types_keys),
      &rap_http_html_default_types[0] },

    { rap_string("gzip_comp_level"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, level),
      &rap_http_gzip_comp_level_bounds },

    { rap_string("gzip_window"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, wbits),
      &rap_http_gzip_window_p },

    { rap_string("gzip_hash"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, memlevel),
      &rap_http_gzip_hash_p },

    { rap_string("postpone_gzipping"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, postpone_gzipping),
      NULL },

    { rap_string("gzip_no_buffer"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, no_buffer),
      NULL },

    { rap_string("gzip_min_length"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_conf_t, min_length),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_gzip_filter_module_ctx = {
    rap_http_gzip_add_variables,           /* preconfiguration */
    rap_http_gzip_filter_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_gzip_create_conf,             /* create location configuration */
    rap_http_gzip_merge_conf               /* merge location configuration */
};


rap_module_t  rap_http_gzip_filter_module = {
    RAP_MODULE_V1,
    &rap_http_gzip_filter_module_ctx,      /* module context */
    rap_http_gzip_filter_commands,         /* module directives */
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


static rap_str_t  rap_http_gzip_ratio = rap_string("gzip_ratio");

static rap_http_output_header_filter_pt  rap_http_next_header_filter;
static rap_http_output_body_filter_pt    rap_http_next_body_filter;

static rap_uint_t  rap_http_gzip_assume_intel;


static rap_int_t
rap_http_gzip_header_filter(rap_http_request_t *r)
{
    rap_table_elt_t       *h;
    rap_http_gzip_ctx_t   *ctx;
    rap_http_gzip_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r, rap_http_gzip_filter_module);

    if (!conf->enable
        || (r->headers_out.status != RAP_HTTP_OK
            && r->headers_out.status != RAP_HTTP_FORBIDDEN
            && r->headers_out.status != RAP_HTTP_NOT_FOUND)
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || (r->headers_out.content_length_n != -1
            && r->headers_out.content_length_n < conf->min_length)
        || rap_http_test_content_type(r, &conf->types) == NULL
        || r->header_only)
    {
        return rap_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

#if (RAP_HTTP_DEGRADATION)
    {
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->gzip_disable_degradation && rap_http_degraded(r)) {
        return rap_http_next_header_filter(r);
    }
    }
#endif

    if (!r->gzip_tested) {
        if (rap_http_gzip_ok(r) != RAP_OK) {
            return rap_http_next_header_filter(r);
        }

    } else if (!r->gzip_ok) {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_gzip_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_gzip_filter_module);

    ctx->request = r;
    ctx->buffering = (conf->postpone_gzipping != 0);

    rap_http_gzip_filter_memory(r, ctx);

    h = rap_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    h->hash = 1;
    rap_str_set(&h->key, "Content-Encoding");
    rap_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    rap_http_clear_content_length(r);
    rap_http_clear_accept_ranges(r);
    rap_http_weak_etag(r);

    return rap_http_next_header_filter(r);
}


static rap_int_t
rap_http_gzip_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    int                   rc;
    rap_uint_t            flush;
    rap_chain_t          *cl;
    rap_http_gzip_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_gzip_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return rap_http_next_body_filter(r, in);
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
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
            switch (rap_http_gzip_filter_buffer(ctx, in)) {

            case RAP_OK:
                return RAP_OK;

            case RAP_DONE:
                in = NULL;
                break;

            default:  /* RAP_ERROR */
                goto failed;
            }

        } else {
            ctx->buffering = 0;
        }
    }

    if (ctx->preallocated == NULL) {
        if (rap_http_gzip_filter_deflate_start(r, ctx) != RAP_OK) {
            goto failed;
        }
    }

    if (in) {
        if (rap_chain_add_copy(r->pool, &ctx->in, in) != RAP_OK) {
            goto failed;
        }

        r->connection->buffered |= RAP_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (rap_http_next_body_filter(r, NULL) == RAP_ERROR) {
            goto failed;
        }

        cl = NULL;

        rap_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (rap_buf_tag_t) &rap_http_gzip_filter_module);
        ctx->nomem = 0;
        flush = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            /* cycle while there is data to feed zlib and ... */

            rc = rap_http_gzip_filter_add_data(r, ctx);

            if (rc == RAP_DECLINED) {
                break;
            }

            if (rc == RAP_AGAIN) {
                continue;
            }


            /* ... there are buffers to write zlib output */

            rc = rap_http_gzip_filter_get_buf(r, ctx);

            if (rc == RAP_DECLINED) {
                break;
            }

            if (rc == RAP_ERROR) {
                goto failed;
            }


            rc = rap_http_gzip_filter_deflate(r, ctx);

            if (rc == RAP_OK) {
                break;
            }

            if (rc == RAP_ERROR) {
                goto failed;
            }

            /* rc == RAP_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            rap_http_gzip_filter_free_copy_buf(r, ctx);

            return ctx->busy ? RAP_AGAIN : RAP_OK;
        }

        rc = rap_http_next_body_filter(r, ctx->out);

        if (rc == RAP_ERROR) {
            goto failed;
        }

        rap_http_gzip_filter_free_copy_buf(r, ctx);

        rap_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (rap_buf_tag_t) &rap_http_gzip_filter_module);
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

        rap_pfree(r->pool, ctx->preallocated);
    }

    rap_http_gzip_filter_free_copy_buf(r, ctx);

    return RAP_ERROR;
}


static void
rap_http_gzip_filter_memory(rap_http_request_t *r, rap_http_gzip_ctx_t *ctx)
{
    int                    wbits, memlevel;
    rap_http_gzip_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r, rap_http_gzip_filter_module);

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

    if (!rap_http_gzip_assume_intel) {
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
            wbits = rap_max(wbits, 13);
        }

        ctx->allocated = 8192 + 16 + (1 << (wbits + 2))
                         + (1 << (rap_max(memlevel, 8) + 8))
                         + (1 << (memlevel + 8));
        ctx->intel = 1;
    }
}


static rap_int_t
rap_http_gzip_filter_buffer(rap_http_gzip_ctx_t *ctx, rap_chain_t *in)
{
    size_t                 size, buffered;
    rap_buf_t             *b, *buf;
    rap_chain_t           *cl, **ll;
    rap_http_request_t    *r;
    rap_http_gzip_conf_t  *conf;

    r = ctx->request;

    r->connection->buffered |= RAP_HTTP_GZIP_BUFFERED;

    buffered = 0;
    ll = &ctx->in;

    for (cl = ctx->in; cl; cl = cl->next) {
        buffered += cl->buf->last - cl->buf->pos;
        ll = &cl->next;
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_gzip_filter_module);

    while (in) {
        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        b = in->buf;

        size = b->last - b->pos;
        buffered += size;

        if (b->flush || b->last_buf || buffered > conf->postpone_gzipping) {
            ctx->buffering = 0;
        }

        if (ctx->buffering && size) {

            buf = rap_create_temp_buf(r->pool, size);
            if (buf == NULL) {
                return RAP_ERROR;
            }

            buf->last = rap_cpymem(buf->pos, b->pos, size);
            b->pos = b->last;

            buf->last_buf = b->last_buf;
            buf->tag = (rap_buf_tag_t) &rap_http_gzip_filter_module;

            cl->buf = buf;

        } else {
            cl->buf = b;
        }

        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return ctx->buffering ? RAP_OK : RAP_DONE;
}


static rap_int_t
rap_http_gzip_filter_deflate_start(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx)
{
    int                    rc;
    rap_http_gzip_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r, rap_http_gzip_filter_module);

    ctx->preallocated = rap_palloc(r->pool, ctx->allocated);
    if (ctx->preallocated == NULL) {
        return RAP_ERROR;
    }

    ctx->free_mem = ctx->preallocated;

    ctx->zstream.zalloc = rap_http_gzip_filter_alloc;
    ctx->zstream.zfree = rap_http_gzip_filter_free;
    ctx->zstream.opaque = ctx;

    rc = deflateInit2(&ctx->zstream, (int) conf->level, Z_DEFLATED,
                      ctx->wbits + 16, ctx->memlevel, Z_DEFAULT_STRATEGY);

    if (rc != Z_OK) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "deflateInit2() failed: %d", rc);
        return RAP_ERROR;
    }

    ctx->last_out = &ctx->out;
    ctx->flush = Z_NO_FLUSH;

    return RAP_OK;
}


static rap_int_t
rap_http_gzip_filter_add_data(rap_http_request_t *r, rap_http_gzip_ctx_t *ctx)
{
    rap_chain_t  *cl;

    if (ctx->zstream.avail_in || ctx->flush != Z_NO_FLUSH || ctx->redo) {
        return RAP_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in: %p", ctx->in);

    if (ctx->in == NULL) {
        return RAP_DECLINED;
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

    if (ctx->in_buf->tag == (rap_buf_tag_t) &rap_http_gzip_filter_module) {
        ctx->copy_buf = cl;

    } else {
        rap_free_chain(r->pool, cl);
    }

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf) {
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
rap_http_gzip_filter_get_buf(rap_http_request_t *r, rap_http_gzip_ctx_t *ctx)
{
    rap_chain_t           *cl;
    rap_http_gzip_conf_t  *conf;

    if (ctx->zstream.avail_out) {
        return RAP_OK;
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_gzip_filter_module);

    if (ctx->free) {

        cl = ctx->free;
        ctx->out_buf = cl->buf;
        ctx->free = cl->next;

        rap_free_chain(r->pool, cl);

    } else if (ctx->bufs < conf->bufs.num) {

        ctx->out_buf = rap_create_temp_buf(r->pool, conf->bufs.size);
        if (ctx->out_buf == NULL) {
            return RAP_ERROR;
        }

        ctx->out_buf->tag = (rap_buf_tag_t) &rap_http_gzip_filter_module;
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
rap_http_gzip_filter_deflate(rap_http_request_t *r, rap_http_gzip_ctx_t *ctx)
{
    int                    rc;
    rap_buf_t             *b;
    rap_chain_t           *cl;
    rap_http_gzip_conf_t  *conf;

    rap_log_debug6(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "deflate in: ni:%p no:%p ai:%ud ao:%ud fl:%d redo:%d",
                 ctx->zstream.next_in, ctx->zstream.next_out,
                 ctx->zstream.avail_in, ctx->zstream.avail_out,
                 ctx->flush, ctx->redo);

    rc = deflate(&ctx->zstream, ctx->flush);

    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "deflate() failed: %d, %d", ctx->flush, rc);
        return RAP_ERROR;
    }

    rap_log_debug5(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "deflate out: ni:%p no:%p ai:%ud ao:%ud rc:%d",
                   ctx->zstream.next_in, ctx->zstream.next_out,
                   ctx->zstream.avail_in, ctx->zstream.avail_out,
                   rc);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

        r->connection->buffered &= ~RAP_HTTP_GZIP_BUFFERED;

        return RAP_OK;
    }

    if (rc == Z_STREAM_END) {

        if (rap_http_gzip_filter_deflate_end(r, ctx) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_OK;
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_gzip_filter_module);

    if (conf->no_buffer && ctx->in == NULL) {

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        cl->buf = ctx->out_buf;
        cl->next = NULL;
        *ctx->last_out = cl;
        ctx->last_out = &cl->next;

        return RAP_OK;
    }

    return RAP_AGAIN;
}


static rap_int_t
rap_http_gzip_filter_deflate_end(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx)
{
    int           rc;
    rap_buf_t    *b;
    rap_chain_t  *cl;

    ctx->zin = ctx->zstream.total_in;
    ctx->zout = ctx->zstream.total_out;

    rc = deflateEnd(&ctx->zstream);

    if (rc != Z_OK) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "deflateEnd() failed: %d", rc);
        return RAP_ERROR;
    }

    rap_pfree(r->pool, ctx->preallocated);

    cl = rap_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    b = ctx->out_buf;

    if (rap_buf_size(b) == 0) {
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

    r->connection->buffered &= ~RAP_HTTP_GZIP_BUFFERED;

    return RAP_OK;
}


static void *
rap_http_gzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    rap_http_gzip_ctx_t *ctx = opaque;

    void        *p;
    rap_uint_t   alloc;

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

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                       "gzip alloc: n:%ud s:%ud a:%ui p:%p",
                       items, size, alloc, p);

        return p;
    }

    if (ctx->intel) {
        rap_log_error(RAP_LOG_ALERT, ctx->request->connection->log, 0,
                      "gzip filter failed to use preallocated memory: "
                      "%ud of %ui", items * size, ctx->allocated);

    } else {
        rap_http_gzip_assume_intel = 1;
    }

    p = rap_palloc(ctx->request->pool, items * size);

    return p;
}


static void
rap_http_gzip_filter_free(void *opaque, void *address)
{
#if 0
    rap_http_gzip_ctx_t *ctx = opaque;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gzip free: %p", address);
#endif
}


static void
rap_http_gzip_filter_free_copy_buf(rap_http_request_t *r,
    rap_http_gzip_ctx_t *ctx)
{
    rap_chain_t  *cl;

    for (cl = ctx->copied; cl; cl = cl->next) {
        rap_pfree(r->pool, cl->buf->start);
    }

    ctx->copied = NULL;
}


static rap_int_t
rap_http_gzip_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var;

    var = rap_http_add_variable(cf, &rap_http_gzip_ratio, RAP_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_gzip_ratio_variable;

    return RAP_OK;
}


static rap_int_t
rap_http_gzip_ratio_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_uint_t            zint, zfrac;
    rap_http_gzip_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_gzip_filter_module);

    if (ctx == NULL || ctx->zout == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(r->pool, RAP_INT32_LEN + 3);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    zint = (rap_uint_t) (ctx->zin / ctx->zout);
    zfrac = (rap_uint_t) ((ctx->zin * 100 / ctx->zout) % 100);

    if ((ctx->zin * 1000 / ctx->zout) % 10 > 4) {

        /* the rounding, e.g., 2.125 to 2.13 */

        zfrac++;

        if (zfrac > 99) {
            zint++;
            zfrac = 0;
        }
    }

    v->len = rap_sprintf(v->data, "%ui.%02ui", zint, zfrac) - v->data;

    return RAP_OK;
}


static void *
rap_http_gzip_create_conf(rap_conf_t *cf)
{
    rap_http_gzip_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_gzip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->bufs.num = 0;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    conf->enable = RAP_CONF_UNSET;
    conf->no_buffer = RAP_CONF_UNSET;

    conf->postpone_gzipping = RAP_CONF_UNSET_SIZE;
    conf->level = RAP_CONF_UNSET;
    conf->wbits = RAP_CONF_UNSET_SIZE;
    conf->memlevel = RAP_CONF_UNSET_SIZE;
    conf->min_length = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_gzip_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_gzip_conf_t *prev = parent;
    rap_http_gzip_conf_t *conf = child;

    rap_conf_merge_value(conf->enable, prev->enable, 0);
    rap_conf_merge_value(conf->no_buffer, prev->no_buffer, 0);

    rap_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / rap_pagesize, rap_pagesize);

    rap_conf_merge_size_value(conf->postpone_gzipping, prev->postpone_gzipping,
                              0);
    rap_conf_merge_value(conf->level, prev->level, 1);
    rap_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    rap_conf_merge_size_value(conf->memlevel, prev->memlevel,
                              MAX_MEM_LEVEL - 1);
    rap_conf_merge_value(conf->min_length, prev->min_length, 20);

    if (rap_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rap_http_html_default_types)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_gzip_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_gzip_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_gzip_body_filter;

    return RAP_OK;
}


static char *
rap_http_gzip_window(rap_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  wbits, wsize;

    wbits = 15;

    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return RAP_CONF_OK;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
}


static char *
rap_http_gzip_hash(rap_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  memlevel, hsize;

    memlevel = 9;

    for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {

        if (hsize == *np) {
            *np = memlevel;

            return RAP_CONF_OK;
        }

        memlevel--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
}

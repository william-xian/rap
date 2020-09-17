
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_CHARSET_OFF    -2
#define RP_HTTP_NO_CHARSET     -3
#define RP_HTTP_CHARSET_VAR    0x10000

/* 1 byte length and up to 3 bytes for the UTF-8 encoding of the UCS-2 */
#define RP_UTF_LEN             4

#define RP_HTML_ENTITY_LEN     (sizeof("&#1114111;") - 1)


typedef struct {
    u_char                    **tables;
    rp_str_t                   name;

    unsigned                    length:16;
    unsigned                    utf8:1;
} rp_http_charset_t;


typedef struct {
    rp_int_t                   src;
    rp_int_t                   dst;
} rp_http_charset_recode_t;


typedef struct {
    rp_int_t                   src;
    rp_int_t                   dst;
    u_char                     *src2dst;
    u_char                     *dst2src;
} rp_http_charset_tables_t;


typedef struct {
    rp_array_t                 charsets;       /* rp_http_charset_t */
    rp_array_t                 tables;         /* rp_http_charset_tables_t */
    rp_array_t                 recodes;        /* rp_http_charset_recode_t */
} rp_http_charset_main_conf_t;


typedef struct {
    rp_int_t                   charset;
    rp_int_t                   source_charset;
    rp_flag_t                  override_charset;

    rp_hash_t                  types;
    rp_array_t                *types_keys;
} rp_http_charset_loc_conf_t;


typedef struct {
    u_char                     *table;
    rp_int_t                   charset;
    rp_str_t                   charset_name;

    rp_chain_t                *busy;
    rp_chain_t                *free_bufs;
    rp_chain_t                *free_buffers;

    size_t                      saved_len;
    u_char                      saved[RP_UTF_LEN];

    unsigned                    length:16;
    unsigned                    from_utf8:1;
    unsigned                    to_utf8:1;
} rp_http_charset_ctx_t;


typedef struct {
    rp_http_charset_tables_t  *table;
    rp_http_charset_t         *charset;
    rp_uint_t                  characters;
} rp_http_charset_conf_ctx_t;


static rp_int_t rp_http_destination_charset(rp_http_request_t *r,
    rp_str_t *name);
static rp_int_t rp_http_main_request_charset(rp_http_request_t *r,
    rp_str_t *name);
static rp_int_t rp_http_source_charset(rp_http_request_t *r,
    rp_str_t *name);
static rp_int_t rp_http_get_charset(rp_http_request_t *r, rp_str_t *name);
static rp_inline void rp_http_set_charset(rp_http_request_t *r,
    rp_str_t *charset);
static rp_int_t rp_http_charset_ctx(rp_http_request_t *r,
    rp_http_charset_t *charsets, rp_int_t charset, rp_int_t source_charset);
static rp_uint_t rp_http_charset_recode(rp_buf_t *b, u_char *table);
static rp_chain_t *rp_http_charset_recode_from_utf8(rp_pool_t *pool,
    rp_buf_t *buf, rp_http_charset_ctx_t *ctx);
static rp_chain_t *rp_http_charset_recode_to_utf8(rp_pool_t *pool,
    rp_buf_t *buf, rp_http_charset_ctx_t *ctx);

static rp_chain_t *rp_http_charset_get_buf(rp_pool_t *pool,
    rp_http_charset_ctx_t *ctx);
static rp_chain_t *rp_http_charset_get_buffer(rp_pool_t *pool,
    rp_http_charset_ctx_t *ctx, size_t size);

static char *rp_http_charset_map_block(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_charset_map(rp_conf_t *cf, rp_command_t *dummy,
    void *conf);

static char *rp_http_set_charset_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_http_add_charset(rp_array_t *charsets, rp_str_t *name);

static void *rp_http_charset_create_main_conf(rp_conf_t *cf);
static void *rp_http_charset_create_loc_conf(rp_conf_t *cf);
static char *rp_http_charset_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_charset_postconfiguration(rp_conf_t *cf);


static rp_str_t  rp_http_charset_default_types[] = {
    rp_string("text/html"),
    rp_string("text/xml"),
    rp_string("text/plain"),
    rp_string("text/vnd.wap.wml"),
    rp_string("application/javascript"),
    rp_string("application/rss+xml"),
    rp_null_string
};


static rp_command_t  rp_http_charset_filter_commands[] = {

    { rp_string("charset"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF
                        |RP_HTTP_LIF_CONF|RP_CONF_TAKE1,
      rp_http_set_charset_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_charset_loc_conf_t, charset),
      NULL },

    { rp_string("source_charset"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF
                        |RP_HTTP_LIF_CONF|RP_CONF_TAKE1,
      rp_http_set_charset_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_charset_loc_conf_t, source_charset),
      NULL },

    { rp_string("override_charset"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF
                        |RP_HTTP_LIF_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_charset_loc_conf_t, override_charset),
      NULL },

    { rp_string("charset_types"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_types_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_charset_loc_conf_t, types_keys),
      &rp_http_charset_default_types[0] },

    { rp_string("charset_map"),
      RP_HTTP_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_TAKE2,
      rp_http_charset_map_block,
      RP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_charset_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_charset_postconfiguration,    /* postconfiguration */

    rp_http_charset_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_charset_create_loc_conf,      /* create location configuration */
    rp_http_charset_merge_loc_conf        /* merge location configuration */
};


rp_module_t  rp_http_charset_filter_module = {
    RP_MODULE_V1,
    &rp_http_charset_filter_module_ctx,   /* module context */
    rp_http_charset_filter_commands,      /* module directives */
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
rp_http_charset_header_filter(rp_http_request_t *r)
{
    rp_int_t                      charset, source_charset;
    rp_str_t                      dst, src;
    rp_http_charset_t            *charsets;
    rp_http_charset_main_conf_t  *mcf;

    if (r == r->main) {
        charset = rp_http_destination_charset(r, &dst);

    } else {
        charset = rp_http_main_request_charset(r, &dst);
    }

    if (charset == RP_ERROR) {
        return RP_ERROR;
    }

    if (charset == RP_DECLINED) {
        return rp_http_next_header_filter(r);
    }

    /* charset: charset index or RP_HTTP_NO_CHARSET */

    source_charset = rp_http_source_charset(r, &src);

    if (source_charset == RP_ERROR) {
        return RP_ERROR;
    }

    /*
     * source_charset: charset index, RP_HTTP_NO_CHARSET,
     *                 or RP_HTTP_CHARSET_OFF
     */

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "charset: \"%V\" > \"%V\"", &src, &dst);

    if (source_charset == RP_HTTP_CHARSET_OFF) {
        rp_http_set_charset(r, &dst);

        return rp_http_next_header_filter(r);
    }

    if (charset == RP_HTTP_NO_CHARSET
        || source_charset == RP_HTTP_NO_CHARSET)
    {
        if (source_charset != charset
            || rp_strncasecmp(dst.data, src.data, dst.len) != 0)
        {
            goto no_charset_map;
        }

        rp_http_set_charset(r, &dst);

        return rp_http_next_header_filter(r);
    }

    if (source_charset == charset) {
        r->headers_out.content_type.len = r->headers_out.content_type_len;

        rp_http_set_charset(r, &dst);

        return rp_http_next_header_filter(r);
    }

    /* source_charset != charset */

    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len)
    {
        return rp_http_next_header_filter(r);
    }

    mcf = rp_http_get_module_main_conf(r, rp_http_charset_filter_module);
    charsets = mcf->charsets.elts;

    if (charsets[source_charset].tables == NULL
        || charsets[source_charset].tables[charset] == NULL)
    {
        goto no_charset_map;
    }

    r->headers_out.content_type.len = r->headers_out.content_type_len;

    rp_http_set_charset(r, &dst);

    return rp_http_charset_ctx(r, charsets, charset, source_charset);

no_charset_map:

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                  &src, &dst);

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_destination_charset(rp_http_request_t *r, rp_str_t *name)
{
    rp_int_t                      charset;
    rp_http_charset_t            *charsets;
    rp_http_variable_value_t     *vv;
    rp_http_charset_loc_conf_t   *mlcf;
    rp_http_charset_main_conf_t  *mcf;

    if (r->headers_out.content_type.len == 0) {
        return RP_DECLINED;
    }

    if (r->headers_out.override_charset
        && r->headers_out.override_charset->len)
    {
        *name = *r->headers_out.override_charset;

        charset = rp_http_get_charset(r, name);

        if (charset != RP_HTTP_NO_CHARSET) {
            return charset;
        }

        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "unknown charset \"%V\" to override", name);

        return RP_DECLINED;
    }

    mlcf = rp_http_get_module_loc_conf(r, rp_http_charset_filter_module);
    charset = mlcf->charset;

    if (charset == RP_HTTP_CHARSET_OFF) {
        return RP_DECLINED;
    }

    if (r->headers_out.charset.len) {
        if (mlcf->override_charset == 0) {
            return RP_DECLINED;
        }

    } else {
        if (rp_http_test_content_type(r, &mlcf->types) == NULL) {
            return RP_DECLINED;
        }
    }

    if (charset < RP_HTTP_CHARSET_VAR) {
        mcf = rp_http_get_module_main_conf(r, rp_http_charset_filter_module);
        charsets = mcf->charsets.elts;
        *name = charsets[charset].name;
        return charset;
    }

    vv = rp_http_get_indexed_variable(r, charset - RP_HTTP_CHARSET_VAR);

    if (vv == NULL || vv->not_found) {
        return RP_ERROR;
    }

    name->len = vv->len;
    name->data = vv->data;

    return rp_http_get_charset(r, name);
}


static rp_int_t
rp_http_main_request_charset(rp_http_request_t *r, rp_str_t *src)
{
    rp_int_t                charset;
    rp_str_t               *main_charset;
    rp_http_charset_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r->main, rp_http_charset_filter_module);

    if (ctx) {
        *src = ctx->charset_name;
        return ctx->charset;
    }

    main_charset = &r->main->headers_out.charset;

    if (main_charset->len == 0) {
        return RP_DECLINED;
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_charset_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r->main, ctx, rp_http_charset_filter_module);

    charset = rp_http_get_charset(r, main_charset);

    ctx->charset = charset;
    ctx->charset_name = *main_charset;
    *src = *main_charset;

    return charset;
}


static rp_int_t
rp_http_source_charset(rp_http_request_t *r, rp_str_t *name)
{
    rp_int_t                      charset;
    rp_http_charset_t            *charsets;
    rp_http_variable_value_t     *vv;
    rp_http_charset_loc_conf_t   *lcf;
    rp_http_charset_main_conf_t  *mcf;

    if (r->headers_out.charset.len) {
        *name = r->headers_out.charset;
        return rp_http_get_charset(r, name);
    }

    lcf = rp_http_get_module_loc_conf(r, rp_http_charset_filter_module);

    charset = lcf->source_charset;

    if (charset == RP_HTTP_CHARSET_OFF) {
        name->len = 0;
        return charset;
    }

    if (charset < RP_HTTP_CHARSET_VAR) {
        mcf = rp_http_get_module_main_conf(r, rp_http_charset_filter_module);
        charsets = mcf->charsets.elts;
        *name = charsets[charset].name;
        return charset;
    }

    vv = rp_http_get_indexed_variable(r, charset - RP_HTTP_CHARSET_VAR);

    if (vv == NULL || vv->not_found) {
        return RP_ERROR;
    }

    name->len = vv->len;
    name->data = vv->data;

    return rp_http_get_charset(r, name);
}


static rp_int_t
rp_http_get_charset(rp_http_request_t *r, rp_str_t *name)
{
    rp_uint_t                     i, n;
    rp_http_charset_t            *charset;
    rp_http_charset_main_conf_t  *mcf;

    mcf = rp_http_get_module_main_conf(r, rp_http_charset_filter_module);

    charset = mcf->charsets.elts;
    n = mcf->charsets.nelts;

    for (i = 0; i < n; i++) {
        if (charset[i].name.len != name->len) {
            continue;
        }

        if (rp_strncasecmp(charset[i].name.data, name->data, name->len) == 0) {
            return i;
        }
    }

    return RP_HTTP_NO_CHARSET;
}


static rp_inline void
rp_http_set_charset(rp_http_request_t *r, rp_str_t *charset)
{
    if (r != r->main) {
        return;
    }

    if (r->headers_out.status == RP_HTTP_MOVED_PERMANENTLY
        || r->headers_out.status == RP_HTTP_MOVED_TEMPORARILY)
    {
        /*
         * do not set charset for the redirect because NN 4.x
         * use this charset instead of the next page charset
         */

        r->headers_out.charset.len = 0;
        return;
    }

    r->headers_out.charset = *charset;
}


static rp_int_t
rp_http_charset_ctx(rp_http_request_t *r, rp_http_charset_t *charsets,
    rp_int_t charset, rp_int_t source_charset)
{
    rp_http_charset_ctx_t  *ctx;

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_charset_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_charset_filter_module);

    ctx->table = charsets[source_charset].tables[charset];
    ctx->charset = charset;
    ctx->charset_name = charsets[charset].name;
    ctx->length = charsets[charset].length;
    ctx->from_utf8 = charsets[source_charset].utf8;
    ctx->to_utf8 = charsets[charset].utf8;

    r->filter_need_in_memory = 1;

    if ((ctx->to_utf8 || ctx->from_utf8) && r == r->main) {
        rp_http_clear_content_length(r);

    } else {
        r->filter_need_temporary = 1;
    }

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_charset_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_int_t                rc;
    rp_buf_t               *b;
    rp_chain_t             *cl, *out, **ll;
    rp_http_charset_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_charset_filter_module);

    if (ctx == NULL || ctx->table == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    if ((ctx->to_utf8 || ctx->from_utf8) || ctx->busy) {

        out = NULL;
        ll = &out;

        for (cl = in; cl; cl = cl->next) {
            b = cl->buf;

            if (rp_buf_size(b) == 0) {

                *ll = rp_alloc_chain_link(r->pool);
                if (*ll == NULL) {
                    return RP_ERROR;
                }

                (*ll)->buf = b;
                (*ll)->next = NULL;

                ll = &(*ll)->next;

                continue;
            }

            if (ctx->to_utf8) {
                *ll = rp_http_charset_recode_to_utf8(r->pool, b, ctx);

            } else {
                *ll = rp_http_charset_recode_from_utf8(r->pool, b, ctx);
            }

            if (*ll == NULL) {
                return RP_ERROR;
            }

            while (*ll) {
                ll = &(*ll)->next;
            }
        }

        rc = rp_http_next_body_filter(r, out);

        if (out) {
            if (ctx->busy == NULL) {
                ctx->busy = out;

            } else {
                for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
                cl->next = out;
            }
        }

        while (ctx->busy) {

            cl = ctx->busy;
            b = cl->buf;

            if (rp_buf_size(b) != 0) {
                break;
            }

            ctx->busy = cl->next;

            if (b->tag != (rp_buf_tag_t) &rp_http_charset_filter_module) {
                continue;
            }

            if (b->shadow) {
                b->shadow->pos = b->shadow->last;
            }

            if (b->pos) {
                cl->next = ctx->free_buffers;
                ctx->free_buffers = cl;
                continue;
            }

            cl->next = ctx->free_bufs;
            ctx->free_bufs = cl;
        }

        return rc;
    }

    for (cl = in; cl; cl = cl->next) {
        (void) rp_http_charset_recode(cl->buf, ctx->table);
    }

    return rp_http_next_body_filter(r, in);
}


static rp_uint_t
rp_http_charset_recode(rp_buf_t *b, u_char *table)
{
    u_char  *p, *last;

    last = b->last;

    for (p = b->pos; p < last; p++) {

        if (*p != table[*p]) {
            goto recode;
        }
    }

    return 0;

recode:

    do {
        if (*p != table[*p]) {
            *p = table[*p];
        }

        p++;

    } while (p < last);

    b->in_file = 0;

    return 1;
}


static rp_chain_t *
rp_http_charset_recode_from_utf8(rp_pool_t *pool, rp_buf_t *buf,
    rp_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char        c, *p, *src, *dst, *saved, **table;
    uint32_t      n;
    rp_buf_t    *b;
    rp_uint_t    i;
    rp_chain_t  *out, *cl, **ll;

    src = buf->pos;

    if (ctx->saved_len == 0) {

        for ( /* void */ ; src < buf->last; src++) {

            if (*src < 0x80) {
                continue;
            }

            len = src - buf->pos;

            if (len > 512) {
                out = rp_http_charset_get_buf(pool, ctx);
                if (out == NULL) {
                    return NULL;
                }

                b = out->buf;

                b->temporary = buf->temporary;
                b->memory = buf->memory;
                b->mmap = buf->mmap;
                b->flush = buf->flush;

                b->pos = buf->pos;
                b->last = src;

                out->buf = b;
                out->next = NULL;

                size = buf->last - src;

                saved = src;
                n = rp_utf8_decode(&saved, size);

                if (n == 0xfffffffe) {
                    /* incomplete UTF-8 symbol */

                    rp_memcpy(ctx->saved, src, size);
                    ctx->saved_len = size;

                    b->shadow = buf;

                    return out;
                }

            } else {
                out = NULL;
                size = len + buf->last - src;
                src = buf->pos;
            }

            if (size < RP_HTML_ENTITY_LEN) {
                size += RP_HTML_ENTITY_LEN;
            }

            cl = rp_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            if (out) {
                out->next = cl;

            } else {
                out = cl;
            }

            b = cl->buf;
            dst = b->pos;

            goto recode;
        }

        out = rp_alloc_chain_link(pool);
        if (out == NULL) {
            return NULL;
        }

        out->buf = buf;
        out->next = NULL;

        return out;
    }

    /* process incomplete UTF sequence from previous buffer */

    rp_log_debug1(RP_LOG_DEBUG_HTTP, pool->log, 0,
                   "http charset utf saved: %z", ctx->saved_len);

    p = src;

    for (i = ctx->saved_len; i < RP_UTF_LEN; i++) {
        ctx->saved[i] = *p++;

        if (p == buf->last) {
            break;
        }
    }

    saved = ctx->saved;
    n = rp_utf8_decode(&saved, i);

    c = '\0';

    if (n < 0x10000) {
        table = (u_char **) ctx->table;
        p = table[n >> 8];

        if (p) {
            c = p[n & 0xff];
        }

    } else if (n == 0xfffffffe) {

        /* incomplete UTF-8 symbol */

        if (i < RP_UTF_LEN) {
            out = rp_http_charset_get_buf(pool, ctx);
            if (out == NULL) {
                return NULL;
            }

            b = out->buf;

            b->pos = buf->pos;
            b->last = buf->last;
            b->sync = 1;
            b->shadow = buf;

            rp_memcpy(&ctx->saved[ctx->saved_len], src, i);
            ctx->saved_len += i;

            return out;
        }
    }

    size = buf->last - buf->pos;

    if (size < RP_HTML_ENTITY_LEN) {
        size += RP_HTML_ENTITY_LEN;
    }

    cl = rp_http_charset_get_buffer(pool, ctx, size);
    if (cl == NULL) {
        return NULL;
    }

    out = cl;

    b = cl->buf;
    dst = b->pos;

    if (c) {
        *dst++ = c;

    } else if (n == 0xfffffffe) {
        *dst++ = '?';

        rp_log_debug0(RP_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 0");

        saved = &ctx->saved[RP_UTF_LEN];

    } else if (n > 0x10ffff) {
        *dst++ = '?';

        rp_log_debug0(RP_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 1");

    } else {
        dst = rp_sprintf(dst, "&#%uD;", n);
    }

    src += (saved - ctx->saved) - ctx->saved_len;
    ctx->saved_len = 0;

recode:

    ll = &cl->next;

    table = (u_char **) ctx->table;

    while (src < buf->last) {

        if ((size_t) (b->end - dst) < RP_HTML_ENTITY_LEN) {
            b->last = dst;

            size = buf->last - src + RP_HTML_ENTITY_LEN;

            cl = rp_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            dst = b->pos;
        }

        if (*src < 0x80) {
            *dst++ = *src++;
            continue;
        }

        len = buf->last - src;

        n = rp_utf8_decode(&src, len);

        if (n < 0x10000) {

            p = table[n >> 8];

            if (p) {
                c = p[n & 0xff];

                if (c) {
                    *dst++ = c;
                    continue;
                }
            }

            dst = rp_sprintf(dst, "&#%uD;", n);

            continue;
        }

        if (n == 0xfffffffe) {
            /* incomplete UTF-8 symbol */

            rp_memcpy(ctx->saved, src, len);
            ctx->saved_len = len;

            if (b->pos == dst) {
                b->sync = 1;
                b->temporary = 0;
            }

            break;
        }

        if (n > 0x10ffff) {
            *dst++ = '?';

            rp_log_debug0(RP_LOG_DEBUG_HTTP, pool->log, 0,
                           "http charset invalid utf 2");

            continue;
        }

        /* n > 0xffff */

        dst = rp_sprintf(dst, "&#%uD;", n);
    }

    b->last = dst;

    b->last_buf = buf->last_buf;
    b->last_in_chain = buf->last_in_chain;
    b->flush = buf->flush;

    b->shadow = buf;

    return out;
}


static rp_chain_t *
rp_http_charset_recode_to_utf8(rp_pool_t *pool, rp_buf_t *buf,
    rp_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char       *p, *src, *dst, *table;
    rp_buf_t    *b;
    rp_chain_t  *out, *cl, **ll;

    table = ctx->table;

    for (src = buf->pos; src < buf->last; src++) {
        if (table[*src * RP_UTF_LEN] == '\1') {
            continue;
        }

        goto recode;
    }

    out = rp_alloc_chain_link(pool);
    if (out == NULL) {
        return NULL;
    }

    out->buf = buf;
    out->next = NULL;

    return out;

recode:

    /*
     * we assume that there are about half of characters to be recoded,
     * so we preallocate "size / 2 + size / 2 * ctx->length"
     */

    len = src - buf->pos;

    if (len > 512) {
        out = rp_http_charset_get_buf(pool, ctx);
        if (out == NULL) {
            return NULL;
        }

        b = out->buf;

        b->temporary = buf->temporary;
        b->memory = buf->memory;
        b->mmap = buf->mmap;
        b->flush = buf->flush;

        b->pos = buf->pos;
        b->last = src;

        out->buf = b;
        out->next = NULL;

        size = buf->last - src;
        size = size / 2 + size / 2 * ctx->length;

    } else {
        out = NULL;

        size = buf->last - src;
        size = len + size / 2 + size / 2 * ctx->length;

        src = buf->pos;
    }

    cl = rp_http_charset_get_buffer(pool, ctx, size);
    if (cl == NULL) {
        return NULL;
    }

    if (out) {
        out->next = cl;

    } else {
        out = cl;
    }

    ll = &cl->next;

    b = cl->buf;
    dst = b->pos;

    while (src < buf->last) {

        p = &table[*src++ * RP_UTF_LEN];
        len = *p++;

        if ((size_t) (b->end - dst) < len) {
            b->last = dst;

            size = buf->last - src;
            size = len + size / 2 + size / 2 * ctx->length;

            cl = rp_http_charset_get_buffer(pool, ctx, size);
            if (cl == NULL) {
                return NULL;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;
            dst = b->pos;
        }

        while (len) {
            *dst++ = *p++;
            len--;
        }
    }

    b->last = dst;

    b->last_buf = buf->last_buf;
    b->last_in_chain = buf->last_in_chain;
    b->flush = buf->flush;

    b->shadow = buf;

    return out;
}


static rp_chain_t *
rp_http_charset_get_buf(rp_pool_t *pool, rp_http_charset_ctx_t *ctx)
{
    rp_chain_t  *cl;

    cl = ctx->free_bufs;

    if (cl) {
        ctx->free_bufs = cl->next;

        cl->buf->shadow = NULL;
        cl->next = NULL;

        return cl;
    }

    cl = rp_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = rp_calloc_buf(pool);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->tag = (rp_buf_tag_t) &rp_http_charset_filter_module;

    return cl;
}


static rp_chain_t *
rp_http_charset_get_buffer(rp_pool_t *pool, rp_http_charset_ctx_t *ctx,
    size_t size)
{
    rp_buf_t    *b;
    rp_chain_t  *cl, **ll;

    for (ll = &ctx->free_buffers, cl = ctx->free_buffers;
         cl;
         ll = &cl->next, cl = cl->next)
    {
        b = cl->buf;

        if ((size_t) (b->end - b->start) >= size) {
            *ll = cl->next;
            cl->next = NULL;

            b->pos = b->start;
            b->temporary = 1;
            b->shadow = NULL;

            return cl;
        }
    }

    cl = rp_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = rp_create_temp_buf(pool, size);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->temporary = 1;
    cl->buf->tag = (rp_buf_tag_t) &rp_http_charset_filter_module;

    return cl;
}


static char *
rp_http_charset_map_block(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_charset_main_conf_t  *mcf = conf;

    char                         *rv;
    u_char                       *p, *dst2src, **pp;
    rp_int_t                     src, dst;
    rp_uint_t                    i, n;
    rp_str_t                    *value;
    rp_conf_t                    pvcf;
    rp_http_charset_t           *charset;
    rp_http_charset_tables_t    *table;
    rp_http_charset_conf_ctx_t   ctx;

    value = cf->args->elts;

    src = rp_http_add_charset(&mcf->charsets, &value[1]);
    if (src == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    dst = rp_http_add_charset(&mcf->charsets, &value[2]);
    if (dst == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    if (src == dst) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"charset_map\" between the same charsets "
                           "\"%V\" and \"%V\"", &value[1], &value[2]);
        return RP_CONF_ERROR;
    }

    table = mcf->tables.elts;
    for (i = 0; i < mcf->tables.nelts; i++) {
        if ((src == table->src && dst == table->dst)
             || (src == table->dst && dst == table->src))
        {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "duplicate \"charset_map\" between "
                               "\"%V\" and \"%V\"", &value[1], &value[2]);
            return RP_CONF_ERROR;
        }
    }

    table = rp_array_push(&mcf->tables);
    if (table == NULL) {
        return RP_CONF_ERROR;
    }

    table->src = src;
    table->dst = dst;

    if (rp_strcasecmp(value[2].data, (u_char *) "utf-8") == 0) {
        table->src2dst = rp_pcalloc(cf->pool, 256 * RP_UTF_LEN);
        if (table->src2dst == NULL) {
            return RP_CONF_ERROR;
        }

        table->dst2src = rp_pcalloc(cf->pool, 256 * sizeof(void *));
        if (table->dst2src == NULL) {
            return RP_CONF_ERROR;
        }

        dst2src = rp_pcalloc(cf->pool, 256);
        if (dst2src == NULL) {
            return RP_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];
        pp[0] = dst2src;

        for (i = 0; i < 128; i++) {
            p = &table->src2dst[i * RP_UTF_LEN];
            p[0] = '\1';
            p[1] = (u_char) i;
            dst2src[i] = (u_char) i;
        }

        for (/* void */; i < 256; i++) {
            p = &table->src2dst[i * RP_UTF_LEN];
            p[0] = '\1';
            p[1] = '?';
        }

    } else {
        table->src2dst = rp_palloc(cf->pool, 256);
        if (table->src2dst == NULL) {
            return RP_CONF_ERROR;
        }

        table->dst2src = rp_palloc(cf->pool, 256);
        if (table->dst2src == NULL) {
            return RP_CONF_ERROR;
        }

        for (i = 0; i < 128; i++) {
            table->src2dst[i] = (u_char) i;
            table->dst2src[i] = (u_char) i;
        }

        for (/* void */; i < 256; i++) {
            table->src2dst[i] = '?';
            table->dst2src[i] = '?';
        }
    }

    charset = mcf->charsets.elts;

    ctx.table = table;
    ctx.charset = &charset[dst];
    ctx.characters = 0;

    pvcf = *cf;
    cf->ctx = &ctx;
    cf->handler = rp_http_charset_map;
    cf->handler_conf = conf;

    rv = rp_conf_parse(cf, NULL);

    *cf = pvcf;

    if (ctx.characters) {
        n = ctx.charset->length;
        ctx.charset->length /= ctx.characters;

        if (((n * 10) / ctx.characters) % 10 > 4) {
            ctx.charset->length++;
        }
    }

    return rv;
}


static char *
rp_http_charset_map(rp_conf_t *cf, rp_command_t *dummy, void *conf)
{
    u_char                       *p, *dst2src, **pp;
    uint32_t                      n;
    rp_int_t                     src, dst;
    rp_str_t                    *value;
    rp_uint_t                    i;
    rp_http_charset_tables_t    *table;
    rp_http_charset_conf_ctx_t  *ctx;

    if (cf->args->nelts != 2) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "invalid parameters number");
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    src = rp_hextoi(value[0].data, value[0].len);
    if (src == RP_ERROR || src > 255) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid value \"%V\"", &value[0]);
        return RP_CONF_ERROR;
    }

    ctx = cf->ctx;
    table = ctx->table;

    if (ctx->charset->utf8) {
        p = &table->src2dst[src * RP_UTF_LEN];

        *p++ = (u_char) (value[1].len / 2);

        for (i = 0; i < value[1].len; i += 2) {
            dst = rp_hextoi(&value[1].data[i], 2);
            if (dst == RP_ERROR || dst > 255) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[1]);
                return RP_CONF_ERROR;
            }

            *p++ = (u_char) dst;
        }

        i /= 2;

        ctx->charset->length += i;
        ctx->characters++;

        p = &table->src2dst[src * RP_UTF_LEN] + 1;

        n = rp_utf8_decode(&p, i);

        if (n > 0xffff) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];

        dst2src = pp[n >> 8];

        if (dst2src == NULL) {
            dst2src = rp_pcalloc(cf->pool, 256);
            if (dst2src == NULL) {
                return RP_CONF_ERROR;
            }

            pp[n >> 8] = dst2src;
        }

        dst2src[n & 0xff] = (u_char) src;

    } else {
        dst = rp_hextoi(value[1].data, value[1].len);
        if (dst == RP_ERROR || dst > 255) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        table->src2dst[src] = (u_char) dst;
        table->dst2src[dst] = (u_char) src;
    }

    return RP_CONF_OK;
}


static char *
rp_http_set_charset_slot(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_int_t                     *cp;
    rp_str_t                     *value, var;
    rp_http_charset_main_conf_t  *mcf;

    cp = (rp_int_t *) (p + cmd->offset);

    if (*cp != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cmd->offset == offsetof(rp_http_charset_loc_conf_t, charset)
        && rp_strcmp(value[1].data, "off") == 0)
    {
        *cp = RP_HTTP_CHARSET_OFF;
        return RP_CONF_OK;
    }


    if (value[1].data[0] == '$') {
        var.len = value[1].len - 1;
        var.data = value[1].data + 1;

        *cp = rp_http_get_variable_index(cf, &var);

        if (*cp == RP_ERROR) {
            return RP_CONF_ERROR;
        }

        *cp += RP_HTTP_CHARSET_VAR;

        return RP_CONF_OK;
    }

    mcf = rp_http_conf_get_module_main_conf(cf,
                                             rp_http_charset_filter_module);

    *cp = rp_http_add_charset(&mcf->charsets, &value[1]);
    if (*cp == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_add_charset(rp_array_t *charsets, rp_str_t *name)
{
    rp_uint_t           i;
    rp_http_charset_t  *c;

    c = charsets->elts;
    for (i = 0; i < charsets->nelts; i++) {
        if (name->len != c[i].name.len) {
            continue;
        }

        if (rp_strcasecmp(name->data, c[i].name.data) == 0) {
            break;
        }
    }

    if (i < charsets->nelts) {
        return i;
    }

    c = rp_array_push(charsets);
    if (c == NULL) {
        return RP_ERROR;
    }

    c->tables = NULL;
    c->name = *name;
    c->length = 0;

    if (rp_strcasecmp(name->data, (u_char *) "utf-8") == 0) {
        c->utf8 = 1;

    } else {
        c->utf8 = 0;
    }

    return i;
}


static void *
rp_http_charset_create_main_conf(rp_conf_t *cf)
{
    rp_http_charset_main_conf_t  *mcf;

    mcf = rp_pcalloc(cf->pool, sizeof(rp_http_charset_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    if (rp_array_init(&mcf->charsets, cf->pool, 2, sizeof(rp_http_charset_t))
        != RP_OK)
    {
        return NULL;
    }

    if (rp_array_init(&mcf->tables, cf->pool, 1,
                       sizeof(rp_http_charset_tables_t))
        != RP_OK)
    {
        return NULL;
    }

    if (rp_array_init(&mcf->recodes, cf->pool, 2,
                       sizeof(rp_http_charset_recode_t))
        != RP_OK)
    {
        return NULL;
    }

    return mcf;
}


static void *
rp_http_charset_create_loc_conf(rp_conf_t *cf)
{
    rp_http_charset_loc_conf_t  *lcf;

    lcf = rp_pcalloc(cf->pool, sizeof(rp_http_charset_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     lcf->types = { NULL };
     *     lcf->types_keys = NULL;
     */

    lcf->charset = RP_CONF_UNSET;
    lcf->source_charset = RP_CONF_UNSET;
    lcf->override_charset = RP_CONF_UNSET;

    return lcf;
}


static char *
rp_http_charset_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_charset_loc_conf_t *prev = parent;
    rp_http_charset_loc_conf_t *conf = child;

    rp_uint_t                     i;
    rp_http_charset_recode_t     *recode;
    rp_http_charset_main_conf_t  *mcf;

    if (rp_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rp_http_charset_default_types)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    rp_conf_merge_value(conf->override_charset, prev->override_charset, 0);
    rp_conf_merge_value(conf->charset, prev->charset, RP_HTTP_CHARSET_OFF);
    rp_conf_merge_value(conf->source_charset, prev->source_charset,
                         RP_HTTP_CHARSET_OFF);

    if (conf->charset == RP_HTTP_CHARSET_OFF
        || conf->source_charset == RP_HTTP_CHARSET_OFF
        || conf->charset == conf->source_charset)
    {
        return RP_CONF_OK;
    }

    if (conf->source_charset >= RP_HTTP_CHARSET_VAR
        || conf->charset >= RP_HTTP_CHARSET_VAR)
    {
        return RP_CONF_OK;
    }

    mcf = rp_http_conf_get_module_main_conf(cf,
                                             rp_http_charset_filter_module);
    recode = mcf->recodes.elts;
    for (i = 0; i < mcf->recodes.nelts; i++) {
        if (conf->source_charset == recode[i].src
            && conf->charset == recode[i].dst)
        {
            return RP_CONF_OK;
        }
    }

    recode = rp_array_push(&mcf->recodes);
    if (recode == NULL) {
        return RP_CONF_ERROR;
    }

    recode->src = conf->source_charset;
    recode->dst = conf->charset;

    return RP_CONF_OK;
}


static rp_int_t
rp_http_charset_postconfiguration(rp_conf_t *cf)
{
    u_char                       **src, **dst;
    rp_int_t                      c;
    rp_uint_t                     i, t;
    rp_http_charset_t            *charset;
    rp_http_charset_recode_t     *recode;
    rp_http_charset_tables_t     *tables;
    rp_http_charset_main_conf_t  *mcf;

    mcf = rp_http_conf_get_module_main_conf(cf,
                                             rp_http_charset_filter_module);

    recode = mcf->recodes.elts;
    tables = mcf->tables.elts;
    charset = mcf->charsets.elts;

    for (i = 0; i < mcf->recodes.nelts; i++) {

        c = recode[i].src;

        for (t = 0; t < mcf->tables.nelts; t++) {

            if (c == tables[t].src && recode[i].dst == tables[t].dst) {
                goto next;
            }

            if (c == tables[t].dst && recode[i].dst == tables[t].src) {
                goto next;
            }
        }

        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                   "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                   &charset[c].name, &charset[recode[i].dst].name);
        return RP_ERROR;

    next:
        continue;
    }


    for (t = 0; t < mcf->tables.nelts; t++) {

        src = charset[tables[t].src].tables;

        if (src == NULL) {
            src = rp_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (src == NULL) {
                return RP_ERROR;
            }

            charset[tables[t].src].tables = src;
        }

        dst = charset[tables[t].dst].tables;

        if (dst == NULL) {
            dst = rp_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (dst == NULL) {
                return RP_ERROR;
            }

            charset[tables[t].dst].tables = dst;
        }

        src[tables[t].dst] = tables[t].src2dst;
        dst[tables[t].src] = tables[t].dst2src;
    }

    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_charset_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_charset_body_filter;

    return RP_OK;
}

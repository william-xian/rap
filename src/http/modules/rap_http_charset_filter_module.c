
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_CHARSET_OFF    -2
#define RAP_HTTP_NO_CHARSET     -3
#define RAP_HTTP_CHARSET_VAR    0x10000

/* 1 byte length and up to 3 bytes for the UTF-8 encoding of the UCS-2 */
#define RAP_UTF_LEN             4

#define RAP_HTML_ENTITY_LEN     (sizeof("&#1114111;") - 1)


typedef struct {
    u_char                    **tables;
    rap_str_t                   name;

    unsigned                    length:16;
    unsigned                    utf8:1;
} rap_http_charset_t;


typedef struct {
    rap_int_t                   src;
    rap_int_t                   dst;
} rap_http_charset_recode_t;


typedef struct {
    rap_int_t                   src;
    rap_int_t                   dst;
    u_char                     *src2dst;
    u_char                     *dst2src;
} rap_http_charset_tables_t;


typedef struct {
    rap_array_t                 charsets;       /* rap_http_charset_t */
    rap_array_t                 tables;         /* rap_http_charset_tables_t */
    rap_array_t                 recodes;        /* rap_http_charset_recode_t */
} rap_http_charset_main_conf_t;


typedef struct {
    rap_int_t                   charset;
    rap_int_t                   source_charset;
    rap_flag_t                  override_charset;

    rap_hash_t                  types;
    rap_array_t                *types_keys;
} rap_http_charset_loc_conf_t;


typedef struct {
    u_char                     *table;
    rap_int_t                   charset;
    rap_str_t                   charset_name;

    rap_chain_t                *busy;
    rap_chain_t                *free_bufs;
    rap_chain_t                *free_buffers;

    size_t                      saved_len;
    u_char                      saved[RAP_UTF_LEN];

    unsigned                    length:16;
    unsigned                    from_utf8:1;
    unsigned                    to_utf8:1;
} rap_http_charset_ctx_t;


typedef struct {
    rap_http_charset_tables_t  *table;
    rap_http_charset_t         *charset;
    rap_uint_t                  characters;
} rap_http_charset_conf_ctx_t;


static rap_int_t rap_http_destination_charset(rap_http_request_t *r,
    rap_str_t *name);
static rap_int_t rap_http_main_request_charset(rap_http_request_t *r,
    rap_str_t *name);
static rap_int_t rap_http_source_charset(rap_http_request_t *r,
    rap_str_t *name);
static rap_int_t rap_http_get_charset(rap_http_request_t *r, rap_str_t *name);
static rap_inline void rap_http_set_charset(rap_http_request_t *r,
    rap_str_t *charset);
static rap_int_t rap_http_charset_ctx(rap_http_request_t *r,
    rap_http_charset_t *charsets, rap_int_t charset, rap_int_t source_charset);
static rap_uint_t rap_http_charset_recode(rap_buf_t *b, u_char *table);
static rap_chain_t *rap_http_charset_recode_from_utf8(rap_pool_t *pool,
    rap_buf_t *buf, rap_http_charset_ctx_t *ctx);
static rap_chain_t *rap_http_charset_recode_to_utf8(rap_pool_t *pool,
    rap_buf_t *buf, rap_http_charset_ctx_t *ctx);

static rap_chain_t *rap_http_charset_get_buf(rap_pool_t *pool,
    rap_http_charset_ctx_t *ctx);
static rap_chain_t *rap_http_charset_get_buffer(rap_pool_t *pool,
    rap_http_charset_ctx_t *ctx, size_t size);

static char *rap_http_charset_map_block(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_charset_map(rap_conf_t *cf, rap_command_t *dummy,
    void *conf);

static char *rap_http_set_charset_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_add_charset(rap_array_t *charsets, rap_str_t *name);

static void *rap_http_charset_create_main_conf(rap_conf_t *cf);
static void *rap_http_charset_create_loc_conf(rap_conf_t *cf);
static char *rap_http_charset_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_charset_postconfiguration(rap_conf_t *cf);


static rap_str_t  rap_http_charset_default_types[] = {
    rap_string("text/html"),
    rap_string("text/xml"),
    rap_string("text/plain"),
    rap_string("text/vnd.wap.wml"),
    rap_string("application/javascript"),
    rap_string("application/rss+xml"),
    rap_null_string
};


static rap_command_t  rap_http_charset_filter_commands[] = {

    { rap_string("charset"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF
                        |RAP_HTTP_LIF_CONF|RAP_CONF_TAKE1,
      rap_http_set_charset_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_charset_loc_conf_t, charset),
      NULL },

    { rap_string("source_charset"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF
                        |RAP_HTTP_LIF_CONF|RAP_CONF_TAKE1,
      rap_http_set_charset_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_charset_loc_conf_t, source_charset),
      NULL },

    { rap_string("override_charset"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF
                        |RAP_HTTP_LIF_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_charset_loc_conf_t, override_charset),
      NULL },

    { rap_string("charset_types"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_types_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_charset_loc_conf_t, types_keys),
      &rap_http_charset_default_types[0] },

    { rap_string("charset_map"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_TAKE2,
      rap_http_charset_map_block,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_charset_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_charset_postconfiguration,    /* postconfiguration */

    rap_http_charset_create_main_conf,     /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_charset_create_loc_conf,      /* create location configuration */
    rap_http_charset_merge_loc_conf        /* merge location configuration */
};


rap_module_t  rap_http_charset_filter_module = {
    RAP_MODULE_V1,
    &rap_http_charset_filter_module_ctx,   /* module context */
    rap_http_charset_filter_commands,      /* module directives */
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
rap_http_charset_header_filter(rap_http_request_t *r)
{
    rap_int_t                      charset, source_charset;
    rap_str_t                      dst, src;
    rap_http_charset_t            *charsets;
    rap_http_charset_main_conf_t  *mcf;

    if (r == r->main) {
        charset = rap_http_destination_charset(r, &dst);

    } else {
        charset = rap_http_main_request_charset(r, &dst);
    }

    if (charset == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (charset == RAP_DECLINED) {
        return rap_http_next_header_filter(r);
    }

    /* charset: charset index or RAP_HTTP_NO_CHARSET */

    source_charset = rap_http_source_charset(r, &src);

    if (source_charset == RAP_ERROR) {
        return RAP_ERROR;
    }

    /*
     * source_charset: charset index, RAP_HTTP_NO_CHARSET,
     *                 or RAP_HTTP_CHARSET_OFF
     */

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "charset: \"%V\" > \"%V\"", &src, &dst);

    if (source_charset == RAP_HTTP_CHARSET_OFF) {
        rap_http_set_charset(r, &dst);

        return rap_http_next_header_filter(r);
    }

    if (charset == RAP_HTTP_NO_CHARSET
        || source_charset == RAP_HTTP_NO_CHARSET)
    {
        if (source_charset != charset
            || rap_strncasecmp(dst.data, src.data, dst.len) != 0)
        {
            goto no_charset_map;
        }

        rap_http_set_charset(r, &dst);

        return rap_http_next_header_filter(r);
    }

    if (source_charset == charset) {
        r->headers_out.content_type.len = r->headers_out.content_type_len;

        rap_http_set_charset(r, &dst);

        return rap_http_next_header_filter(r);
    }

    /* source_charset != charset */

    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len)
    {
        return rap_http_next_header_filter(r);
    }

    mcf = rap_http_get_module_main_conf(r, rap_http_charset_filter_module);
    charsets = mcf->charsets.elts;

    if (charsets[source_charset].tables == NULL
        || charsets[source_charset].tables[charset] == NULL)
    {
        goto no_charset_map;
    }

    r->headers_out.content_type.len = r->headers_out.content_type_len;

    rap_http_set_charset(r, &dst);

    return rap_http_charset_ctx(r, charsets, charset, source_charset);

no_charset_map:

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                  &src, &dst);

    return rap_http_next_header_filter(r);
}


static rap_int_t
rap_http_destination_charset(rap_http_request_t *r, rap_str_t *name)
{
    rap_int_t                      charset;
    rap_http_charset_t            *charsets;
    rap_http_variable_value_t     *vv;
    rap_http_charset_loc_conf_t   *mlcf;
    rap_http_charset_main_conf_t  *mcf;

    if (r->headers_out.content_type.len == 0) {
        return RAP_DECLINED;
    }

    if (r->headers_out.override_charset
        && r->headers_out.override_charset->len)
    {
        *name = *r->headers_out.override_charset;

        charset = rap_http_get_charset(r, name);

        if (charset != RAP_HTTP_NO_CHARSET) {
            return charset;
        }

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "unknown charset \"%V\" to override", name);

        return RAP_DECLINED;
    }

    mlcf = rap_http_get_module_loc_conf(r, rap_http_charset_filter_module);
    charset = mlcf->charset;

    if (charset == RAP_HTTP_CHARSET_OFF) {
        return RAP_DECLINED;
    }

    if (r->headers_out.charset.len) {
        if (mlcf->override_charset == 0) {
            return RAP_DECLINED;
        }

    } else {
        if (rap_http_test_content_type(r, &mlcf->types) == NULL) {
            return RAP_DECLINED;
        }
    }

    if (charset < RAP_HTTP_CHARSET_VAR) {
        mcf = rap_http_get_module_main_conf(r, rap_http_charset_filter_module);
        charsets = mcf->charsets.elts;
        *name = charsets[charset].name;
        return charset;
    }

    vv = rap_http_get_indexed_variable(r, charset - RAP_HTTP_CHARSET_VAR);

    if (vv == NULL || vv->not_found) {
        return RAP_ERROR;
    }

    name->len = vv->len;
    name->data = vv->data;

    return rap_http_get_charset(r, name);
}


static rap_int_t
rap_http_main_request_charset(rap_http_request_t *r, rap_str_t *src)
{
    rap_int_t                charset;
    rap_str_t               *main_charset;
    rap_http_charset_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r->main, rap_http_charset_filter_module);

    if (ctx) {
        *src = ctx->charset_name;
        return ctx->charset;
    }

    main_charset = &r->main->headers_out.charset;

    if (main_charset->len == 0) {
        return RAP_DECLINED;
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_charset_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r->main, ctx, rap_http_charset_filter_module);

    charset = rap_http_get_charset(r, main_charset);

    ctx->charset = charset;
    ctx->charset_name = *main_charset;
    *src = *main_charset;

    return charset;
}


static rap_int_t
rap_http_source_charset(rap_http_request_t *r, rap_str_t *name)
{
    rap_int_t                      charset;
    rap_http_charset_t            *charsets;
    rap_http_variable_value_t     *vv;
    rap_http_charset_loc_conf_t   *lcf;
    rap_http_charset_main_conf_t  *mcf;

    if (r->headers_out.charset.len) {
        *name = r->headers_out.charset;
        return rap_http_get_charset(r, name);
    }

    lcf = rap_http_get_module_loc_conf(r, rap_http_charset_filter_module);

    charset = lcf->source_charset;

    if (charset == RAP_HTTP_CHARSET_OFF) {
        name->len = 0;
        return charset;
    }

    if (charset < RAP_HTTP_CHARSET_VAR) {
        mcf = rap_http_get_module_main_conf(r, rap_http_charset_filter_module);
        charsets = mcf->charsets.elts;
        *name = charsets[charset].name;
        return charset;
    }

    vv = rap_http_get_indexed_variable(r, charset - RAP_HTTP_CHARSET_VAR);

    if (vv == NULL || vv->not_found) {
        return RAP_ERROR;
    }

    name->len = vv->len;
    name->data = vv->data;

    return rap_http_get_charset(r, name);
}


static rap_int_t
rap_http_get_charset(rap_http_request_t *r, rap_str_t *name)
{
    rap_uint_t                     i, n;
    rap_http_charset_t            *charset;
    rap_http_charset_main_conf_t  *mcf;

    mcf = rap_http_get_module_main_conf(r, rap_http_charset_filter_module);

    charset = mcf->charsets.elts;
    n = mcf->charsets.nelts;

    for (i = 0; i < n; i++) {
        if (charset[i].name.len != name->len) {
            continue;
        }

        if (rap_strncasecmp(charset[i].name.data, name->data, name->len) == 0) {
            return i;
        }
    }

    return RAP_HTTP_NO_CHARSET;
}


static rap_inline void
rap_http_set_charset(rap_http_request_t *r, rap_str_t *charset)
{
    if (r != r->main) {
        return;
    }

    if (r->headers_out.status == RAP_HTTP_MOVED_PERMANENTLY
        || r->headers_out.status == RAP_HTTP_MOVED_TEMPORARILY)
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


static rap_int_t
rap_http_charset_ctx(rap_http_request_t *r, rap_http_charset_t *charsets,
    rap_int_t charset, rap_int_t source_charset)
{
    rap_http_charset_ctx_t  *ctx;

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_charset_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_charset_filter_module);

    ctx->table = charsets[source_charset].tables[charset];
    ctx->charset = charset;
    ctx->charset_name = charsets[charset].name;
    ctx->length = charsets[charset].length;
    ctx->from_utf8 = charsets[source_charset].utf8;
    ctx->to_utf8 = charsets[charset].utf8;

    r->filter_need_in_memory = 1;

    if ((ctx->to_utf8 || ctx->from_utf8) && r == r->main) {
        rap_http_clear_content_length(r);

    } else {
        r->filter_need_temporary = 1;
    }

    return rap_http_next_header_filter(r);
}


static rap_int_t
rap_http_charset_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_int_t                rc;
    rap_buf_t               *b;
    rap_chain_t             *cl, *out, **ll;
    rap_http_charset_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_charset_filter_module);

    if (ctx == NULL || ctx->table == NULL) {
        return rap_http_next_body_filter(r, in);
    }

    if ((ctx->to_utf8 || ctx->from_utf8) || ctx->busy) {

        out = NULL;
        ll = &out;

        for (cl = in; cl; cl = cl->next) {
            b = cl->buf;

            if (rap_buf_size(b) == 0) {

                *ll = rap_alloc_chain_link(r->pool);
                if (*ll == NULL) {
                    return RAP_ERROR;
                }

                (*ll)->buf = b;
                (*ll)->next = NULL;

                ll = &(*ll)->next;

                continue;
            }

            if (ctx->to_utf8) {
                *ll = rap_http_charset_recode_to_utf8(r->pool, b, ctx);

            } else {
                *ll = rap_http_charset_recode_from_utf8(r->pool, b, ctx);
            }

            if (*ll == NULL) {
                return RAP_ERROR;
            }

            while (*ll) {
                ll = &(*ll)->next;
            }
        }

        rc = rap_http_next_body_filter(r, out);

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

            if (rap_buf_size(b) != 0) {
                break;
            }

            ctx->busy = cl->next;

            if (b->tag != (rap_buf_tag_t) &rap_http_charset_filter_module) {
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
        (void) rap_http_charset_recode(cl->buf, ctx->table);
    }

    return rap_http_next_body_filter(r, in);
}


static rap_uint_t
rap_http_charset_recode(rap_buf_t *b, u_char *table)
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


static rap_chain_t *
rap_http_charset_recode_from_utf8(rap_pool_t *pool, rap_buf_t *buf,
    rap_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char        c, *p, *src, *dst, *saved, **table;
    uint32_t      n;
    rap_buf_t    *b;
    rap_uint_t    i;
    rap_chain_t  *out, *cl, **ll;

    src = buf->pos;

    if (ctx->saved_len == 0) {

        for ( /* void */ ; src < buf->last; src++) {

            if (*src < 0x80) {
                continue;
            }

            len = src - buf->pos;

            if (len > 512) {
                out = rap_http_charset_get_buf(pool, ctx);
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
                n = rap_utf8_decode(&saved, size);

                if (n == 0xfffffffe) {
                    /* incomplete UTF-8 symbol */

                    rap_memcpy(ctx->saved, src, size);
                    ctx->saved_len = size;

                    b->shadow = buf;

                    return out;
                }

            } else {
                out = NULL;
                size = len + buf->last - src;
                src = buf->pos;
            }

            if (size < RAP_HTML_ENTITY_LEN) {
                size += RAP_HTML_ENTITY_LEN;
            }

            cl = rap_http_charset_get_buffer(pool, ctx, size);
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

        out = rap_alloc_chain_link(pool);
        if (out == NULL) {
            return NULL;
        }

        out->buf = buf;
        out->next = NULL;

        return out;
    }

    /* process incomplete UTF sequence from previous buffer */

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, pool->log, 0,
                   "http charset utf saved: %z", ctx->saved_len);

    p = src;

    for (i = ctx->saved_len; i < RAP_UTF_LEN; i++) {
        ctx->saved[i] = *p++;

        if (p == buf->last) {
            break;
        }
    }

    saved = ctx->saved;
    n = rap_utf8_decode(&saved, i);

    c = '\0';

    if (n < 0x10000) {
        table = (u_char **) ctx->table;
        p = table[n >> 8];

        if (p) {
            c = p[n & 0xff];
        }

    } else if (n == 0xfffffffe) {

        /* incomplete UTF-8 symbol */

        if (i < RAP_UTF_LEN) {
            out = rap_http_charset_get_buf(pool, ctx);
            if (out == NULL) {
                return NULL;
            }

            b = out->buf;

            b->pos = buf->pos;
            b->last = buf->last;
            b->sync = 1;
            b->shadow = buf;

            rap_memcpy(&ctx->saved[ctx->saved_len], src, i);
            ctx->saved_len += i;

            return out;
        }
    }

    size = buf->last - buf->pos;

    if (size < RAP_HTML_ENTITY_LEN) {
        size += RAP_HTML_ENTITY_LEN;
    }

    cl = rap_http_charset_get_buffer(pool, ctx, size);
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

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 0");

        saved = &ctx->saved[RAP_UTF_LEN];

    } else if (n > 0x10ffff) {
        *dst++ = '?';

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, pool->log, 0,
                       "http charset invalid utf 1");

    } else {
        dst = rap_sprintf(dst, "&#%uD;", n);
    }

    src += (saved - ctx->saved) - ctx->saved_len;
    ctx->saved_len = 0;

recode:

    ll = &cl->next;

    table = (u_char **) ctx->table;

    while (src < buf->last) {

        if ((size_t) (b->end - dst) < RAP_HTML_ENTITY_LEN) {
            b->last = dst;

            size = buf->last - src + RAP_HTML_ENTITY_LEN;

            cl = rap_http_charset_get_buffer(pool, ctx, size);
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

        n = rap_utf8_decode(&src, len);

        if (n < 0x10000) {

            p = table[n >> 8];

            if (p) {
                c = p[n & 0xff];

                if (c) {
                    *dst++ = c;
                    continue;
                }
            }

            dst = rap_sprintf(dst, "&#%uD;", n);

            continue;
        }

        if (n == 0xfffffffe) {
            /* incomplete UTF-8 symbol */

            rap_memcpy(ctx->saved, src, len);
            ctx->saved_len = len;

            if (b->pos == dst) {
                b->sync = 1;
                b->temporary = 0;
            }

            break;
        }

        if (n > 0x10ffff) {
            *dst++ = '?';

            rap_log_debug0(RAP_LOG_DEBUG_HTTP, pool->log, 0,
                           "http charset invalid utf 2");

            continue;
        }

        /* n > 0xffff */

        dst = rap_sprintf(dst, "&#%uD;", n);
    }

    b->last = dst;

    b->last_buf = buf->last_buf;
    b->last_in_chain = buf->last_in_chain;
    b->flush = buf->flush;

    b->shadow = buf;

    return out;
}


static rap_chain_t *
rap_http_charset_recode_to_utf8(rap_pool_t *pool, rap_buf_t *buf,
    rap_http_charset_ctx_t *ctx)
{
    size_t        len, size;
    u_char       *p, *src, *dst, *table;
    rap_buf_t    *b;
    rap_chain_t  *out, *cl, **ll;

    table = ctx->table;

    for (src = buf->pos; src < buf->last; src++) {
        if (table[*src * RAP_UTF_LEN] == '\1') {
            continue;
        }

        goto recode;
    }

    out = rap_alloc_chain_link(pool);
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
        out = rap_http_charset_get_buf(pool, ctx);
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

    cl = rap_http_charset_get_buffer(pool, ctx, size);
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

        p = &table[*src++ * RAP_UTF_LEN];
        len = *p++;

        if ((size_t) (b->end - dst) < len) {
            b->last = dst;

            size = buf->last - src;
            size = len + size / 2 + size / 2 * ctx->length;

            cl = rap_http_charset_get_buffer(pool, ctx, size);
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


static rap_chain_t *
rap_http_charset_get_buf(rap_pool_t *pool, rap_http_charset_ctx_t *ctx)
{
    rap_chain_t  *cl;

    cl = ctx->free_bufs;

    if (cl) {
        ctx->free_bufs = cl->next;

        cl->buf->shadow = NULL;
        cl->next = NULL;

        return cl;
    }

    cl = rap_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = rap_calloc_buf(pool);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->tag = (rap_buf_tag_t) &rap_http_charset_filter_module;

    return cl;
}


static rap_chain_t *
rap_http_charset_get_buffer(rap_pool_t *pool, rap_http_charset_ctx_t *ctx,
    size_t size)
{
    rap_buf_t    *b;
    rap_chain_t  *cl, **ll;

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

    cl = rap_alloc_chain_link(pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = rap_create_temp_buf(pool, size);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    cl->buf->temporary = 1;
    cl->buf->tag = (rap_buf_tag_t) &rap_http_charset_filter_module;

    return cl;
}


static char *
rap_http_charset_map_block(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_charset_main_conf_t  *mcf = conf;

    char                         *rv;
    u_char                       *p, *dst2src, **pp;
    rap_int_t                     src, dst;
    rap_uint_t                    i, n;
    rap_str_t                    *value;
    rap_conf_t                    pvcf;
    rap_http_charset_t           *charset;
    rap_http_charset_tables_t    *table;
    rap_http_charset_conf_ctx_t   ctx;

    value = cf->args->elts;

    src = rap_http_add_charset(&mcf->charsets, &value[1]);
    if (src == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    dst = rap_http_add_charset(&mcf->charsets, &value[2]);
    if (dst == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    if (src == dst) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"charset_map\" between the same charsets "
                           "\"%V\" and \"%V\"", &value[1], &value[2]);
        return RAP_CONF_ERROR;
    }

    table = mcf->tables.elts;
    for (i = 0; i < mcf->tables.nelts; i++) {
        if ((src == table->src && dst == table->dst)
             || (src == table->dst && dst == table->src))
        {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "duplicate \"charset_map\" between "
                               "\"%V\" and \"%V\"", &value[1], &value[2]);
            return RAP_CONF_ERROR;
        }
    }

    table = rap_array_push(&mcf->tables);
    if (table == NULL) {
        return RAP_CONF_ERROR;
    }

    table->src = src;
    table->dst = dst;

    if (rap_strcasecmp(value[2].data, (u_char *) "utf-8") == 0) {
        table->src2dst = rap_pcalloc(cf->pool, 256 * RAP_UTF_LEN);
        if (table->src2dst == NULL) {
            return RAP_CONF_ERROR;
        }

        table->dst2src = rap_pcalloc(cf->pool, 256 * sizeof(void *));
        if (table->dst2src == NULL) {
            return RAP_CONF_ERROR;
        }

        dst2src = rap_pcalloc(cf->pool, 256);
        if (dst2src == NULL) {
            return RAP_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];
        pp[0] = dst2src;

        for (i = 0; i < 128; i++) {
            p = &table->src2dst[i * RAP_UTF_LEN];
            p[0] = '\1';
            p[1] = (u_char) i;
            dst2src[i] = (u_char) i;
        }

        for (/* void */; i < 256; i++) {
            p = &table->src2dst[i * RAP_UTF_LEN];
            p[0] = '\1';
            p[1] = '?';
        }

    } else {
        table->src2dst = rap_palloc(cf->pool, 256);
        if (table->src2dst == NULL) {
            return RAP_CONF_ERROR;
        }

        table->dst2src = rap_palloc(cf->pool, 256);
        if (table->dst2src == NULL) {
            return RAP_CONF_ERROR;
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
    cf->handler = rap_http_charset_map;
    cf->handler_conf = conf;

    rv = rap_conf_parse(cf, NULL);

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
rap_http_charset_map(rap_conf_t *cf, rap_command_t *dummy, void *conf)
{
    u_char                       *p, *dst2src, **pp;
    uint32_t                      n;
    rap_int_t                     src, dst;
    rap_str_t                    *value;
    rap_uint_t                    i;
    rap_http_charset_tables_t    *table;
    rap_http_charset_conf_ctx_t  *ctx;

    if (cf->args->nelts != 2) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid parameters number");
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    src = rap_hextoi(value[0].data, value[0].len);
    if (src == RAP_ERROR || src > 255) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid value \"%V\"", &value[0]);
        return RAP_CONF_ERROR;
    }

    ctx = cf->ctx;
    table = ctx->table;

    if (ctx->charset->utf8) {
        p = &table->src2dst[src * RAP_UTF_LEN];

        *p++ = (u_char) (value[1].len / 2);

        for (i = 0; i < value[1].len; i += 2) {
            dst = rap_hextoi(&value[1].data[i], 2);
            if (dst == RAP_ERROR || dst > 255) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[1]);
                return RAP_CONF_ERROR;
            }

            *p++ = (u_char) dst;
        }

        i /= 2;

        ctx->charset->length += i;
        ctx->characters++;

        p = &table->src2dst[src * RAP_UTF_LEN] + 1;

        n = rap_utf8_decode(&p, i);

        if (n > 0xffff) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        pp = (u_char **) &table->dst2src[0];

        dst2src = pp[n >> 8];

        if (dst2src == NULL) {
            dst2src = rap_pcalloc(cf->pool, 256);
            if (dst2src == NULL) {
                return RAP_CONF_ERROR;
            }

            pp[n >> 8] = dst2src;
        }

        dst2src[n & 0xff] = (u_char) src;

    } else {
        dst = rap_hextoi(value[1].data, value[1].len);
        if (dst == RAP_ERROR || dst > 255) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        table->src2dst[src] = (u_char) dst;
        table->dst2src[dst] = (u_char) src;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_set_charset_slot(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_int_t                     *cp;
    rap_str_t                     *value, var;
    rap_http_charset_main_conf_t  *mcf;

    cp = (rap_int_t *) (p + cmd->offset);

    if (*cp != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cmd->offset == offsetof(rap_http_charset_loc_conf_t, charset)
        && rap_strcmp(value[1].data, "off") == 0)
    {
        *cp = RAP_HTTP_CHARSET_OFF;
        return RAP_CONF_OK;
    }


    if (value[1].data[0] == '$') {
        var.len = value[1].len - 1;
        var.data = value[1].data + 1;

        *cp = rap_http_get_variable_index(cf, &var);

        if (*cp == RAP_ERROR) {
            return RAP_CONF_ERROR;
        }

        *cp += RAP_HTTP_CHARSET_VAR;

        return RAP_CONF_OK;
    }

    mcf = rap_http_conf_get_module_main_conf(cf,
                                             rap_http_charset_filter_module);

    *cp = rap_http_add_charset(&mcf->charsets, &value[1]);
    if (*cp == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_add_charset(rap_array_t *charsets, rap_str_t *name)
{
    rap_uint_t           i;
    rap_http_charset_t  *c;

    c = charsets->elts;
    for (i = 0; i < charsets->nelts; i++) {
        if (name->len != c[i].name.len) {
            continue;
        }

        if (rap_strcasecmp(name->data, c[i].name.data) == 0) {
            break;
        }
    }

    if (i < charsets->nelts) {
        return i;
    }

    c = rap_array_push(charsets);
    if (c == NULL) {
        return RAP_ERROR;
    }

    c->tables = NULL;
    c->name = *name;
    c->length = 0;

    if (rap_strcasecmp(name->data, (u_char *) "utf-8") == 0) {
        c->utf8 = 1;

    } else {
        c->utf8 = 0;
    }

    return i;
}


static void *
rap_http_charset_create_main_conf(rap_conf_t *cf)
{
    rap_http_charset_main_conf_t  *mcf;

    mcf = rap_pcalloc(cf->pool, sizeof(rap_http_charset_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    if (rap_array_init(&mcf->charsets, cf->pool, 2, sizeof(rap_http_charset_t))
        != RAP_OK)
    {
        return NULL;
    }

    if (rap_array_init(&mcf->tables, cf->pool, 1,
                       sizeof(rap_http_charset_tables_t))
        != RAP_OK)
    {
        return NULL;
    }

    if (rap_array_init(&mcf->recodes, cf->pool, 2,
                       sizeof(rap_http_charset_recode_t))
        != RAP_OK)
    {
        return NULL;
    }

    return mcf;
}


static void *
rap_http_charset_create_loc_conf(rap_conf_t *cf)
{
    rap_http_charset_loc_conf_t  *lcf;

    lcf = rap_pcalloc(cf->pool, sizeof(rap_http_charset_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     lcf->types = { NULL };
     *     lcf->types_keys = NULL;
     */

    lcf->charset = RAP_CONF_UNSET;
    lcf->source_charset = RAP_CONF_UNSET;
    lcf->override_charset = RAP_CONF_UNSET;

    return lcf;
}


static char *
rap_http_charset_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_charset_loc_conf_t *prev = parent;
    rap_http_charset_loc_conf_t *conf = child;

    rap_uint_t                     i;
    rap_http_charset_recode_t     *recode;
    rap_http_charset_main_conf_t  *mcf;

    if (rap_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rap_http_charset_default_types)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_value(conf->override_charset, prev->override_charset, 0);
    rap_conf_merge_value(conf->charset, prev->charset, RAP_HTTP_CHARSET_OFF);
    rap_conf_merge_value(conf->source_charset, prev->source_charset,
                         RAP_HTTP_CHARSET_OFF);

    if (conf->charset == RAP_HTTP_CHARSET_OFF
        || conf->source_charset == RAP_HTTP_CHARSET_OFF
        || conf->charset == conf->source_charset)
    {
        return RAP_CONF_OK;
    }

    if (conf->source_charset >= RAP_HTTP_CHARSET_VAR
        || conf->charset >= RAP_HTTP_CHARSET_VAR)
    {
        return RAP_CONF_OK;
    }

    mcf = rap_http_conf_get_module_main_conf(cf,
                                             rap_http_charset_filter_module);
    recode = mcf->recodes.elts;
    for (i = 0; i < mcf->recodes.nelts; i++) {
        if (conf->source_charset == recode[i].src
            && conf->charset == recode[i].dst)
        {
            return RAP_CONF_OK;
        }
    }

    recode = rap_array_push(&mcf->recodes);
    if (recode == NULL) {
        return RAP_CONF_ERROR;
    }

    recode->src = conf->source_charset;
    recode->dst = conf->charset;

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_charset_postconfiguration(rap_conf_t *cf)
{
    u_char                       **src, **dst;
    rap_int_t                      c;
    rap_uint_t                     i, t;
    rap_http_charset_t            *charset;
    rap_http_charset_recode_t     *recode;
    rap_http_charset_tables_t     *tables;
    rap_http_charset_main_conf_t  *mcf;

    mcf = rap_http_conf_get_module_main_conf(cf,
                                             rap_http_charset_filter_module);

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

        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                   "no \"charset_map\" between the charsets \"%V\" and \"%V\"",
                   &charset[c].name, &charset[recode[i].dst].name);
        return RAP_ERROR;

    next:
        continue;
    }


    for (t = 0; t < mcf->tables.nelts; t++) {

        src = charset[tables[t].src].tables;

        if (src == NULL) {
            src = rap_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (src == NULL) {
                return RAP_ERROR;
            }

            charset[tables[t].src].tables = src;
        }

        dst = charset[tables[t].dst].tables;

        if (dst == NULL) {
            dst = rap_pcalloc(cf->pool, sizeof(u_char *) * mcf->charsets.nelts);
            if (dst == NULL) {
                return RAP_ERROR;
            }

            charset[tables[t].dst].tables = dst;
        }

        src[tables[t].dst] = tables[t].src2dst;
        dst[tables[t].src] = tables[t].dst2src;
    }

    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_charset_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_charset_body_filter;

    return RAP_OK;
}

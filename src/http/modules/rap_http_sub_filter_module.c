
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_http_complex_value_t   match;
    rap_http_complex_value_t   value;
} rap_http_sub_pair_t;


typedef struct {
    rap_str_t                  match;
    rap_http_complex_value_t  *value;
} rap_http_sub_match_t;


typedef struct {
    rap_uint_t                 min_match_len;
    rap_uint_t                 max_match_len;

    u_char                     index[257];
    u_char                     shift[256];
} rap_http_sub_tables_t;


typedef struct {
    rap_uint_t                 dynamic; /* unsigned dynamic:1; */

    rap_array_t               *pairs;

    rap_http_sub_tables_t     *tables;

    rap_hash_t                 types;

    rap_flag_t                 once;
    rap_flag_t                 last_modified;

    rap_array_t               *types_keys;
    rap_array_t               *matches;
} rap_http_sub_loc_conf_t;


typedef struct {
    rap_str_t                  saved;
    rap_str_t                  looked;

    rap_uint_t                 once;   /* unsigned  once:1 */

    rap_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    rap_chain_t               *in;
    rap_chain_t               *out;
    rap_chain_t              **last_out;
    rap_chain_t               *busy;
    rap_chain_t               *free;

    rap_str_t                 *sub;
    rap_uint_t                 applied;

    rap_int_t                  offset;
    rap_uint_t                 index;

    rap_http_sub_tables_t     *tables;
    rap_array_t               *matches;
} rap_http_sub_ctx_t;


static rap_uint_t rap_http_sub_cmp_index;


static rap_int_t rap_http_sub_output(rap_http_request_t *r,
    rap_http_sub_ctx_t *ctx);
static rap_int_t rap_http_sub_parse(rap_http_request_t *r,
    rap_http_sub_ctx_t *ctx, rap_uint_t flush);
static rap_int_t rap_http_sub_match(rap_http_sub_ctx_t *ctx, rap_int_t start,
    rap_str_t *m);

static char * rap_http_sub_filter(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static void *rap_http_sub_create_conf(rap_conf_t *cf);
static char *rap_http_sub_merge_conf(rap_conf_t *cf,
    void *parent, void *child);
static void rap_http_sub_init_tables(rap_http_sub_tables_t *tables,
    rap_http_sub_match_t *match, rap_uint_t n);
static rap_int_t rap_http_sub_cmp_matches(const void *one, const void *two);
static rap_int_t rap_http_sub_filter_init(rap_conf_t *cf);


static rap_command_t  rap_http_sub_filter_commands[] = {

    { rap_string("sub_filter"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_http_sub_filter,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("sub_filter_types"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_types_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_sub_loc_conf_t, types_keys),
      &rap_http_html_default_types[0] },

    { rap_string("sub_filter_once"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_sub_loc_conf_t, once),
      NULL },

    { rap_string("sub_filter_last_modified"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_sub_loc_conf_t, last_modified),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_sub_create_conf,              /* create location configuration */
    rap_http_sub_merge_conf                /* merge location configuration */
};


rap_module_t  rap_http_sub_filter_module = {
    RAP_MODULE_V1,
    &rap_http_sub_filter_module_ctx,       /* module context */
    rap_http_sub_filter_commands,          /* module directives */
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
rap_http_sub_header_filter(rap_http_request_t *r)
{
    rap_str_t                *m;
    rap_uint_t                i, j, n;
    rap_http_sub_ctx_t       *ctx;
    rap_http_sub_pair_t      *pairs;
    rap_http_sub_match_t     *matches;
    rap_http_sub_loc_conf_t  *slcf;

    slcf = rap_http_get_module_loc_conf(r, rap_http_sub_filter_module);

    if (slcf->pairs == NULL
        || r->headers_out.content_length_n == 0
        || rap_http_test_content_type(r, &slcf->types) == NULL)
    {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_sub_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    if (slcf->dynamic == 0) {
        ctx->tables = slcf->tables;
        ctx->matches = slcf->matches;

    } else {
        pairs = slcf->pairs->elts;
        n = slcf->pairs->nelts;

        matches = rap_pcalloc(r->pool, sizeof(rap_http_sub_match_t) * n);
        if (matches == NULL) {
            return RAP_ERROR;
        }

        j = 0;
        for (i = 0; i < n; i++) {
            matches[j].value = &pairs[i].value;

            if (pairs[i].match.lengths == NULL) {
                matches[j].match = pairs[i].match.value;
                j++;
                continue;
            }

            m = &matches[j].match;
            if (rap_http_complex_value(r, &pairs[i].match, m) != RAP_OK) {
                return RAP_ERROR;
            }

            if (m->len == 0) {
                continue;
            }

            rap_strlow(m->data, m->data, m->len);
            j++;
        }

        if (j == 0) {
            return rap_http_next_header_filter(r);
        }

        ctx->matches = rap_palloc(r->pool, sizeof(rap_array_t));
        if (ctx->matches == NULL) {
            return RAP_ERROR;
        }

        ctx->matches->elts = matches;
        ctx->matches->nelts = j;

        ctx->tables = rap_palloc(r->pool, sizeof(rap_http_sub_tables_t));
        if (ctx->tables == NULL) {
            return RAP_ERROR;
        }

        rap_http_sub_init_tables(ctx->tables, ctx->matches->elts,
                                 ctx->matches->nelts);
    }

    ctx->saved.data = rap_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->saved.data == NULL) {
        return RAP_ERROR;
    }

    ctx->looked.data = rap_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->looked.data == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_sub_filter_module);

    ctx->offset = ctx->tables->min_match_len - 1;
    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        rap_http_clear_content_length(r);

        if (!slcf->last_modified) {
            rap_http_clear_last_modified(r);
            rap_http_clear_etag(r);

        } else {
            rap_http_weak_etag(r);
        }
    }

    return rap_http_next_header_filter(r);
}


static rap_int_t
rap_http_sub_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_int_t                  rc;
    rap_buf_t                 *b;
    rap_str_t                 *sub;
    rap_uint_t                 flush, last;
    rap_chain_t               *cl;
    rap_http_sub_ctx_t        *ctx;
    rap_http_sub_match_t      *match;
    rap_http_sub_loc_conf_t   *slcf;

    ctx = rap_http_get_module_ctx(r, rap_http_sub_filter_module);

    if (ctx == NULL) {
        return rap_http_next_body_filter(r, in);
    }

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return rap_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (rap_http_sub_output(r, ctx) == RAP_ERROR) {
                return RAP_ERROR;
            }
        }

        return rap_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (rap_chain_add_copy(r->pool, &ctx->in, in) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http sub filter \"%V\"", &r->uri);

    flush = 0;
    last = 0;

    while (ctx->in || ctx->buf) {

        if (ctx->buf == NULL) {
            ctx->buf = ctx->in->buf;
            ctx->in = ctx->in->next;
            ctx->pos = ctx->buf->pos;
        }

        if (ctx->buf->flush || ctx->buf->recycled) {
            flush = 1;
        }

        if (ctx->in == NULL) {
            last = flush;
        }

        b = NULL;

        while (ctx->pos < ctx->buf->last) {

            rc = rap_http_sub_parse(r, ctx, last);

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %i, looked: \"%V\" %p-%p",
                           rc, &ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == RAP_ERROR) {
                return rc;
            }

            if (ctx->saved.len) {

                rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: \"%V\"", &ctx->saved);

                cl = rap_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return RAP_ERROR;
                }

                b = cl->buf;

                rap_memzero(b, sizeof(rap_buf_t));

                b->pos = rap_pnalloc(r->pool, ctx->saved.len);
                if (b->pos == NULL) {
                    return RAP_ERROR;
                }

                rap_memcpy(b->pos, ctx->saved.data, ctx->saved.len);
                b->last = b->pos + ctx->saved.len;
                b->memory = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->saved.len = 0;
            }

            if (ctx->copy_start != ctx->copy_end) {

                cl = rap_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return RAP_ERROR;
                }

                b = cl->buf;

                rap_memcpy(b, ctx->buf, sizeof(rap_buf_t));

                b->pos = ctx->copy_start;
                b->last = ctx->copy_end;
                b->shadow = NULL;
                b->last_buf = 0;
                b->last_in_chain = 0;
                b->recycled = 0;

                if (b->in_file) {
                    b->file_last = b->file_pos + (b->last - ctx->buf->pos);
                    b->file_pos += b->pos - ctx->buf->pos;
                }

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            if (rc == RAP_AGAIN) {
                continue;
            }


            /* rc == RAP_OK */

            cl = rap_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return RAP_ERROR;
            }

            b = cl->buf;

            rap_memzero(b, sizeof(rap_buf_t));

            slcf = rap_http_get_module_loc_conf(r, rap_http_sub_filter_module);

            if (ctx->sub == NULL) {
                ctx->sub = rap_pcalloc(r->pool, sizeof(rap_str_t)
                                                * ctx->matches->nelts);
                if (ctx->sub == NULL) {
                    return RAP_ERROR;
                }
            }

            sub = &ctx->sub[ctx->index];

            if (sub->data == NULL) {
                match = ctx->matches->elts;

                if (rap_http_complex_value(r, match[ctx->index].value, sub)
                    != RAP_OK)
                {
                    return RAP_ERROR;
                }
            }

            if (sub->len) {
                b->memory = 1;
                b->pos = sub->data;
                b->last = sub->data + sub->len;

            } else {
                b->sync = 1;
            }

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->index = 0;
            ctx->once = slcf->once && (++ctx->applied == ctx->matches->nelts);

            continue;
        }

        if (ctx->looked.len
            && (ctx->buf->last_buf || ctx->buf->last_in_chain))
        {
            cl = rap_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return RAP_ERROR;
            }

            b = cl->buf;

            rap_memzero(b, sizeof(rap_buf_t));

            b->pos = ctx->looked.data;
            b->last = b->pos + ctx->looked.len;
            b->memory = 1;

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->looked.len = 0;
        }

        if (ctx->buf->last_buf || ctx->buf->flush || ctx->buf->sync
            || rap_buf_in_memory(ctx->buf))
        {
            if (b == NULL) {
                cl = rap_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return RAP_ERROR;
                }

                b = cl->buf;

                rap_memzero(b, sizeof(rap_buf_t));

                b->sync = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;
            }

            b->last_buf = ctx->buf->last_buf;
            b->last_in_chain = ctx->buf->last_in_chain;
            b->flush = ctx->buf->flush;
            b->shadow = ctx->buf;

            b->recycled = ctx->buf->recycled;
        }

        ctx->buf = NULL;
    }

    if (ctx->out == NULL && ctx->busy == NULL) {
        return RAP_OK;
    }

    return rap_http_sub_output(r, ctx);
}


static rap_int_t
rap_http_sub_output(rap_http_request_t *r, rap_http_sub_ctx_t *ctx)
{
    rap_int_t     rc;
    rap_buf_t    *b;
    rap_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            rap_debug_point();
            return RAP_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = rap_http_next_body_filter(r, ctx->out);

    if (ctx->busy == NULL) {
        ctx->busy = ctx->out;

    } else {
        for (cl = ctx->busy; cl->next; cl = cl->next) { /* void */ }
        cl->next = ctx->out;
    }

    ctx->out = NULL;
    ctx->last_out = &ctx->out;

    while (ctx->busy) {

        cl = ctx->busy;
        b = cl->buf;

        if (rap_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (rap_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= RAP_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~RAP_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static rap_int_t
rap_http_sub_parse(rap_http_request_t *r, rap_http_sub_ctx_t *ctx,
    rap_uint_t flush)
{
    u_char                   *p, c;
    rap_str_t                *m;
    rap_int_t                 offset, start, next, end, len, rc;
    rap_uint_t                shift, i, j;
    rap_http_sub_match_t     *match;
    rap_http_sub_tables_t    *tables;
    rap_http_sub_loc_conf_t  *slcf;

    slcf = rap_http_get_module_loc_conf(r, rap_http_sub_filter_module);
    tables = ctx->tables;
    match = ctx->matches->elts;

    offset = ctx->offset;
    end = ctx->buf->last - ctx->pos;

    if (ctx->once) {
        /* sets start and next to end */
        offset = end + (rap_int_t) tables->min_match_len - 1;
        goto again;
    }

    while (offset < end) {

        c = offset < 0 ? ctx->looked.data[ctx->looked.len + offset]
                       : ctx->pos[offset];

        c = rap_tolower(c);

        shift = tables->shift[c];
        if (shift > 0) {
            offset += shift;
            continue;
        }

        /* a potential match */

        start = offset - (rap_int_t) tables->min_match_len + 1;

        i = rap_max((rap_uint_t) tables->index[c], ctx->index);
        j = tables->index[c + 1];

        while (i != j) {

            if (slcf->once && ctx->sub && ctx->sub[i].data) {
                goto next;
            }

            m = &match[i].match;

            rc = rap_http_sub_match(ctx, start, m);

            if (rc == RAP_DECLINED) {
                goto next;
            }

            ctx->index = i;

            if (rc == RAP_AGAIN) {
                goto again;
            }

            ctx->offset = offset + (rap_int_t) m->len;
            next = start + (rap_int_t) m->len;
            end = rap_max(next, 0);
            rc = RAP_OK;

            goto done;

        next:

            i++;
        }

        offset++;
        ctx->index = 0;
    }

    if (flush) {
        for ( ;; ) {
            start = offset - (rap_int_t) tables->min_match_len + 1;

            if (start >= end) {
                break;
            }

            for (i = 0; i < ctx->matches->nelts; i++) {
                m = &match[i].match;

                if (rap_http_sub_match(ctx, start, m) == RAP_AGAIN) {
                    goto again;
                }
            }

            offset++;
        }
    }

again:

    ctx->offset = offset;
    start = offset - (rap_int_t) tables->min_match_len + 1;
    next = start;
    rc = RAP_AGAIN;

done:

    /* send [ - looked.len, start ] to client */

    ctx->saved.len = ctx->looked.len + rap_min(start, 0);
    rap_memcpy(ctx->saved.data, ctx->looked.data, ctx->saved.len);

    ctx->copy_start = ctx->pos;
    ctx->copy_end = ctx->pos + rap_max(start, 0);

    /* save [ next, end ] in looked */

    len = rap_min(next, 0);
    p = ctx->looked.data;
    p = rap_movemem(p, p + ctx->looked.len + len, - len);

    len = rap_max(next, 0);
    p = rap_cpymem(p, ctx->pos + len, end - len);
    ctx->looked.len = p - ctx->looked.data;

    /* update position */

    ctx->pos += end;
    ctx->offset -= end;

    return rc;
}


static rap_int_t
rap_http_sub_match(rap_http_sub_ctx_t *ctx, rap_int_t start, rap_str_t *m)
{
    u_char  *p, *last, *pat, *pat_end;

    pat = m->data;
    pat_end = m->data + m->len;

    if (start >= 0) {
        p = ctx->pos + start;

    } else {
        last = ctx->looked.data + ctx->looked.len;
        p = last + start;

        while (p < last && pat < pat_end) {
            if (rap_tolower(*p) != *pat) {
                return RAP_DECLINED;
            }

            p++;
            pat++;
        }

        p = ctx->pos;
    }

    while (p < ctx->buf->last && pat < pat_end) {
        if (rap_tolower(*p) != *pat) {
            return RAP_DECLINED;
        }

        p++;
        pat++;
    }

    if (pat != pat_end) {
        /* partial match */
        return RAP_AGAIN;
    }

    return RAP_OK;
}


static char *
rap_http_sub_filter(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_sub_loc_conf_t *slcf = conf;

    rap_str_t                         *value;
    rap_http_sub_pair_t               *pair;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "empty search pattern");
        return RAP_CONF_ERROR;
    }

    if (slcf->pairs == NULL) {
        slcf->pairs = rap_array_create(cf->pool, 1,
                                       sizeof(rap_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    if (slcf->pairs->nelts == 255) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "number of search patterns exceeds 255");
        return RAP_CONF_ERROR;
    }

    rap_strlow(value[1].data, value[1].data, value[1].len);

    pair = rap_array_push(slcf->pairs);
    if (pair == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &pair->match;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (ccv.complex_value->lengths != NULL) {
        slcf->dynamic = 1;

    } else {
        rap_strlow(pair->match.value.data, pair->match.value.data,
                   pair->match.value.len);
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pair->value;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static void *
rap_http_sub_create_conf(rap_conf_t *cf)
{
    rap_http_sub_loc_conf_t  *slcf;

    slcf = rap_pcalloc(cf->pool, sizeof(rap_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->dynamic = 0;
     *     conf->pairs = NULL;
     *     conf->tables = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->matches = NULL;
     */

    slcf->once = RAP_CONF_UNSET;
    slcf->last_modified = RAP_CONF_UNSET;

    return slcf;
}


static char *
rap_http_sub_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_uint_t                i, n;
    rap_http_sub_pair_t      *pairs;
    rap_http_sub_match_t     *matches;
    rap_http_sub_loc_conf_t  *prev = parent;
    rap_http_sub_loc_conf_t  *conf = child;

    rap_conf_merge_value(conf->once, prev->once, 1);
    rap_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    if (rap_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rap_http_html_default_types)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    if (conf->pairs == NULL) {
        conf->dynamic = prev->dynamic;
        conf->pairs = prev->pairs;
        conf->matches = prev->matches;
        conf->tables = prev->tables;
    }

    if (conf->pairs && conf->dynamic == 0 && conf->tables == NULL) {
        pairs = conf->pairs->elts;
        n = conf->pairs->nelts;

        matches = rap_palloc(cf->pool, sizeof(rap_http_sub_match_t) * n);
        if (matches == NULL) {
            return RAP_CONF_ERROR;
        }

        for (i = 0; i < n; i++) {
            matches[i].match = pairs[i].match.value;
            matches[i].value = &pairs[i].value;
        }

        conf->matches = rap_palloc(cf->pool, sizeof(rap_array_t));
        if (conf->matches == NULL) {
            return RAP_CONF_ERROR;
        }

        conf->matches->elts = matches;
        conf->matches->nelts = n;

        conf->tables = rap_palloc(cf->pool, sizeof(rap_http_sub_tables_t));
        if (conf->tables == NULL) {
            return RAP_CONF_ERROR;
        }

        rap_http_sub_init_tables(conf->tables, conf->matches->elts,
                                 conf->matches->nelts);
    }

    return RAP_CONF_OK;
}


static void
rap_http_sub_init_tables(rap_http_sub_tables_t *tables,
    rap_http_sub_match_t *match, rap_uint_t n)
{
    u_char      c;
    rap_uint_t  i, j, min, max, ch;

    min = match[0].match.len;
    max = match[0].match.len;

    for (i = 1; i < n; i++) {
        min = rap_min(min, match[i].match.len);
        max = rap_max(max, match[i].match.len);
    }

    tables->min_match_len = min;
    tables->max_match_len = max;

    rap_http_sub_cmp_index = tables->min_match_len - 1;
    rap_sort(match, n, sizeof(rap_http_sub_match_t), rap_http_sub_cmp_matches);

    min = rap_min(min, 255);
    rap_memset(tables->shift, min, 256);

    ch = 0;

    for (i = 0; i < n; i++) {

        for (j = 0; j < min; j++) {
            c = match[i].match.data[tables->min_match_len - 1 - j];
            tables->shift[c] = rap_min(tables->shift[c], (u_char) j);
        }

        c = match[i].match.data[tables->min_match_len - 1];
        while (ch <= (rap_uint_t) c) {
            tables->index[ch++] = (u_char) i;
        }
    }

    while (ch < 257) {
        tables->index[ch++] = (u_char) n;
    }
}


static rap_int_t
rap_http_sub_cmp_matches(const void *one, const void *two)
{
    rap_int_t              c1, c2;
    rap_http_sub_match_t  *first, *second;

    first = (rap_http_sub_match_t *) one;
    second = (rap_http_sub_match_t *) two;

    c1 = first->match.data[rap_http_sub_cmp_index];
    c2 = second->match.data[rap_http_sub_cmp_index];

    return c1 - c2;
}


static rap_int_t
rap_http_sub_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_sub_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_sub_body_filter;

    return RAP_OK;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_http_complex_value_t   match;
    rp_http_complex_value_t   value;
} rp_http_sub_pair_t;


typedef struct {
    rp_str_t                  match;
    rp_http_complex_value_t  *value;
} rp_http_sub_match_t;


typedef struct {
    rp_uint_t                 min_match_len;
    rp_uint_t                 max_match_len;

    u_char                     index[257];
    u_char                     shift[256];
} rp_http_sub_tables_t;


typedef struct {
    rp_uint_t                 dynamic; /* unsigned dynamic:1; */

    rp_array_t               *pairs;

    rp_http_sub_tables_t     *tables;

    rp_hash_t                 types;

    rp_flag_t                 once;
    rp_flag_t                 last_modified;

    rp_array_t               *types_keys;
    rp_array_t               *matches;
} rp_http_sub_loc_conf_t;


typedef struct {
    rp_str_t                  saved;
    rp_str_t                  looked;

    rp_uint_t                 once;   /* unsigned  once:1 */

    rp_buf_t                 *buf;

    u_char                    *pos;
    u_char                    *copy_start;
    u_char                    *copy_end;

    rp_chain_t               *in;
    rp_chain_t               *out;
    rp_chain_t              **last_out;
    rp_chain_t               *busy;
    rp_chain_t               *free;

    rp_str_t                 *sub;
    rp_uint_t                 applied;

    rp_int_t                  offset;
    rp_uint_t                 index;

    rp_http_sub_tables_t     *tables;
    rp_array_t               *matches;
} rp_http_sub_ctx_t;


static rp_uint_t rp_http_sub_cmp_index;


static rp_int_t rp_http_sub_output(rp_http_request_t *r,
    rp_http_sub_ctx_t *ctx);
static rp_int_t rp_http_sub_parse(rp_http_request_t *r,
    rp_http_sub_ctx_t *ctx, rp_uint_t flush);
static rp_int_t rp_http_sub_match(rp_http_sub_ctx_t *ctx, rp_int_t start,
    rp_str_t *m);

static char * rp_http_sub_filter(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static void *rp_http_sub_create_conf(rp_conf_t *cf);
static char *rp_http_sub_merge_conf(rp_conf_t *cf,
    void *parent, void *child);
static void rp_http_sub_init_tables(rp_http_sub_tables_t *tables,
    rp_http_sub_match_t *match, rp_uint_t n);
static rp_int_t rp_http_sub_cmp_matches(const void *one, const void *two);
static rp_int_t rp_http_sub_filter_init(rp_conf_t *cf);


static rp_command_t  rp_http_sub_filter_commands[] = {

    { rp_string("sub_filter"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_http_sub_filter,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("sub_filter_types"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_types_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_sub_loc_conf_t, types_keys),
      &rp_http_html_default_types[0] },

    { rp_string("sub_filter_once"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_sub_loc_conf_t, once),
      NULL },

    { rp_string("sub_filter_last_modified"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_sub_loc_conf_t, last_modified),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_sub_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_sub_filter_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_sub_create_conf,              /* create location configuration */
    rp_http_sub_merge_conf                /* merge location configuration */
};


rp_module_t  rp_http_sub_filter_module = {
    RP_MODULE_V1,
    &rp_http_sub_filter_module_ctx,       /* module context */
    rp_http_sub_filter_commands,          /* module directives */
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
rp_http_sub_header_filter(rp_http_request_t *r)
{
    rp_str_t                *m;
    rp_uint_t                i, j, n;
    rp_http_sub_ctx_t       *ctx;
    rp_http_sub_pair_t      *pairs;
    rp_http_sub_match_t     *matches;
    rp_http_sub_loc_conf_t  *slcf;

    slcf = rp_http_get_module_loc_conf(r, rp_http_sub_filter_module);

    if (slcf->pairs == NULL
        || r->headers_out.content_length_n == 0
        || rp_http_test_content_type(r, &slcf->types) == NULL)
    {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_sub_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    if (slcf->dynamic == 0) {
        ctx->tables = slcf->tables;
        ctx->matches = slcf->matches;

    } else {
        pairs = slcf->pairs->elts;
        n = slcf->pairs->nelts;

        matches = rp_pcalloc(r->pool, sizeof(rp_http_sub_match_t) * n);
        if (matches == NULL) {
            return RP_ERROR;
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
            if (rp_http_complex_value(r, &pairs[i].match, m) != RP_OK) {
                return RP_ERROR;
            }

            if (m->len == 0) {
                continue;
            }

            rp_strlow(m->data, m->data, m->len);
            j++;
        }

        if (j == 0) {
            return rp_http_next_header_filter(r);
        }

        ctx->matches = rp_palloc(r->pool, sizeof(rp_array_t));
        if (ctx->matches == NULL) {
            return RP_ERROR;
        }

        ctx->matches->elts = matches;
        ctx->matches->nelts = j;

        ctx->tables = rp_palloc(r->pool, sizeof(rp_http_sub_tables_t));
        if (ctx->tables == NULL) {
            return RP_ERROR;
        }

        rp_http_sub_init_tables(ctx->tables, ctx->matches->elts,
                                 ctx->matches->nelts);
    }

    ctx->saved.data = rp_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->saved.data == NULL) {
        return RP_ERROR;
    }

    ctx->looked.data = rp_pnalloc(r->pool, ctx->tables->max_match_len - 1);
    if (ctx->looked.data == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_sub_filter_module);

    ctx->offset = ctx->tables->min_match_len - 1;
    ctx->last_out = &ctx->out;

    r->filter_need_in_memory = 1;

    if (r == r->main) {
        rp_http_clear_content_length(r);

        if (!slcf->last_modified) {
            rp_http_clear_last_modified(r);
            rp_http_clear_etag(r);

        } else {
            rp_http_weak_etag(r);
        }
    }

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_sub_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_int_t                  rc;
    rp_buf_t                 *b;
    rp_str_t                 *sub;
    rp_uint_t                 flush, last;
    rp_chain_t               *cl;
    rp_http_sub_ctx_t        *ctx;
    rp_http_sub_match_t      *match;
    rp_http_sub_loc_conf_t   *slcf;

    ctx = rp_http_get_module_ctx(r, rp_http_sub_filter_module);

    if (ctx == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    if ((in == NULL
         && ctx->buf == NULL
         && ctx->in == NULL
         && ctx->busy == NULL))
    {
        return rp_http_next_body_filter(r, in);
    }

    if (ctx->once && (ctx->buf == NULL || ctx->in == NULL)) {

        if (ctx->busy) {
            if (rp_http_sub_output(r, ctx) == RP_ERROR) {
                return RP_ERROR;
            }
        }

        return rp_http_next_body_filter(r, in);
    }

    /* add the incoming chain to the chain ctx->in */

    if (in) {
        if (rp_chain_add_copy(r->pool, &ctx->in, in) != RP_OK) {
            return RP_ERROR;
        }
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

            rc = rp_http_sub_parse(r, ctx, last);

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "parse: %i, looked: \"%V\" %p-%p",
                           rc, &ctx->looked, ctx->copy_start, ctx->copy_end);

            if (rc == RP_ERROR) {
                return rc;
            }

            if (ctx->saved.len) {

                rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "saved: \"%V\"", &ctx->saved);

                cl = rp_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return RP_ERROR;
                }

                b = cl->buf;

                rp_memzero(b, sizeof(rp_buf_t));

                b->pos = rp_pnalloc(r->pool, ctx->saved.len);
                if (b->pos == NULL) {
                    return RP_ERROR;
                }

                rp_memcpy(b->pos, ctx->saved.data, ctx->saved.len);
                b->last = b->pos + ctx->saved.len;
                b->memory = 1;

                *ctx->last_out = cl;
                ctx->last_out = &cl->next;

                ctx->saved.len = 0;
            }

            if (ctx->copy_start != ctx->copy_end) {

                cl = rp_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return RP_ERROR;
                }

                b = cl->buf;

                rp_memcpy(b, ctx->buf, sizeof(rp_buf_t));

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

            if (rc == RP_AGAIN) {
                continue;
            }


            /* rc == RP_OK */

            cl = rp_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return RP_ERROR;
            }

            b = cl->buf;

            rp_memzero(b, sizeof(rp_buf_t));

            slcf = rp_http_get_module_loc_conf(r, rp_http_sub_filter_module);

            if (ctx->sub == NULL) {
                ctx->sub = rp_pcalloc(r->pool, sizeof(rp_str_t)
                                                * ctx->matches->nelts);
                if (ctx->sub == NULL) {
                    return RP_ERROR;
                }
            }

            sub = &ctx->sub[ctx->index];

            if (sub->data == NULL) {
                match = ctx->matches->elts;

                if (rp_http_complex_value(r, match[ctx->index].value, sub)
                    != RP_OK)
                {
                    return RP_ERROR;
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
            cl = rp_chain_get_free_buf(r->pool, &ctx->free);
            if (cl == NULL) {
                return RP_ERROR;
            }

            b = cl->buf;

            rp_memzero(b, sizeof(rp_buf_t));

            b->pos = ctx->looked.data;
            b->last = b->pos + ctx->looked.len;
            b->memory = 1;

            *ctx->last_out = cl;
            ctx->last_out = &cl->next;

            ctx->looked.len = 0;
        }

        if (ctx->buf->last_buf || ctx->buf->flush || ctx->buf->sync
            || rp_buf_in_memory(ctx->buf))
        {
            if (b == NULL) {
                cl = rp_chain_get_free_buf(r->pool, &ctx->free);
                if (cl == NULL) {
                    return RP_ERROR;
                }

                b = cl->buf;

                rp_memzero(b, sizeof(rp_buf_t));

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
        return RP_OK;
    }

    return rp_http_sub_output(r, ctx);
}


static rp_int_t
rp_http_sub_output(rp_http_request_t *r, rp_http_sub_ctx_t *ctx)
{
    rp_int_t     rc;
    rp_buf_t    *b;
    rp_chain_t  *cl;

#if 1
    b = NULL;
    for (cl = ctx->out; cl; cl = cl->next) {
        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "sub out: %p %p", cl->buf, cl->buf->pos);
        if (cl->buf == b) {
            rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                          "the same buf was used in sub");
            rp_debug_point();
            return RP_ERROR;
        }
        b = cl->buf;
    }
#endif

    rc = rp_http_next_body_filter(r, ctx->out);

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

        if (rp_buf_size(b) != 0) {
            break;
        }

        if (b->shadow) {
            b->shadow->pos = b->shadow->last;
        }

        ctx->busy = cl->next;

        if (rp_buf_in_memory(b) || b->in_file) {
            /* add data bufs only to the free buf chain */

            cl->next = ctx->free;
            ctx->free = cl;
        }
    }

    if (ctx->in || ctx->buf) {
        r->buffered |= RP_HTTP_SUB_BUFFERED;

    } else {
        r->buffered &= ~RP_HTTP_SUB_BUFFERED;
    }

    return rc;
}


static rp_int_t
rp_http_sub_parse(rp_http_request_t *r, rp_http_sub_ctx_t *ctx,
    rp_uint_t flush)
{
    u_char                   *p, c;
    rp_str_t                *m;
    rp_int_t                 offset, start, next, end, len, rc;
    rp_uint_t                shift, i, j;
    rp_http_sub_match_t     *match;
    rp_http_sub_tables_t    *tables;
    rp_http_sub_loc_conf_t  *slcf;

    slcf = rp_http_get_module_loc_conf(r, rp_http_sub_filter_module);
    tables = ctx->tables;
    match = ctx->matches->elts;

    offset = ctx->offset;
    end = ctx->buf->last - ctx->pos;

    if (ctx->once) {
        /* sets start and next to end */
        offset = end + (rp_int_t) tables->min_match_len - 1;
        goto again;
    }

    while (offset < end) {

        c = offset < 0 ? ctx->looked.data[ctx->looked.len + offset]
                       : ctx->pos[offset];

        c = rp_tolower(c);

        shift = tables->shift[c];
        if (shift > 0) {
            offset += shift;
            continue;
        }

        /* a potential match */

        start = offset - (rp_int_t) tables->min_match_len + 1;

        i = rp_max((rp_uint_t) tables->index[c], ctx->index);
        j = tables->index[c + 1];

        while (i != j) {

            if (slcf->once && ctx->sub && ctx->sub[i].data) {
                goto next;
            }

            m = &match[i].match;

            rc = rp_http_sub_match(ctx, start, m);

            if (rc == RP_DECLINED) {
                goto next;
            }

            ctx->index = i;

            if (rc == RP_AGAIN) {
                goto again;
            }

            ctx->offset = offset + (rp_int_t) m->len;
            next = start + (rp_int_t) m->len;
            end = rp_max(next, 0);
            rc = RP_OK;

            goto done;

        next:

            i++;
        }

        offset++;
        ctx->index = 0;
    }

    if (flush) {
        for ( ;; ) {
            start = offset - (rp_int_t) tables->min_match_len + 1;

            if (start >= end) {
                break;
            }

            for (i = 0; i < ctx->matches->nelts; i++) {
                m = &match[i].match;

                if (rp_http_sub_match(ctx, start, m) == RP_AGAIN) {
                    goto again;
                }
            }

            offset++;
        }
    }

again:

    ctx->offset = offset;
    start = offset - (rp_int_t) tables->min_match_len + 1;
    next = start;
    rc = RP_AGAIN;

done:

    /* send [ - looked.len, start ] to client */

    ctx->saved.len = ctx->looked.len + rp_min(start, 0);
    rp_memcpy(ctx->saved.data, ctx->looked.data, ctx->saved.len);

    ctx->copy_start = ctx->pos;
    ctx->copy_end = ctx->pos + rp_max(start, 0);

    /* save [ next, end ] in looked */

    len = rp_min(next, 0);
    p = ctx->looked.data;
    p = rp_movemem(p, p + ctx->looked.len + len, - len);

    len = rp_max(next, 0);
    p = rp_cpymem(p, ctx->pos + len, end - len);
    ctx->looked.len = p - ctx->looked.data;

    /* update position */

    ctx->pos += end;
    ctx->offset -= end;

    return rc;
}


static rp_int_t
rp_http_sub_match(rp_http_sub_ctx_t *ctx, rp_int_t start, rp_str_t *m)
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
            if (rp_tolower(*p) != *pat) {
                return RP_DECLINED;
            }

            p++;
            pat++;
        }

        p = ctx->pos;
    }

    while (p < ctx->buf->last && pat < pat_end) {
        if (rp_tolower(*p) != *pat) {
            return RP_DECLINED;
        }

        p++;
        pat++;
    }

    if (pat != pat_end) {
        /* partial match */
        return RP_AGAIN;
    }

    return RP_OK;
}


static char *
rp_http_sub_filter(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_sub_loc_conf_t *slcf = conf;

    rp_str_t                         *value;
    rp_http_sub_pair_t               *pair;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].len == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "empty search pattern");
        return RP_CONF_ERROR;
    }

    if (slcf->pairs == NULL) {
        slcf->pairs = rp_array_create(cf->pool, 1,
                                       sizeof(rp_http_sub_pair_t));
        if (slcf->pairs == NULL) {
            return RP_CONF_ERROR;
        }
    }

    if (slcf->pairs->nelts == 255) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "number of search patterns exceeds 255");
        return RP_CONF_ERROR;
    }

    rp_strlow(value[1].data, value[1].data, value[1].len);

    pair = rp_array_push(slcf->pairs);
    if (pair == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &pair->match;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (ccv.complex_value->lengths != NULL) {
        slcf->dynamic = 1;

    } else {
        rp_strlow(pair->match.value.data, pair->match.value.data,
                   pair->match.value.len);
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pair->value;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static void *
rp_http_sub_create_conf(rp_conf_t *cf)
{
    rp_http_sub_loc_conf_t  *slcf;

    slcf = rp_pcalloc(cf->pool, sizeof(rp_http_sub_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->dynamic = 0;
     *     conf->pairs = NULL;
     *     conf->tables = NULL;
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->matches = NULL;
     */

    slcf->once = RP_CONF_UNSET;
    slcf->last_modified = RP_CONF_UNSET;

    return slcf;
}


static char *
rp_http_sub_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_uint_t                i, n;
    rp_http_sub_pair_t      *pairs;
    rp_http_sub_match_t     *matches;
    rp_http_sub_loc_conf_t  *prev = parent;
    rp_http_sub_loc_conf_t  *conf = child;

    rp_conf_merge_value(conf->once, prev->once, 1);
    rp_conf_merge_value(conf->last_modified, prev->last_modified, 0);

    if (rp_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rp_http_html_default_types)
        != RP_OK)
    {
        return RP_CONF_ERROR;
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

        matches = rp_palloc(cf->pool, sizeof(rp_http_sub_match_t) * n);
        if (matches == NULL) {
            return RP_CONF_ERROR;
        }

        for (i = 0; i < n; i++) {
            matches[i].match = pairs[i].match.value;
            matches[i].value = &pairs[i].value;
        }

        conf->matches = rp_palloc(cf->pool, sizeof(rp_array_t));
        if (conf->matches == NULL) {
            return RP_CONF_ERROR;
        }

        conf->matches->elts = matches;
        conf->matches->nelts = n;

        conf->tables = rp_palloc(cf->pool, sizeof(rp_http_sub_tables_t));
        if (conf->tables == NULL) {
            return RP_CONF_ERROR;
        }

        rp_http_sub_init_tables(conf->tables, conf->matches->elts,
                                 conf->matches->nelts);
    }

    return RP_CONF_OK;
}


static void
rp_http_sub_init_tables(rp_http_sub_tables_t *tables,
    rp_http_sub_match_t *match, rp_uint_t n)
{
    u_char      c;
    rp_uint_t  i, j, min, max, ch;

    min = match[0].match.len;
    max = match[0].match.len;

    for (i = 1; i < n; i++) {
        min = rp_min(min, match[i].match.len);
        max = rp_max(max, match[i].match.len);
    }

    tables->min_match_len = min;
    tables->max_match_len = max;

    rp_http_sub_cmp_index = tables->min_match_len - 1;
    rp_sort(match, n, sizeof(rp_http_sub_match_t), rp_http_sub_cmp_matches);

    min = rp_min(min, 255);
    rp_memset(tables->shift, min, 256);

    ch = 0;

    for (i = 0; i < n; i++) {

        for (j = 0; j < min; j++) {
            c = match[i].match.data[tables->min_match_len - 1 - j];
            tables->shift[c] = rp_min(tables->shift[c], (u_char) j);
        }

        c = match[i].match.data[tables->min_match_len - 1];
        while (ch <= (rp_uint_t) c) {
            tables->index[ch++] = (u_char) i;
        }
    }

    while (ch < 257) {
        tables->index[ch++] = (u_char) n;
    }
}


static rp_int_t
rp_http_sub_cmp_matches(const void *one, const void *two)
{
    rp_int_t              c1, c2;
    rp_http_sub_match_t  *first, *second;

    first = (rp_http_sub_match_t *) one;
    second = (rp_http_sub_match_t *) two;

    c1 = first->match.data[rp_http_sub_cmp_index];
    c2 = second->match.data[rp_http_sub_cmp_index];

    return c1 - c2;
}


static rp_int_t
rp_http_sub_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_sub_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_sub_body_filter;

    return RP_OK;
}

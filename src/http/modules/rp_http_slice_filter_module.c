
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    size_t               size;
} rp_http_slice_loc_conf_t;


typedef struct {
    off_t                start;
    off_t                end;
    rp_str_t            range;
    rp_str_t            etag;
    unsigned             last:1;
    unsigned             active:1;
    rp_http_request_t  *sr;
} rp_http_slice_ctx_t;


typedef struct {
    off_t                start;
    off_t                end;
    off_t                complete_length;
} rp_http_slice_content_range_t;


static rp_int_t rp_http_slice_header_filter(rp_http_request_t *r);
static rp_int_t rp_http_slice_body_filter(rp_http_request_t *r,
    rp_chain_t *in);
static rp_int_t rp_http_slice_parse_content_range(rp_http_request_t *r,
    rp_http_slice_content_range_t *cr);
static rp_int_t rp_http_slice_range_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static off_t rp_http_slice_get_start(rp_http_request_t *r);
static void *rp_http_slice_create_loc_conf(rp_conf_t *cf);
static char *rp_http_slice_merge_loc_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_http_slice_add_variables(rp_conf_t *cf);
static rp_int_t rp_http_slice_init(rp_conf_t *cf);


static rp_command_t  rp_http_slice_filter_commands[] = {

    { rp_string("slice"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_slice_loc_conf_t, size),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_slice_filter_module_ctx = {
    rp_http_slice_add_variables,          /* preconfiguration */
    rp_http_slice_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_slice_create_loc_conf,        /* create location configuration */
    rp_http_slice_merge_loc_conf          /* merge location configuration */
};


rp_module_t  rp_http_slice_filter_module = {
    RP_MODULE_V1,
    &rp_http_slice_filter_module_ctx,     /* module context */
    rp_http_slice_filter_commands,        /* module directives */
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


static rp_str_t  rp_http_slice_range_name = rp_string("slice_range");

static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_slice_header_filter(rp_http_request_t *r)
{
    off_t                            end;
    rp_int_t                        rc;
    rp_table_elt_t                 *h;
    rp_http_slice_ctx_t            *ctx;
    rp_http_slice_loc_conf_t       *slcf;
    rp_http_slice_content_range_t   cr;

    ctx = rp_http_get_module_ctx(r, rp_http_slice_filter_module);
    if (ctx == NULL) {
        return rp_http_next_header_filter(r);
    }

    if (r->headers_out.status != RP_HTTP_PARTIAL_CONTENT) {
        if (r == r->main) {
            rp_http_set_ctx(r, NULL, rp_http_slice_filter_module);
            return rp_http_next_header_filter(r);
        }

        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return RP_ERROR;
    }

    h = r->headers_out.etag;

    if (ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || rp_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "etag mismatch in slice response");
            return RP_ERROR;
        }
    }

    if (h) {
        ctx->etag = h->value;
    }

    if (rp_http_slice_parse_content_range(r, &cr) != RP_OK) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "invalid range in slice response");
        return RP_ERROR;
    }

    if (cr.complete_length == -1) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "no complete length in slice response");
        return RP_ERROR;
    }

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice response range: %O-%O/%O",
                   cr.start, cr.end, cr.complete_length);

    slcf = rp_http_get_module_loc_conf(r, rp_http_slice_filter_module);

    end = rp_min(cr.start + (off_t) slcf->size, cr.complete_length);

    if (cr.start != ctx->start || cr.end != end) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "unexpected range in slice response: %O-%O",
                      cr.start, cr.end);
        return RP_ERROR;
    }

    ctx->start = end;
    ctx->active = 1;

    r->headers_out.status = RP_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_offset = cr.start;
    r->headers_out.content_range->hash = 0;
    r->headers_out.content_range = NULL;

    r->allow_ranges = 1;
    r->subrequest_ranges = 1;
    r->single_range = 1;

    rc = rp_http_next_header_filter(r);

    if (r != r->main) {
        return rc;
    }

    r->preserve_body = 1;

    if (r->headers_out.status == RP_HTTP_PARTIAL_CONTENT) {
        if (ctx->start + (off_t) slcf->size <= r->headers_out.content_offset) {
            ctx->start = slcf->size
                         * (r->headers_out.content_offset / slcf->size);
        }

        ctx->end = r->headers_out.content_offset
                   + r->headers_out.content_length_n;

    } else {
        ctx->end = cr.complete_length;
    }

    return rc;
}


static rp_int_t
rp_http_slice_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_int_t                   rc;
    rp_chain_t                *cl;
    rp_http_slice_ctx_t       *ctx;
    rp_http_slice_loc_conf_t  *slcf;

    ctx = rp_http_get_module_ctx(r, rp_http_slice_filter_module);

    if (ctx == NULL || r != r->main) {
        return rp_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = rp_http_next_body_filter(r, in);

    if (rc == RP_ERROR || !ctx->last) {
        return rc;
    }

    if (ctx->sr && !ctx->sr->done) {
        return rc;
    }

    if (!ctx->active) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "missing slice response");
        return RP_ERROR;
    }

    if (ctx->start >= ctx->end) {
        rp_http_set_ctx(r, NULL, rp_http_slice_filter_module);
        rp_http_send_special(r, RP_HTTP_LAST);
        return rc;
    }

    if (r->buffered) {
        return rc;
    }

    if (rp_http_subrequest(r, &r->uri, &r->args, &ctx->sr, NULL,
                            RP_HTTP_SUBREQUEST_CLONE)
        != RP_OK)
    {
        return RP_ERROR;
    }

    rp_http_set_ctx(ctx->sr, ctx, rp_http_slice_filter_module);

    slcf = rp_http_get_module_loc_conf(r, rp_http_slice_filter_module);

    ctx->range.len = rp_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start,
                                 ctx->start + (off_t) slcf->size - 1)
                     - ctx->range.data;

    ctx->active = 0;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice subrequest: \"%V\"", &ctx->range);

    return rc;
}


static rp_int_t
rp_http_slice_parse_content_range(rp_http_request_t *r,
    rp_http_slice_content_range_t *cr)
{
    off_t             start, end, complete_length, cutoff, cutlim;
    u_char           *p;
    rp_table_elt_t  *h;

    h = r->headers_out.content_range;

    if (h == NULL
        || h->value.len < 7
        || rp_strncmp(h->value.data, "bytes ", 6) != 0)
    {
        return RP_ERROR;
    }

    p = h->value.data + 6;

    cutoff = RP_MAX_OFF_T_VALUE / 10;
    cutlim = RP_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    complete_length = 0;

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return RP_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return RP_ERROR;
        }

        start = start * 10 + (*p++ - '0');
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
        return RP_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return RP_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return RP_ERROR;
        }

        end = end * 10 + (*p++ - '0');
    }

    end++;

    while (*p == ' ') { p++; }

    if (*p++ != '/') {
        return RP_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p != '*') {
        if (*p < '0' || *p > '9') {
            return RP_ERROR;
        }

        while (*p >= '0' && *p <= '9') {
            if (complete_length >= cutoff
                && (complete_length > cutoff || *p - '0' > cutlim))
            {
                return RP_ERROR;
            }

            complete_length = complete_length * 10 + (*p++ - '0');
        }

    } else {
        complete_length = -1;
        p++;
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return RP_ERROR;
    }

    cr->start = start;
    cr->end = end;
    cr->complete_length = complete_length;

    return RP_OK;
}


static rp_int_t
rp_http_slice_range_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    rp_http_slice_ctx_t       *ctx;
    rp_http_slice_loc_conf_t  *slcf;

    ctx = rp_http_get_module_ctx(r, rp_http_slice_filter_module);

    if (ctx == NULL) {
        if (r != r->main || r->headers_out.status) {
            v->not_found = 1;
            return RP_OK;
        }

        slcf = rp_http_get_module_loc_conf(r, rp_http_slice_filter_module);

        if (slcf->size == 0) {
            v->not_found = 1;
            return RP_OK;
        }

        ctx = rp_pcalloc(r->pool, sizeof(rp_http_slice_ctx_t));
        if (ctx == NULL) {
            return RP_ERROR;
        }

        rp_http_set_ctx(r, ctx, rp_http_slice_filter_module);

        p = rp_pnalloc(r->pool, sizeof("bytes=-") - 1 + 2 * RP_OFF_T_LEN);
        if (p == NULL) {
            return RP_ERROR;
        }

        ctx->start = slcf->size * (rp_http_slice_get_start(r) / slcf->size);

        ctx->range.data = p;
        ctx->range.len = rp_sprintf(p, "bytes=%O-%O", ctx->start,
                                     ctx->start + (off_t) slcf->size - 1)
                         - p;
    }

    v->data = ctx->range.data;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;
    v->len = ctx->range.len;

    return RP_OK;
}


static off_t
rp_http_slice_get_start(rp_http_request_t *r)
{
    off_t             start, cutoff, cutlim;
    u_char           *p;
    rp_table_elt_t  *h;

    if (r->headers_in.if_range) {
        return 0;
    }

    h = r->headers_in.range;

    if (h == NULL
        || h->value.len < 7
        || rp_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return 0;
    }

    p = h->value.data + 6;

    if (rp_strchr(p, ',')) {
        return 0;
    }

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return 0;
    }

    cutoff = RP_MAX_OFF_T_VALUE / 10;
    cutlim = RP_MAX_OFF_T_VALUE % 10;

    start = 0;

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return 0;
        }

        start = start * 10 + (*p++ - '0');
    }

    return start;
}


static void *
rp_http_slice_create_loc_conf(rp_conf_t *cf)
{
    rp_http_slice_loc_conf_t  *slcf;

    slcf = rp_palloc(cf->pool, sizeof(rp_http_slice_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->size = RP_CONF_UNSET_SIZE;

    return slcf;
}


static char *
rp_http_slice_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_slice_loc_conf_t *prev = parent;
    rp_http_slice_loc_conf_t *conf = child;

    rp_conf_merge_size_value(conf->size, prev->size, 0);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_slice_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var;

    var = rp_http_add_variable(cf, &rp_http_slice_range_name, 0);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_slice_range_variable;

    return RP_OK;
}


static rp_int_t
rp_http_slice_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_slice_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_slice_body_filter;

    return RP_OK;
}

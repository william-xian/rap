
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    size_t               size;
} rap_http_slice_loc_conf_t;


typedef struct {
    off_t                start;
    off_t                end;
    rap_str_t            range;
    rap_str_t            etag;
    unsigned             last:1;
    unsigned             active:1;
    rap_http_request_t  *sr;
} rap_http_slice_ctx_t;


typedef struct {
    off_t                start;
    off_t                end;
    off_t                complete_length;
} rap_http_slice_content_range_t;


static rap_int_t rap_http_slice_header_filter(rap_http_request_t *r);
static rap_int_t rap_http_slice_body_filter(rap_http_request_t *r,
    rap_chain_t *in);
static rap_int_t rap_http_slice_parse_content_range(rap_http_request_t *r,
    rap_http_slice_content_range_t *cr);
static rap_int_t rap_http_slice_range_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static off_t rap_http_slice_get_start(rap_http_request_t *r);
static void *rap_http_slice_create_loc_conf(rap_conf_t *cf);
static char *rap_http_slice_merge_loc_conf(rap_conf_t *cf, void *parent,
    void *child);
static rap_int_t rap_http_slice_add_variables(rap_conf_t *cf);
static rap_int_t rap_http_slice_init(rap_conf_t *cf);


static rap_command_t  rap_http_slice_filter_commands[] = {

    { rap_string("slice"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_slice_loc_conf_t, size),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_slice_filter_module_ctx = {
    rap_http_slice_add_variables,          /* preconfiguration */
    rap_http_slice_init,                   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_slice_create_loc_conf,        /* create location configuration */
    rap_http_slice_merge_loc_conf          /* merge location configuration */
};


rap_module_t  rap_http_slice_filter_module = {
    RAP_MODULE_V1,
    &rap_http_slice_filter_module_ctx,     /* module context */
    rap_http_slice_filter_commands,        /* module directives */
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


static rap_str_t  rap_http_slice_range_name = rap_string("slice_range");

static rap_http_output_header_filter_pt  rap_http_next_header_filter;
static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_int_t
rap_http_slice_header_filter(rap_http_request_t *r)
{
    off_t                            end;
    rap_int_t                        rc;
    rap_table_elt_t                 *h;
    rap_http_slice_ctx_t            *ctx;
    rap_http_slice_loc_conf_t       *slcf;
    rap_http_slice_content_range_t   cr;

    ctx = rap_http_get_module_ctx(r, rap_http_slice_filter_module);
    if (ctx == NULL) {
        return rap_http_next_header_filter(r);
    }

    if (r->headers_out.status != RAP_HTTP_PARTIAL_CONTENT) {
        if (r == r->main) {
            rap_http_set_ctx(r, NULL, rap_http_slice_filter_module);
            return rap_http_next_header_filter(r);
        }

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "unexpected status code %ui in slice response",
                      r->headers_out.status);
        return RAP_ERROR;
    }

    h = r->headers_out.etag;

    if (ctx->etag.len) {
        if (h == NULL
            || h->value.len != ctx->etag.len
            || rap_strncmp(h->value.data, ctx->etag.data, ctx->etag.len)
               != 0)
        {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "etag mismatch in slice response");
            return RAP_ERROR;
        }
    }

    if (h) {
        ctx->etag = h->value;
    }

    if (rap_http_slice_parse_content_range(r, &cr) != RAP_OK) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "invalid range in slice response");
        return RAP_ERROR;
    }

    if (cr.complete_length == -1) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "no complete length in slice response");
        return RAP_ERROR;
    }

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice response range: %O-%O/%O",
                   cr.start, cr.end, cr.complete_length);

    slcf = rap_http_get_module_loc_conf(r, rap_http_slice_filter_module);

    end = rap_min(cr.start + (off_t) slcf->size, cr.complete_length);

    if (cr.start != ctx->start || cr.end != end) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "unexpected range in slice response: %O-%O",
                      cr.start, cr.end);
        return RAP_ERROR;
    }

    ctx->start = end;
    ctx->active = 1;

    r->headers_out.status = RAP_HTTP_OK;
    r->headers_out.status_line.len = 0;
    r->headers_out.content_length_n = cr.complete_length;
    r->headers_out.content_offset = cr.start;
    r->headers_out.content_range->hash = 0;
    r->headers_out.content_range = NULL;

    r->allow_ranges = 1;
    r->subrequest_ranges = 1;
    r->single_range = 1;

    rc = rap_http_next_header_filter(r);

    if (r != r->main) {
        return rc;
    }

    r->preserve_body = 1;

    if (r->headers_out.status == RAP_HTTP_PARTIAL_CONTENT) {
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


static rap_int_t
rap_http_slice_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_int_t                   rc;
    rap_chain_t                *cl;
    rap_http_slice_ctx_t       *ctx;
    rap_http_slice_loc_conf_t  *slcf;

    ctx = rap_http_get_module_ctx(r, rap_http_slice_filter_module);

    if (ctx == NULL || r != r->main) {
        return rap_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            ctx->last = 1;
        }
    }

    rc = rap_http_next_body_filter(r, in);

    if (rc == RAP_ERROR || !ctx->last) {
        return rc;
    }

    if (ctx->sr && !ctx->sr->done) {
        return rc;
    }

    if (!ctx->active) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "missing slice response");
        return RAP_ERROR;
    }

    if (ctx->start >= ctx->end) {
        rap_http_set_ctx(r, NULL, rap_http_slice_filter_module);
        rap_http_send_special(r, RAP_HTTP_LAST);
        return rc;
    }

    if (r->buffered) {
        return rc;
    }

    if (rap_http_subrequest(r, &r->uri, &r->args, &ctx->sr, NULL,
                            RAP_HTTP_SUBREQUEST_CLONE)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    rap_http_set_ctx(ctx->sr, ctx, rap_http_slice_filter_module);

    slcf = rap_http_get_module_loc_conf(r, rap_http_slice_filter_module);

    ctx->range.len = rap_sprintf(ctx->range.data, "bytes=%O-%O", ctx->start,
                                 ctx->start + (off_t) slcf->size - 1)
                     - ctx->range.data;

    ctx->active = 0;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http slice subrequest: \"%V\"", &ctx->range);

    return rc;
}


static rap_int_t
rap_http_slice_parse_content_range(rap_http_request_t *r,
    rap_http_slice_content_range_t *cr)
{
    off_t             start, end, complete_length, cutoff, cutlim;
    u_char           *p;
    rap_table_elt_t  *h;

    h = r->headers_out.content_range;

    if (h == NULL
        || h->value.len < 7
        || rap_strncmp(h->value.data, "bytes ", 6) != 0)
    {
        return RAP_ERROR;
    }

    p = h->value.data + 6;

    cutoff = RAP_MAX_OFF_T_VALUE / 10;
    cutlim = RAP_MAX_OFF_T_VALUE % 10;

    start = 0;
    end = 0;
    complete_length = 0;

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return RAP_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
            return RAP_ERROR;
        }

        start = start * 10 + (*p++ - '0');
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
        return RAP_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p < '0' || *p > '9') {
        return RAP_ERROR;
    }

    while (*p >= '0' && *p <= '9') {
        if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
            return RAP_ERROR;
        }

        end = end * 10 + (*p++ - '0');
    }

    end++;

    while (*p == ' ') { p++; }

    if (*p++ != '/') {
        return RAP_ERROR;
    }

    while (*p == ' ') { p++; }

    if (*p != '*') {
        if (*p < '0' || *p > '9') {
            return RAP_ERROR;
        }

        while (*p >= '0' && *p <= '9') {
            if (complete_length >= cutoff
                && (complete_length > cutoff || *p - '0' > cutlim))
            {
                return RAP_ERROR;
            }

            complete_length = complete_length * 10 + (*p++ - '0');
        }

    } else {
        complete_length = -1;
        p++;
    }

    while (*p == ' ') { p++; }

    if (*p != '\0') {
        return RAP_ERROR;
    }

    cr->start = start;
    cr->end = end;
    cr->complete_length = complete_length;

    return RAP_OK;
}


static rap_int_t
rap_http_slice_range_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    rap_http_slice_ctx_t       *ctx;
    rap_http_slice_loc_conf_t  *slcf;

    ctx = rap_http_get_module_ctx(r, rap_http_slice_filter_module);

    if (ctx == NULL) {
        if (r != r->main || r->headers_out.status) {
            v->not_found = 1;
            return RAP_OK;
        }

        slcf = rap_http_get_module_loc_conf(r, rap_http_slice_filter_module);

        if (slcf->size == 0) {
            v->not_found = 1;
            return RAP_OK;
        }

        ctx = rap_pcalloc(r->pool, sizeof(rap_http_slice_ctx_t));
        if (ctx == NULL) {
            return RAP_ERROR;
        }

        rap_http_set_ctx(r, ctx, rap_http_slice_filter_module);

        p = rap_pnalloc(r->pool, sizeof("bytes=-") - 1 + 2 * RAP_OFF_T_LEN);
        if (p == NULL) {
            return RAP_ERROR;
        }

        ctx->start = slcf->size * (rap_http_slice_get_start(r) / slcf->size);

        ctx->range.data = p;
        ctx->range.len = rap_sprintf(p, "bytes=%O-%O", ctx->start,
                                     ctx->start + (off_t) slcf->size - 1)
                         - p;
    }

    v->data = ctx->range.data;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;
    v->len = ctx->range.len;

    return RAP_OK;
}


static off_t
rap_http_slice_get_start(rap_http_request_t *r)
{
    off_t             start, cutoff, cutlim;
    u_char           *p;
    rap_table_elt_t  *h;

    if (r->headers_in.if_range) {
        return 0;
    }

    h = r->headers_in.range;

    if (h == NULL
        || h->value.len < 7
        || rap_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return 0;
    }

    p = h->value.data + 6;

    if (rap_strchr(p, ',')) {
        return 0;
    }

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return 0;
    }

    cutoff = RAP_MAX_OFF_T_VALUE / 10;
    cutlim = RAP_MAX_OFF_T_VALUE % 10;

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
rap_http_slice_create_loc_conf(rap_conf_t *cf)
{
    rap_http_slice_loc_conf_t  *slcf;

    slcf = rap_palloc(cf->pool, sizeof(rap_http_slice_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->size = RAP_CONF_UNSET_SIZE;

    return slcf;
}


static char *
rap_http_slice_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_slice_loc_conf_t *prev = parent;
    rap_http_slice_loc_conf_t *conf = child;

    rap_conf_merge_size_value(conf->size, prev->size, 0);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_slice_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var;

    var = rap_http_add_variable(cf, &rap_http_slice_range_name, 0);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_slice_range_variable;

    return RAP_OK;
}


static rap_int_t
rap_http_slice_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_slice_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_slice_body_filter;

    return RAP_OK;
}

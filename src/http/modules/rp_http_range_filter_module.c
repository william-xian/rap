
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


/*
 * the single part format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: image/jpeg" CRLF
 * "Content-Length: SIZE" CRLF
 * "Content-Range: bytes START-END/SIZE" CRLF
 * CRLF
 * ... data ...
 *
 *
 * the multipart format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: multipart/byteranges; boundary=0123456789" CRLF
 * CRLF
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START0-END0/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START1-END1/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789--" CRLF
 */


typedef struct {
    off_t        start;
    off_t        end;
    rp_str_t    content_range;
} rp_http_range_t;


typedef struct {
    off_t        offset;
    rp_str_t    boundary_header;
    rp_array_t  ranges;
} rp_http_range_filter_ctx_t;


static rp_int_t rp_http_range_parse(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx, rp_uint_t ranges);
static rp_int_t rp_http_range_singlepart_header(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx);
static rp_int_t rp_http_range_multipart_header(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx);
static rp_int_t rp_http_range_not_satisfiable(rp_http_request_t *r);
static rp_int_t rp_http_range_test_overlapped(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx, rp_chain_t *in);
static rp_int_t rp_http_range_singlepart_body(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx, rp_chain_t *in);
static rp_int_t rp_http_range_multipart_body(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx, rp_chain_t *in);

static rp_int_t rp_http_range_header_filter_init(rp_conf_t *cf);
static rp_int_t rp_http_range_body_filter_init(rp_conf_t *cf);


static rp_http_module_t  rp_http_range_header_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_range_header_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


rp_module_t  rp_http_range_header_filter_module = {
    RP_MODULE_V1,
    &rp_http_range_header_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
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


static rp_http_module_t  rp_http_range_body_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_range_body_filter_init,       /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


rp_module_t  rp_http_range_body_filter_module = {
    RP_MODULE_V1,
    &rp_http_range_body_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
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
rp_http_range_header_filter(rp_http_request_t *r)
{
    time_t                        if_range_time;
    rp_str_t                    *if_range, *etag;
    rp_uint_t                    ranges;
    rp_http_core_loc_conf_t     *clcf;
    rp_http_range_filter_ctx_t  *ctx;

    if (r->http_version < RP_HTTP_VERSION_10
        || r->headers_out.status != RP_HTTP_OK
        || (r != r->main && !r->subrequest_ranges)
        || r->headers_out.content_length_n == -1
        || !r->allow_ranges)
    {
        return rp_http_next_header_filter(r);
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->max_ranges == 0) {
        return rp_http_next_header_filter(r);
    }

    if (r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || rp_strncasecmp(r->headers_in.range->value.data,
                           (u_char *) "bytes=", 6)
           != 0)
    {
        goto next_filter;
    }

    if (r->headers_in.if_range) {

        if_range = &r->headers_in.if_range->value;

        if (if_range->len >= 2 && if_range->data[if_range->len - 1] == '"') {

            if (r->headers_out.etag == NULL) {
                goto next_filter;
            }

            etag = &r->headers_out.etag->value;

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http ir:%V etag:%V", if_range, etag);

            if (if_range->len != etag->len
                || rp_strncmp(if_range->data, etag->data, etag->len) != 0)
            {
                goto next_filter;
            }

            goto parse;
        }

        if (r->headers_out.last_modified_time == (time_t) -1) {
            goto next_filter;
        }

        if_range_time = rp_parse_http_time(if_range->data, if_range->len);

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http ir:%T lm:%T",
                       if_range_time, r->headers_out.last_modified_time);

        if (if_range_time != r->headers_out.last_modified_time) {
            goto next_filter;
        }
    }

parse:

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_range_filter_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    ctx->offset = r->headers_out.content_offset;

    ranges = r->single_range ? 1 : clcf->max_ranges;

    switch (rp_http_range_parse(r, ctx, ranges)) {

    case RP_OK:
        rp_http_set_ctx(r, ctx, rp_http_range_body_filter_module);

        r->headers_out.status = RP_HTTP_PARTIAL_CONTENT;
        r->headers_out.status_line.len = 0;

        if (ctx->ranges.nelts == 1) {
            return rp_http_range_singlepart_header(r, ctx);
        }

        return rp_http_range_multipart_header(r, ctx);

    case RP_HTTP_RANGE_NOT_SATISFIABLE:
        return rp_http_range_not_satisfiable(r);

    case RP_ERROR:
        return RP_ERROR;

    default: /* RP_DECLINED */
        break;
    }

next_filter:

    r->headers_out.accept_ranges = rp_list_push(&r->headers_out.headers);
    if (r->headers_out.accept_ranges == NULL) {
        return RP_ERROR;
    }

    r->headers_out.accept_ranges->hash = 1;
    rp_str_set(&r->headers_out.accept_ranges->key, "Accept-Ranges");
    rp_str_set(&r->headers_out.accept_ranges->value, "bytes");

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_range_parse(rp_http_request_t *r, rp_http_range_filter_ctx_t *ctx,
    rp_uint_t ranges)
{
    u_char                       *p;
    off_t                         start, end, size, content_length, cutoff,
                                  cutlim;
    rp_uint_t                    suffix;
    rp_http_range_t             *range;
    rp_http_range_filter_ctx_t  *mctx;

    if (r != r->main) {
        mctx = rp_http_get_module_ctx(r->main,
                                       rp_http_range_body_filter_module);
        if (mctx) {
            ctx->ranges = mctx->ranges;
            return RP_OK;
        }
    }

    if (rp_array_init(&ctx->ranges, r->pool, 1, sizeof(rp_http_range_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    p = r->headers_in.range->value.data + 6;
    size = 0;
    content_length = r->headers_out.content_length_n;

    cutoff = RP_MAX_OFF_T_VALUE / 10;
    cutlim = RP_MAX_OFF_T_VALUE % 10;

    for ( ;; ) {
        start = 0;
        end = 0;
        suffix = 0;

        while (*p == ' ') { p++; }

        if (*p != '-') {
            if (*p < '0' || *p > '9') {
                return RP_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p >= '0' && *p <= '9') {
                if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
                    return RP_HTTP_RANGE_NOT_SATISFIABLE;
                }

                start = start * 10 + (*p++ - '0');
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                return RP_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p == ' ') { p++; }

            if (*p == ',' || *p == '\0') {
                end = content_length;
                goto found;
            }

        } else {
            suffix = 1;
            p++;
        }

        if (*p < '0' || *p > '9') {
            return RP_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
                return RP_HTTP_RANGE_NOT_SATISFIABLE;
            }

            end = end * 10 + (*p++ - '0');
        }

        while (*p == ' ') { p++; }

        if (*p != ',' && *p != '\0') {
            return RP_HTTP_RANGE_NOT_SATISFIABLE;
        }

        if (suffix) {
            start = (end < content_length) ? content_length - end : 0;
            end = content_length - 1;
        }

        if (end >= content_length) {
            end = content_length;

        } else {
            end++;
        }

    found:

        if (start < end) {
            range = rp_array_push(&ctx->ranges);
            if (range == NULL) {
                return RP_ERROR;
            }

            range->start = start;
            range->end = end;

            if (size > RP_MAX_OFF_T_VALUE - (end - start)) {
                return RP_HTTP_RANGE_NOT_SATISFIABLE;
            }

            size += end - start;

            if (ranges-- == 0) {
                return RP_DECLINED;
            }

        } else if (start == 0) {
            return RP_DECLINED;
        }

        if (*p++ != ',') {
            break;
        }
    }

    if (ctx->ranges.nelts == 0) {
        return RP_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (size > content_length) {
        return RP_DECLINED;
    }

    return RP_OK;
}


static rp_int_t
rp_http_range_singlepart_header(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx)
{
    rp_table_elt_t   *content_range;
    rp_http_range_t  *range;

    if (r != r->main) {
        return rp_http_next_header_filter(r);
    }

    content_range = rp_list_push(&r->headers_out.headers);
    if (content_range == NULL) {
        return RP_ERROR;
    }

    r->headers_out.content_range = content_range;

    content_range->hash = 1;
    rp_str_set(&content_range->key, "Content-Range");

    content_range->value.data = rp_pnalloc(r->pool,
                                    sizeof("bytes -/") - 1 + 3 * RP_OFF_T_LEN);
    if (content_range->value.data == NULL) {
        content_range->hash = 0;
        r->headers_out.content_range = NULL;
        return RP_ERROR;
    }

    /* "Content-Range: bytes SSSS-EEEE/TTTT" header */

    range = ctx->ranges.elts;

    content_range->value.len = rp_sprintf(content_range->value.data,
                                           "bytes %O-%O/%O",
                                           range->start, range->end - 1,
                                           r->headers_out.content_length_n)
                               - content_range->value.data;

    r->headers_out.content_length_n = range->end - range->start;
    r->headers_out.content_offset = range->start;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_range_multipart_header(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx)
{
    off_t               len;
    size_t              size;
    rp_uint_t          i;
    rp_http_range_t   *range;
    rp_atomic_uint_t   boundary;

    size = sizeof(CRLF "--") - 1 + RP_ATOMIC_T_LEN
           + sizeof(CRLF "Content-Type: ") - 1
           + r->headers_out.content_type.len
           + sizeof(CRLF "Content-Range: bytes ") - 1;

    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        size += sizeof("; charset=") - 1 + r->headers_out.charset.len;
    }

    ctx->boundary_header.data = rp_pnalloc(r->pool, size);
    if (ctx->boundary_header.data == NULL) {
        return RP_ERROR;
    }

    boundary = rp_next_temp_number(0);

    /*
     * The boundary header of the range:
     * CRLF
     * "--0123456789" CRLF
     * "Content-Type: image/jpeg" CRLF
     * "Content-Range: bytes "
     */

    if (r->headers_out.content_type_len == r->headers_out.content_type.len
        && r->headers_out.charset.len)
    {
        ctx->boundary_header.len = rp_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V; charset=%V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type,
                                           &r->headers_out.charset)
                                   - ctx->boundary_header.data;

    } else if (r->headers_out.content_type.len) {
        ctx->boundary_header.len = rp_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Type: %V" CRLF
                                           "Content-Range: bytes ",
                                           boundary,
                                           &r->headers_out.content_type)
                                   - ctx->boundary_header.data;

    } else {
        ctx->boundary_header.len = rp_sprintf(ctx->boundary_header.data,
                                           CRLF "--%0muA" CRLF
                                           "Content-Range: bytes ",
                                           boundary)
                                   - ctx->boundary_header.data;
    }

    r->headers_out.content_type.data =
        rp_pnalloc(r->pool,
                    sizeof("Content-Type: multipart/byteranges; boundary=") - 1
                    + RP_ATOMIC_T_LEN);

    if (r->headers_out.content_type.data == NULL) {
        return RP_ERROR;
    }

    r->headers_out.content_type_lowcase = NULL;

    /* "Content-Type: multipart/byteranges; boundary=0123456789" */

    r->headers_out.content_type.len =
                           rp_sprintf(r->headers_out.content_type.data,
                                       "multipart/byteranges; boundary=%0muA",
                                       boundary)
                           - r->headers_out.content_type.data;

    r->headers_out.content_type_len = r->headers_out.content_type.len;

    r->headers_out.charset.len = 0;

    /* the size of the last boundary CRLF "--0123456789--" CRLF */

    len = sizeof(CRLF "--") - 1 + RP_ATOMIC_T_LEN + sizeof("--" CRLF) - 1;

    range = ctx->ranges.elts;
    for (i = 0; i < ctx->ranges.nelts; i++) {

        /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */

        range[i].content_range.data =
                               rp_pnalloc(r->pool, 3 * RP_OFF_T_LEN + 2 + 4);

        if (range[i].content_range.data == NULL) {
            return RP_ERROR;
        }

        range[i].content_range.len = rp_sprintf(range[i].content_range.data,
                                               "%O-%O/%O" CRLF CRLF,
                                               range[i].start, range[i].end - 1,
                                               r->headers_out.content_length_n)
                                     - range[i].content_range.data;

        len += ctx->boundary_header.len + range[i].content_range.len
                                             + (range[i].end - range[i].start);
    }

    r->headers_out.content_length_n = len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_range_not_satisfiable(rp_http_request_t *r)
{
    rp_table_elt_t  *content_range;

    r->headers_out.status = RP_HTTP_RANGE_NOT_SATISFIABLE;

    content_range = rp_list_push(&r->headers_out.headers);
    if (content_range == NULL) {
        return RP_ERROR;
    }

    r->headers_out.content_range = content_range;

    content_range->hash = 1;
    rp_str_set(&content_range->key, "Content-Range");

    content_range->value.data = rp_pnalloc(r->pool,
                                       sizeof("bytes */") - 1 + RP_OFF_T_LEN);
    if (content_range->value.data == NULL) {
        content_range->hash = 0;
        r->headers_out.content_range = NULL;
        return RP_ERROR;
    }

    content_range->value.len = rp_sprintf(content_range->value.data,
                                           "bytes */%O",
                                           r->headers_out.content_length_n)
                               - content_range->value.data;

    rp_http_clear_content_length(r);

    return RP_HTTP_RANGE_NOT_SATISFIABLE;
}


static rp_int_t
rp_http_range_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_http_range_filter_ctx_t  *ctx;

    if (in == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    ctx = rp_http_get_module_ctx(r, rp_http_range_body_filter_module);

    if (ctx == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    if (ctx->ranges.nelts == 1) {
        return rp_http_range_singlepart_body(r, ctx, in);
    }

    /*
     * multipart ranges are supported only if whole body is in a single buffer
     */

    if (rp_buf_special(in->buf)) {
        return rp_http_next_body_filter(r, in);
    }

    if (rp_http_range_test_overlapped(r, ctx, in) != RP_OK) {
        return RP_ERROR;
    }

    return rp_http_range_multipart_body(r, ctx, in);
}


static rp_int_t
rp_http_range_test_overlapped(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx, rp_chain_t *in)
{
    off_t              start, last;
    rp_buf_t         *buf;
    rp_uint_t         i;
    rp_http_range_t  *range;

    if (ctx->offset) {
        goto overlapped;
    }

    buf = in->buf;

    if (!buf->last_buf) {
        start = ctx->offset;
        last = ctx->offset + rp_buf_size(buf);

        range = ctx->ranges.elts;
        for (i = 0; i < ctx->ranges.nelts; i++) {
            if (start > range[i].start || last < range[i].end) {
                goto overlapped;
            }
        }
    }

    ctx->offset = rp_buf_size(buf);

    return RP_OK;

overlapped:

    rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                  "range in overlapped buffers");

    return RP_ERROR;
}


static rp_int_t
rp_http_range_singlepart_body(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx, rp_chain_t *in)
{
    off_t              start, last;
    rp_int_t          rc;
    rp_buf_t         *buf;
    rp_chain_t       *out, *cl, *tl, **ll;
    rp_http_range_t  *range;

    out = NULL;
    ll = &out;
    range = ctx->ranges.elts;

    for (cl = in; cl; cl = cl->next) {

        buf = cl->buf;

        start = ctx->offset;
        last = ctx->offset + rp_buf_size(buf);

        ctx->offset = last;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http range body buf: %O-%O", start, last);

        if (rp_buf_special(buf)) {

            if (range->end <= start) {
                continue;
            }

            tl = rp_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return RP_ERROR;
            }

            tl->buf = buf;
            tl->next = NULL;

            *ll = tl;
            ll = &tl->next;

            continue;
        }

        if (range->end <= start || range->start >= last) {

            rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http range body skip");

            if (buf->in_file) {
                buf->file_pos = buf->file_last;
            }

            buf->pos = buf->last;
            buf->sync = 1;

            continue;
        }

        if (range->start > start) {

            if (buf->in_file) {
                buf->file_pos += range->start - start;
            }

            if (rp_buf_in_memory(buf)) {
                buf->pos += (size_t) (range->start - start);
            }
        }

        if (range->end <= last) {

            if (buf->in_file) {
                buf->file_last -= last - range->end;
            }

            if (rp_buf_in_memory(buf)) {
                buf->last -= (size_t) (last - range->end);
            }

            buf->last_buf = (r == r->main) ? 1 : 0;
            buf->last_in_chain = 1;

            tl = rp_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return RP_ERROR;
            }

            tl->buf = buf;
            tl->next = NULL;

            *ll = tl;
            ll = &tl->next;

            continue;
        }

        tl = rp_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return RP_ERROR;
        }

        tl->buf = buf;
        tl->next = NULL;

        *ll = tl;
        ll = &tl->next;
    }

    rc = rp_http_next_body_filter(r, out);

    while (out) {
        cl = out;
        out = out->next;
        rp_free_chain(r->pool, cl);
    }

    return rc;
}


static rp_int_t
rp_http_range_multipart_body(rp_http_request_t *r,
    rp_http_range_filter_ctx_t *ctx, rp_chain_t *in)
{
    rp_buf_t         *b, *buf;
    rp_uint_t         i;
    rp_chain_t       *out, *hcl, *rcl, *dcl, **ll;
    rp_http_range_t  *range;

    ll = &out;
    buf = in->buf;
    range = ctx->ranges.elts;

    for (i = 0; i < ctx->ranges.nelts; i++) {

        /*
         * The boundary header of the range:
         * CRLF
         * "--0123456789" CRLF
         * "Content-Type: image/jpeg" CRLF
         * "Content-Range: bytes "
         */

        b = rp_calloc_buf(r->pool);
        if (b == NULL) {
            return RP_ERROR;
        }

        b->memory = 1;
        b->pos = ctx->boundary_header.data;
        b->last = ctx->boundary_header.data + ctx->boundary_header.len;

        hcl = rp_alloc_chain_link(r->pool);
        if (hcl == NULL) {
            return RP_ERROR;
        }

        hcl->buf = b;


        /* "SSSS-EEEE/TTTT" CRLF CRLF */

        b = rp_calloc_buf(r->pool);
        if (b == NULL) {
            return RP_ERROR;
        }

        b->temporary = 1;
        b->pos = range[i].content_range.data;
        b->last = range[i].content_range.data + range[i].content_range.len;

        rcl = rp_alloc_chain_link(r->pool);
        if (rcl == NULL) {
            return RP_ERROR;
        }

        rcl->buf = b;


        /* the range data */

        b = rp_calloc_buf(r->pool);
        if (b == NULL) {
            return RP_ERROR;
        }

        b->in_file = buf->in_file;
        b->temporary = buf->temporary;
        b->memory = buf->memory;
        b->mmap = buf->mmap;
        b->file = buf->file;

        if (buf->in_file) {
            b->file_pos = buf->file_pos + range[i].start;
            b->file_last = buf->file_pos + range[i].end;
        }

        if (rp_buf_in_memory(buf)) {
            b->pos = buf->pos + (size_t) range[i].start;
            b->last = buf->pos + (size_t) range[i].end;
        }

        dcl = rp_alloc_chain_link(r->pool);
        if (dcl == NULL) {
            return RP_ERROR;
        }

        dcl->buf = b;

        *ll = hcl;
        hcl->next = rcl;
        rcl->next = dcl;
        ll = &dcl->next;
    }

    /* the last boundary CRLF "--0123456789--" CRLF  */

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_ERROR;
    }

    b->temporary = 1;
    b->last_buf = 1;

    b->pos = rp_pnalloc(r->pool, sizeof(CRLF "--") - 1 + RP_ATOMIC_T_LEN
                                  + sizeof("--" CRLF) - 1);
    if (b->pos == NULL) {
        return RP_ERROR;
    }

    b->last = rp_cpymem(b->pos, ctx->boundary_header.data,
                         sizeof(CRLF "--") - 1 + RP_ATOMIC_T_LEN);
    *b->last++ = '-'; *b->last++ = '-';
    *b->last++ = CR; *b->last++ = LF;

    hcl = rp_alloc_chain_link(r->pool);
    if (hcl == NULL) {
        return RP_ERROR;
    }

    hcl->buf = b;
    hcl->next = NULL;

    *ll = hcl;

    return rp_http_next_body_filter(r, out);
}


static rp_int_t
rp_http_range_header_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_range_header_filter;

    return RP_OK;
}


static rp_int_t
rp_http_range_body_filter_init(rp_conf_t *cf)
{
    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_range_body_filter;

    return RP_OK;
}

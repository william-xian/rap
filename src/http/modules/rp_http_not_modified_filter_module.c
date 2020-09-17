
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static rp_uint_t rp_http_test_if_unmodified(rp_http_request_t *r);
static rp_uint_t rp_http_test_if_modified(rp_http_request_t *r);
static rp_uint_t rp_http_test_if_match(rp_http_request_t *r,
    rp_table_elt_t *header, rp_uint_t weak);
static rp_int_t rp_http_not_modified_filter_init(rp_conf_t *cf);


static rp_http_module_t  rp_http_not_modified_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_not_modified_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_not_modified_filter_module = {
    RP_MODULE_V1,
    &rp_http_not_modified_filter_module_ctx, /* module context */
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


static rp_int_t
rp_http_not_modified_header_filter(rp_http_request_t *r)
{
    if (r->headers_out.status != RP_HTTP_OK
        || r != r->main
        || r->disable_not_modified)
    {
        return rp_http_next_header_filter(r);
    }

    if (r->headers_in.if_unmodified_since
        && !rp_http_test_if_unmodified(r))
    {
        return rp_http_filter_finalize_request(r, NULL,
                                                RP_HTTP_PRECONDITION_FAILED);
    }

    if (r->headers_in.if_match
        && !rp_http_test_if_match(r, r->headers_in.if_match, 0))
    {
        return rp_http_filter_finalize_request(r, NULL,
                                                RP_HTTP_PRECONDITION_FAILED);
    }

    if (r->headers_in.if_modified_since || r->headers_in.if_none_match) {

        if (r->headers_in.if_modified_since
            && rp_http_test_if_modified(r))
        {
            return rp_http_next_header_filter(r);
        }

        if (r->headers_in.if_none_match
            && !rp_http_test_if_match(r, r->headers_in.if_none_match, 1))
        {
            return rp_http_next_header_filter(r);
        }

        /* not modified */

        r->headers_out.status = RP_HTTP_NOT_MODIFIED;
        r->headers_out.status_line.len = 0;
        r->headers_out.content_type.len = 0;
        rp_http_clear_content_length(r);
        rp_http_clear_accept_ranges(r);

        if (r->headers_out.content_encoding) {
            r->headers_out.content_encoding->hash = 0;
            r->headers_out.content_encoding = NULL;
        }

        return rp_http_next_header_filter(r);
    }

    return rp_http_next_header_filter(r);
}


static rp_uint_t
rp_http_test_if_unmodified(rp_http_request_t *r)
{
    time_t  iums;

    if (r->headers_out.last_modified_time == (time_t) -1) {
        return 0;
    }

    iums = rp_parse_http_time(r->headers_in.if_unmodified_since->value.data,
                               r->headers_in.if_unmodified_since->value.len);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http iums:%T lm:%T", iums, r->headers_out.last_modified_time);

    if (iums >= r->headers_out.last_modified_time) {
        return 1;
    }

    return 0;
}


static rp_uint_t
rp_http_test_if_modified(rp_http_request_t *r)
{
    time_t                     ims;
    rp_http_core_loc_conf_t  *clcf;

    if (r->headers_out.last_modified_time == (time_t) -1) {
        return 1;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->if_modified_since == RP_HTTP_IMS_OFF) {
        return 1;
    }

    ims = rp_parse_http_time(r->headers_in.if_modified_since->value.data,
                              r->headers_in.if_modified_since->value.len);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ims:%T lm:%T", ims, r->headers_out.last_modified_time);

    if (ims == r->headers_out.last_modified_time) {
        return 0;
    }

    if (clcf->if_modified_since == RP_HTTP_IMS_EXACT
        || ims < r->headers_out.last_modified_time)
    {
        return 1;
    }

    return 0;
}


static rp_uint_t
rp_http_test_if_match(rp_http_request_t *r, rp_table_elt_t *header,
    rp_uint_t weak)
{
    u_char     *start, *end, ch;
    rp_str_t   etag, *list;

    list = &header->value;

    if (list->len == 1 && list->data[0] == '*') {
        return 1;
    }

    if (r->headers_out.etag == NULL) {
        return 0;
    }

    etag = r->headers_out.etag->value;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http im:\"%V\" etag:%V", list, &etag);

    if (weak
        && etag.len > 2
        && etag.data[0] == 'W'
        && etag.data[1] == '/')
    {
        etag.len -= 2;
        etag.data += 2;
    }

    start = list->data;
    end = list->data + list->len;

    while (start < end) {

        if (weak
            && end - start > 2
            && start[0] == 'W'
            && start[1] == '/')
        {
            start += 2;
        }

        if (etag.len > (size_t) (end - start)) {
            return 0;
        }

        if (rp_strncmp(start, etag.data, etag.len) != 0) {
            goto skip;
        }

        start += etag.len;

        while (start < end) {
            ch = *start;

            if (ch == ' ' || ch == '\t') {
                start++;
                continue;
            }

            break;
        }

        if (start == end || *start == ',') {
            return 1;
        }

    skip:

        while (start < end && *start != ',') { start++; }
        while (start < end) {
            ch = *start;

            if (ch == ' ' || ch == '\t' || ch == ',') {
                start++;
                continue;
            }

            break;
        }
    }

    return 0;
}


static rp_int_t
rp_http_not_modified_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_not_modified_header_filter;

    return RP_OK;
}

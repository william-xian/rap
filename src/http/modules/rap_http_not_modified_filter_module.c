
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static rap_uint_t rap_http_test_if_unmodified(rap_http_request_t *r);
static rap_uint_t rap_http_test_if_modified(rap_http_request_t *r);
static rap_uint_t rap_http_test_if_match(rap_http_request_t *r,
    rap_table_elt_t *header, rap_uint_t weak);
static rap_int_t rap_http_not_modified_filter_init(rap_conf_t *cf);


static rap_http_module_t  rap_http_not_modified_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_not_modified_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_not_modified_filter_module = {
    RAP_MODULE_V1,
    &rap_http_not_modified_filter_module_ctx, /* module context */
    NULL,                                  /* module directives */
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


static rap_int_t
rap_http_not_modified_header_filter(rap_http_request_t *r)
{
    if (r->headers_out.status != RAP_HTTP_OK
        || r != r->main
        || r->disable_not_modified)
    {
        return rap_http_next_header_filter(r);
    }

    if (r->headers_in.if_unmodified_since
        && !rap_http_test_if_unmodified(r))
    {
        return rap_http_filter_finalize_request(r, NULL,
                                                RAP_HTTP_PRECONDITION_FAILED);
    }

    if (r->headers_in.if_match
        && !rap_http_test_if_match(r, r->headers_in.if_match, 0))
    {
        return rap_http_filter_finalize_request(r, NULL,
                                                RAP_HTTP_PRECONDITION_FAILED);
    }

    if (r->headers_in.if_modified_since || r->headers_in.if_none_match) {

        if (r->headers_in.if_modified_since
            && rap_http_test_if_modified(r))
        {
            return rap_http_next_header_filter(r);
        }

        if (r->headers_in.if_none_match
            && !rap_http_test_if_match(r, r->headers_in.if_none_match, 1))
        {
            return rap_http_next_header_filter(r);
        }

        /* not modified */

        r->headers_out.status = RAP_HTTP_NOT_MODIFIED;
        r->headers_out.status_line.len = 0;
        r->headers_out.content_type.len = 0;
        rap_http_clear_content_length(r);
        rap_http_clear_accept_ranges(r);

        if (r->headers_out.content_encoding) {
            r->headers_out.content_encoding->hash = 0;
            r->headers_out.content_encoding = NULL;
        }

        return rap_http_next_header_filter(r);
    }

    return rap_http_next_header_filter(r);
}


static rap_uint_t
rap_http_test_if_unmodified(rap_http_request_t *r)
{
    time_t  iums;

    if (r->headers_out.last_modified_time == (time_t) -1) {
        return 0;
    }

    iums = rap_parse_http_time(r->headers_in.if_unmodified_since->value.data,
                               r->headers_in.if_unmodified_since->value.len);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                 "http iums:%T lm:%T", iums, r->headers_out.last_modified_time);

    if (iums >= r->headers_out.last_modified_time) {
        return 1;
    }

    return 0;
}


static rap_uint_t
rap_http_test_if_modified(rap_http_request_t *r)
{
    time_t                     ims;
    rap_http_core_loc_conf_t  *clcf;

    if (r->headers_out.last_modified_time == (time_t) -1) {
        return 1;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->if_modified_since == RAP_HTTP_IMS_OFF) {
        return 1;
    }

    ims = rap_parse_http_time(r->headers_in.if_modified_since->value.data,
                              r->headers_in.if_modified_since->value.len);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ims:%T lm:%T", ims, r->headers_out.last_modified_time);

    if (ims == r->headers_out.last_modified_time) {
        return 0;
    }

    if (clcf->if_modified_since == RAP_HTTP_IMS_EXACT
        || ims < r->headers_out.last_modified_time)
    {
        return 1;
    }

    return 0;
}


static rap_uint_t
rap_http_test_if_match(rap_http_request_t *r, rap_table_elt_t *header,
    rap_uint_t weak)
{
    u_char     *start, *end, ch;
    rap_str_t   etag, *list;

    list = &header->value;

    if (list->len == 1 && list->data[0] == '*') {
        return 1;
    }

    if (r->headers_out.etag == NULL) {
        return 0;
    }

    etag = r->headers_out.etag->value;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

        if (rap_strncmp(start, etag.data, etag.len) != 0) {
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


static rap_int_t
rap_http_not_modified_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_not_modified_header_filter;

    return RAP_OK;
}

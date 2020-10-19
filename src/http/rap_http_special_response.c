
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap.h>


static rap_int_t rap_http_send_error_page(rap_http_request_t *r,
    rap_http_err_page_t *err_page);
static rap_int_t rap_http_send_special_response(rap_http_request_t *r,
    rap_http_core_loc_conf_t *clcf, rap_uint_t err);
static rap_int_t rap_http_send_refresh(rap_http_request_t *r);


static u_char rap_http_error_full_tail[] =
"<hr><center>" RAP_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char rap_http_error_build_tail[] =
"<hr><center>" RAP_VER_BUILD "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char rap_http_error_tail[] =
"<hr><center>rap</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char rap_http_msie_padding[] =
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
;


static u_char rap_http_msie_refresh_head[] =
"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";


static u_char rap_http_msie_refresh_tail[] =
"\"></head><body></body></html>" CRLF;


static char rap_http_error_301_page[] =
"<html>" CRLF
"<head><title>301 Moved Permanently</title></head>" CRLF
"<body>" CRLF
"<center><h1>301 Moved Permanently</h1></center>" CRLF
;


static char rap_http_error_302_page[] =
"<html>" CRLF
"<head><title>302 Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>302 Found</h1></center>" CRLF
;


static char rap_http_error_303_page[] =
"<html>" CRLF
"<head><title>303 See Other</title></head>" CRLF
"<body>" CRLF
"<center><h1>303 See Other</h1></center>" CRLF
;


static char rap_http_error_307_page[] =
"<html>" CRLF
"<head><title>307 Temporary Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>307 Temporary Redirect</h1></center>" CRLF
;


static char rap_http_error_308_page[] =
"<html>" CRLF
"<head><title>308 Permanent Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>308 Permanent Redirect</h1></center>" CRLF
;


static char rap_http_error_400_page[] =
"<html>" CRLF
"<head><title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
;


static char rap_http_error_401_page[] =
"<html>" CRLF
"<head><title>401 Authorization Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>401 Authorization Required</h1></center>" CRLF
;


static char rap_http_error_402_page[] =
"<html>" CRLF
"<head><title>402 Payment Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>402 Payment Required</h1></center>" CRLF
;


static char rap_http_error_403_page[] =
"<html>" CRLF
"<head><title>403 Forbidden</title></head>" CRLF
"<body>" CRLF
"<center><h1>403 Forbidden</h1></center>" CRLF
;


static char rap_http_error_404_page[] =
"<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF
;


static char rap_http_error_405_page[] =
"<html>" CRLF
"<head><title>405 Not Allowed</title></head>" CRLF
"<body>" CRLF
"<center><h1>405 Not Allowed</h1></center>" CRLF
;


static char rap_http_error_406_page[] =
"<html>" CRLF
"<head><title>406 Not Acceptable</title></head>" CRLF
"<body>" CRLF
"<center><h1>406 Not Acceptable</h1></center>" CRLF
;


static char rap_http_error_408_page[] =
"<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF
;


static char rap_http_error_409_page[] =
"<html>" CRLF
"<head><title>409 Conflict</title></head>" CRLF
"<body>" CRLF
"<center><h1>409 Conflict</h1></center>" CRLF
;


static char rap_http_error_410_page[] =
"<html>" CRLF
"<head><title>410 Gone</title></head>" CRLF
"<body>" CRLF
"<center><h1>410 Gone</h1></center>" CRLF
;


static char rap_http_error_411_page[] =
"<html>" CRLF
"<head><title>411 Length Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>411 Length Required</h1></center>" CRLF
;


static char rap_http_error_412_page[] =
"<html>" CRLF
"<head><title>412 Precondition Failed</title></head>" CRLF
"<body>" CRLF
"<center><h1>412 Precondition Failed</h1></center>" CRLF
;


static char rap_http_error_413_page[] =
"<html>" CRLF
"<head><title>413 Request Entity Too Large</title></head>" CRLF
"<body>" CRLF
"<center><h1>413 Request Entity Too Large</h1></center>" CRLF
;


static char rap_http_error_414_page[] =
"<html>" CRLF
"<head><title>414 Request-URI Too Large</title></head>" CRLF
"<body>" CRLF
"<center><h1>414 Request-URI Too Large</h1></center>" CRLF
;


static char rap_http_error_415_page[] =
"<html>" CRLF
"<head><title>415 Unsupported Media Type</title></head>" CRLF
"<body>" CRLF
"<center><h1>415 Unsupported Media Type</h1></center>" CRLF
;


static char rap_http_error_416_page[] =
"<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body>" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
;


static char rap_http_error_421_page[] =
"<html>" CRLF
"<head><title>421 Misdirected Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>421 Misdirected Request</h1></center>" CRLF
;


static char rap_http_error_429_page[] =
"<html>" CRLF
"<head><title>429 Too Many Requests</title></head>" CRLF
"<body>" CRLF
"<center><h1>429 Too Many Requests</h1></center>" CRLF
;


static char rap_http_error_494_page[] =
"<html>" CRLF
"<head><title>400 Request Header Or Cookie Too Large</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>Request Header Or Cookie Too Large</center>" CRLF
;


static char rap_http_error_495_page[] =
"<html>" CRLF
"<head><title>400 The SSL certificate error</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The SSL certificate error</center>" CRLF
;


static char rap_http_error_496_page[] =
"<html>" CRLF
"<head><title>400 No required SSL certificate was sent</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>No required SSL certificate was sent</center>" CRLF
;


static char rap_http_error_497_page[] =
"<html>" CRLF
"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
;


static char rap_http_error_500_page[] =
"<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body>" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF
;


static char rap_http_error_501_page[] =
"<html>" CRLF
"<head><title>501 Not Implemented</title></head>" CRLF
"<body>" CRLF
"<center><h1>501 Not Implemented</h1></center>" CRLF
;


static char rap_http_error_502_page[] =
"<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body>" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF
;


static char rap_http_error_503_page[] =
"<html>" CRLF
"<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
"<body>" CRLF
"<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF
;


static char rap_http_error_504_page[] =
"<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF
;


static char rap_http_error_505_page[] =
"<html>" CRLF
"<head><title>505 HTTP Version Not Supported</title></head>" CRLF
"<body>" CRLF
"<center><h1>505 HTTP Version Not Supported</h1></center>" CRLF
;


static char rap_http_error_507_page[] =
"<html>" CRLF
"<head><title>507 Insufficient Storage</title></head>" CRLF
"<body>" CRLF
"<center><h1>507 Insufficient Storage</h1></center>" CRLF
;


static rap_str_t rap_http_error_pages[] = {

    rap_null_string,                     /* 201, 204 */

#define RAP_HTTP_LAST_2XX  202
#define RAP_HTTP_OFF_3XX   (RAP_HTTP_LAST_2XX - 201)

    /* rap_null_string, */               /* 300 */
    rap_string(rap_http_error_301_page),
    rap_string(rap_http_error_302_page),
    rap_string(rap_http_error_303_page),
    rap_null_string,                     /* 304 */
    rap_null_string,                     /* 305 */
    rap_null_string,                     /* 306 */
    rap_string(rap_http_error_307_page),
    rap_string(rap_http_error_308_page),

#define RAP_HTTP_LAST_3XX  309
#define RAP_HTTP_OFF_4XX   (RAP_HTTP_LAST_3XX - 301 + RAP_HTTP_OFF_3XX)

    rap_string(rap_http_error_400_page),
    rap_string(rap_http_error_401_page),
    rap_string(rap_http_error_402_page),
    rap_string(rap_http_error_403_page),
    rap_string(rap_http_error_404_page),
    rap_string(rap_http_error_405_page),
    rap_string(rap_http_error_406_page),
    rap_null_string,                     /* 407 */
    rap_string(rap_http_error_408_page),
    rap_string(rap_http_error_409_page),
    rap_string(rap_http_error_410_page),
    rap_string(rap_http_error_411_page),
    rap_string(rap_http_error_412_page),
    rap_string(rap_http_error_413_page),
    rap_string(rap_http_error_414_page),
    rap_string(rap_http_error_415_page),
    rap_string(rap_http_error_416_page),
    rap_null_string,                     /* 417 */
    rap_null_string,                     /* 418 */
    rap_null_string,                     /* 419 */
    rap_null_string,                     /* 420 */
    rap_string(rap_http_error_421_page),
    rap_null_string,                     /* 422 */
    rap_null_string,                     /* 423 */
    rap_null_string,                     /* 424 */
    rap_null_string,                     /* 425 */
    rap_null_string,                     /* 426 */
    rap_null_string,                     /* 427 */
    rap_null_string,                     /* 428 */
    rap_string(rap_http_error_429_page),

#define RAP_HTTP_LAST_4XX  430
#define RAP_HTTP_OFF_5XX   (RAP_HTTP_LAST_4XX - 400 + RAP_HTTP_OFF_4XX)

    rap_string(rap_http_error_494_page), /* 494, request header too large */
    rap_string(rap_http_error_495_page), /* 495, https certificate error */
    rap_string(rap_http_error_496_page), /* 496, https no certificate */
    rap_string(rap_http_error_497_page), /* 497, http to https */
    rap_string(rap_http_error_404_page), /* 498, canceled */
    rap_null_string,                     /* 499, client has closed connection */

    rap_string(rap_http_error_500_page),
    rap_string(rap_http_error_501_page),
    rap_string(rap_http_error_502_page),
    rap_string(rap_http_error_503_page),
    rap_string(rap_http_error_504_page),
    rap_string(rap_http_error_505_page),
    rap_null_string,                     /* 506 */
    rap_string(rap_http_error_507_page)

#define RAP_HTTP_LAST_5XX  508

};


rap_int_t
rap_http_special_response_handler(rap_http_request_t *r, rap_int_t error)
{
    rap_uint_t                 i, err;
    rap_http_err_page_t       *err_page;
    rap_http_core_loc_conf_t  *clcf;

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http special response: %i, \"%V?%V\"",
                   error, &r->uri, &r->args);

    r->err_status = error;

    if (r->keepalive) {
        switch (error) {
            case RAP_HTTP_BAD_REQUEST:
            case RAP_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case RAP_HTTP_REQUEST_URI_TOO_LARGE:
            case RAP_HTTP_TO_HTTPS:
            case RAP_HTTPS_CERT_ERROR:
            case RAP_HTTPS_NO_CERT:
            case RAP_HTTP_INTERNAL_SERVER_ERROR:
            case RAP_HTTP_NOT_IMPLEMENTED:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close) {
        switch (error) {
            case RAP_HTTP_BAD_REQUEST:
            case RAP_HTTP_TO_HTTPS:
            case RAP_HTTPS_CERT_ERROR:
            case RAP_HTTPS_NO_CERT:
                r->lingering_close = 0;
        }
    }

    r->headers_out.content_type.len = 0;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (!r->error_page && clcf->error_pages && r->uri_changes != 0) {

        if (clcf->recursive_error_pages == 0) {
            r->error_page = 1;
        }

        err_page = clcf->error_pages->elts;

        for (i = 0; i < clcf->error_pages->nelts; i++) {
            if (err_page[i].status == error) {
                return rap_http_send_error_page(r, &err_page[i]);
            }
        }
    }

    r->expect_tested = 1;

    if (rap_http_discard_request_body(r) != RAP_OK) {
        r->keepalive = 0;
    }

    if (clcf->msie_refresh
        && r->headers_in.msie
        && (error == RAP_HTTP_MOVED_PERMANENTLY
            || error == RAP_HTTP_MOVED_TEMPORARILY))
    {
        return rap_http_send_refresh(r);
    }

    if (error == RAP_HTTP_CREATED) {
        /* 201 */
        err = 0;

    } else if (error == RAP_HTTP_NO_CONTENT) {
        /* 204 */
        err = 0;

    } else if (error >= RAP_HTTP_MOVED_PERMANENTLY
               && error < RAP_HTTP_LAST_3XX)
    {
        /* 3XX */
        err = error - RAP_HTTP_MOVED_PERMANENTLY + RAP_HTTP_OFF_3XX;

    } else if (error >= RAP_HTTP_BAD_REQUEST
               && error < RAP_HTTP_LAST_4XX)
    {
        /* 4XX */
        err = error - RAP_HTTP_BAD_REQUEST + RAP_HTTP_OFF_4XX;

    } else if (error >= RAP_HTTP_RAP_CODES
               && error < RAP_HTTP_LAST_5XX)
    {
        /* 49X, 5XX */
        err = error - RAP_HTTP_RAP_CODES + RAP_HTTP_OFF_5XX;
        switch (error) {
            case RAP_HTTP_TO_HTTPS:
            case RAP_HTTPS_CERT_ERROR:
            case RAP_HTTPS_NO_CERT:
            case RAP_HTTP_REQUEST_HEADER_TOO_LARGE:
                r->err_status = RAP_HTTP_BAD_REQUEST;
        }

    } else {
        /* unknown code, zero body */
        err = 0;
    }

    return rap_http_send_special_response(r, clcf, err);
}


rap_int_t
rap_http_filter_finalize_request(rap_http_request_t *r, rap_module_t *m,
    rap_int_t error)
{
    void       *ctx;
    rap_int_t   rc;

    rap_http_clean_header(r);

    ctx = NULL;

    if (m) {
        ctx = r->ctx[m->ctx_index];
    }

    /* clear the modules contexts */
    rap_memzero(r->ctx, sizeof(void *) * rap_http_max_module);

    if (m) {
        r->ctx[m->ctx_index] = ctx;
    }

    r->filter_finalize = 1;

    rc = rap_http_special_response_handler(r, error);

    /* RAP_ERROR resets any pending data */

    switch (rc) {

    case RAP_OK:
    case RAP_DONE:
        return RAP_ERROR;

    default:
        return rc;
    }
}


void
rap_http_clean_header(rap_http_request_t *r)
{
    rap_memzero(&r->headers_out.status,
                sizeof(rap_http_headers_out_t)
                    - offsetof(rap_http_headers_out_t, status));

    r->headers_out.headers.part.nelts = 0;
    r->headers_out.headers.part.next = NULL;
    r->headers_out.headers.last = &r->headers_out.headers.part;

    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;
}


static rap_int_t
rap_http_send_error_page(rap_http_request_t *r, rap_http_err_page_t *err_page)
{
    rap_int_t                  overwrite;
    rap_str_t                  uri, args;
    rap_table_elt_t           *location;
    rap_http_core_loc_conf_t  *clcf;

    overwrite = err_page->overwrite;

    if (overwrite && overwrite != RAP_HTTP_OK) {
        r->expect_tested = 1;
    }

    if (overwrite >= 0) {
        r->err_status = overwrite;
    }

    if (rap_http_complex_value(r, &err_page->value, &uri) != RAP_OK) {
        return RAP_ERROR;
    }

    if (uri.len && uri.data[0] == '/') {

        if (err_page->value.lengths) {
            rap_http_split_args(r, &uri, &args);

        } else {
            args = err_page->args;
        }

        if (r->method != RAP_HTTP_HEAD) {
            r->method = RAP_HTTP_GET;
            r->method_name = rap_http_core_get_method;
        }

        return rap_http_internal_redirect(r, &uri, &args);
    }

    if (uri.len && uri.data[0] == '@') {
        return rap_http_named_location(r, &uri);
    }

    r->expect_tested = 1;

    if (rap_http_discard_request_body(r) != RAP_OK) {
        r->keepalive = 0;
    }

    location = rap_list_push(&r->headers_out.headers);

    if (location == NULL) {
        return RAP_ERROR;
    }

    if (overwrite != RAP_HTTP_MOVED_PERMANENTLY
        && overwrite != RAP_HTTP_MOVED_TEMPORARILY
        && overwrite != RAP_HTTP_SEE_OTHER
        && overwrite != RAP_HTTP_TEMPORARY_REDIRECT
        && overwrite != RAP_HTTP_PERMANENT_REDIRECT)
    {
        r->err_status = RAP_HTTP_MOVED_TEMPORARILY;
    }

    location->hash = 1;
    rap_str_set(&location->key, "Location");
    location->value = uri;

    rap_http_clear_location(r);

    r->headers_out.location = location;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->msie_refresh && r->headers_in.msie) {
        return rap_http_send_refresh(r);
    }

    return rap_http_send_special_response(r, clcf, r->err_status
                                                   - RAP_HTTP_MOVED_PERMANENTLY
                                                   + RAP_HTTP_OFF_3XX);
}


static rap_int_t
rap_http_send_special_response(rap_http_request_t *r,
    rap_http_core_loc_conf_t *clcf, rap_uint_t err)
{
    u_char       *tail;
    size_t        len;
    rap_int_t     rc;
    rap_buf_t    *b;
    rap_uint_t    msie_padding;
    rap_chain_t   out[3];

    if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_ON) {
        len = sizeof(rap_http_error_full_tail) - 1;
        tail = rap_http_error_full_tail;

    } else if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_BUILD) {
        len = sizeof(rap_http_error_build_tail) - 1;
        tail = rap_http_error_build_tail;

    } else {
        len = sizeof(rap_http_error_tail) - 1;
        tail = rap_http_error_tail;
    }

    msie_padding = 0;

    if (rap_http_error_pages[err].len) {
        r->headers_out.content_length_n = rap_http_error_pages[err].len + len;
        if (clcf->msie_padding
            && (r->headers_in.msie || r->headers_in.chrome)
            && r->http_version >= RAP_HTTP_VERSION_10
            && err >= RAP_HTTP_OFF_4XX)
        {
            r->headers_out.content_length_n +=
                                         sizeof(rap_http_msie_padding) - 1;
            msie_padding = 1;
        }

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        rap_str_set(&r->headers_out.content_type, "text/html");
        r->headers_out.content_type_lowcase = NULL;

    } else {
        r->headers_out.content_length_n = 0;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rap_http_clear_accept_ranges(r);
    rap_http_clear_last_modified(r);
    rap_http_clear_etag(r);

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || r->header_only) {
        return rc;
    }

    if (rap_http_error_pages[err].len == 0) {
        return rap_http_send_special(r, RAP_HTTP_LAST);
    }

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return RAP_ERROR;
    }

    b->memory = 1;
    b->pos = rap_http_error_pages[err].data;
    b->last = rap_http_error_pages[err].data + rap_http_error_pages[err].len;

    out[0].buf = b;
    out[0].next = &out[1];

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return RAP_ERROR;
    }

    b->memory = 1;

    b->pos = tail;
    b->last = tail + len;

    out[1].buf = b;
    out[1].next = NULL;

    if (msie_padding) {
        b = rap_calloc_buf(r->pool);
        if (b == NULL) {
            return RAP_ERROR;
        }

        b->memory = 1;
        b->pos = rap_http_msie_padding;
        b->last = rap_http_msie_padding + sizeof(rap_http_msie_padding) - 1;

        out[1].next = &out[2];
        out[2].buf = b;
        out[2].next = NULL;
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    return rap_http_output_filter(r, &out[0]);
}


static rap_int_t
rap_http_send_refresh(rap_http_request_t *r)
{
    u_char       *p, *location;
    size_t        len, size;
    uintptr_t     escape;
    rap_int_t     rc;
    rap_buf_t    *b;
    rap_chain_t   out;

    len = r->headers_out.location->value.len;
    location = r->headers_out.location->value.data;

    escape = 2 * rap_escape_uri(NULL, location, len, RAP_ESCAPE_REFRESH);

    size = sizeof(rap_http_msie_refresh_head) - 1
           + escape + len
           + sizeof(rap_http_msie_refresh_tail) - 1;

    r->err_status = RAP_HTTP_OK;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    rap_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_lowcase = NULL;

    r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;

    r->headers_out.content_length_n = size;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rap_http_clear_accept_ranges(r);
    rap_http_clear_last_modified(r);
    rap_http_clear_etag(r);

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || r->header_only) {
        return rc;
    }

    b = rap_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return RAP_ERROR;
    }

    p = rap_cpymem(b->pos, rap_http_msie_refresh_head,
                   sizeof(rap_http_msie_refresh_head) - 1);

    if (escape == 0) {
        p = rap_cpymem(p, location, len);

    } else {
        p = (u_char *) rap_escape_uri(p, location, len, RAP_ESCAPE_REFRESH);
    }

    b->last = rap_cpymem(p, rap_http_msie_refresh_tail,
                         sizeof(rap_http_msie_refresh_tail) - 1);

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return rap_http_output_filter(r, &out);
}

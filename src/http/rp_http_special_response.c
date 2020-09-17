
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rap.h>


static rp_int_t rp_http_send_error_page(rp_http_request_t *r,
    rp_http_err_page_t *err_page);
static rp_int_t rp_http_send_special_response(rp_http_request_t *r,
    rp_http_core_loc_conf_t *clcf, rp_uint_t err);
static rp_int_t rp_http_send_refresh(rp_http_request_t *r);


static u_char rp_http_error_full_tail[] =
"<hr><center>" RAP_VER "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char rp_http_error_build_tail[] =
"<hr><center>" RAP_VER_BUILD "</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char rp_http_error_tail[] =
"<hr><center>rap</center>" CRLF
"</body>" CRLF
"</html>" CRLF
;


static u_char rp_http_msie_padding[] =
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
"<!-- a padding to disable MSIE and Chrome friendly error page -->" CRLF
;


static u_char rp_http_msie_refresh_head[] =
"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";


static u_char rp_http_msie_refresh_tail[] =
"\"></head><body></body></html>" CRLF;


static char rp_http_error_301_page[] =
"<html>" CRLF
"<head><title>301 Moved Permanently</title></head>" CRLF
"<body>" CRLF
"<center><h1>301 Moved Permanently</h1></center>" CRLF
;


static char rp_http_error_302_page[] =
"<html>" CRLF
"<head><title>302 Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>302 Found</h1></center>" CRLF
;


static char rp_http_error_303_page[] =
"<html>" CRLF
"<head><title>303 See Other</title></head>" CRLF
"<body>" CRLF
"<center><h1>303 See Other</h1></center>" CRLF
;


static char rp_http_error_307_page[] =
"<html>" CRLF
"<head><title>307 Temporary Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>307 Temporary Redirect</h1></center>" CRLF
;


static char rp_http_error_308_page[] =
"<html>" CRLF
"<head><title>308 Permanent Redirect</title></head>" CRLF
"<body>" CRLF
"<center><h1>308 Permanent Redirect</h1></center>" CRLF
;


static char rp_http_error_400_page[] =
"<html>" CRLF
"<head><title>400 Bad Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
;


static char rp_http_error_401_page[] =
"<html>" CRLF
"<head><title>401 Authorization Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>401 Authorization Required</h1></center>" CRLF
;


static char rp_http_error_402_page[] =
"<html>" CRLF
"<head><title>402 Payment Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>402 Payment Required</h1></center>" CRLF
;


static char rp_http_error_403_page[] =
"<html>" CRLF
"<head><title>403 Forbidden</title></head>" CRLF
"<body>" CRLF
"<center><h1>403 Forbidden</h1></center>" CRLF
;


static char rp_http_error_404_page[] =
"<html>" CRLF
"<head><title>404 Not Found</title></head>" CRLF
"<body>" CRLF
"<center><h1>404 Not Found</h1></center>" CRLF
;


static char rp_http_error_405_page[] =
"<html>" CRLF
"<head><title>405 Not Allowed</title></head>" CRLF
"<body>" CRLF
"<center><h1>405 Not Allowed</h1></center>" CRLF
;


static char rp_http_error_406_page[] =
"<html>" CRLF
"<head><title>406 Not Acceptable</title></head>" CRLF
"<body>" CRLF
"<center><h1>406 Not Acceptable</h1></center>" CRLF
;


static char rp_http_error_408_page[] =
"<html>" CRLF
"<head><title>408 Request Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>408 Request Time-out</h1></center>" CRLF
;


static char rp_http_error_409_page[] =
"<html>" CRLF
"<head><title>409 Conflict</title></head>" CRLF
"<body>" CRLF
"<center><h1>409 Conflict</h1></center>" CRLF
;


static char rp_http_error_410_page[] =
"<html>" CRLF
"<head><title>410 Gone</title></head>" CRLF
"<body>" CRLF
"<center><h1>410 Gone</h1></center>" CRLF
;


static char rp_http_error_411_page[] =
"<html>" CRLF
"<head><title>411 Length Required</title></head>" CRLF
"<body>" CRLF
"<center><h1>411 Length Required</h1></center>" CRLF
;


static char rp_http_error_412_page[] =
"<html>" CRLF
"<head><title>412 Precondition Failed</title></head>" CRLF
"<body>" CRLF
"<center><h1>412 Precondition Failed</h1></center>" CRLF
;


static char rp_http_error_413_page[] =
"<html>" CRLF
"<head><title>413 Request Entity Too Large</title></head>" CRLF
"<body>" CRLF
"<center><h1>413 Request Entity Too Large</h1></center>" CRLF
;


static char rp_http_error_414_page[] =
"<html>" CRLF
"<head><title>414 Request-URI Too Large</title></head>" CRLF
"<body>" CRLF
"<center><h1>414 Request-URI Too Large</h1></center>" CRLF
;


static char rp_http_error_415_page[] =
"<html>" CRLF
"<head><title>415 Unsupported Media Type</title></head>" CRLF
"<body>" CRLF
"<center><h1>415 Unsupported Media Type</h1></center>" CRLF
;


static char rp_http_error_416_page[] =
"<html>" CRLF
"<head><title>416 Requested Range Not Satisfiable</title></head>" CRLF
"<body>" CRLF
"<center><h1>416 Requested Range Not Satisfiable</h1></center>" CRLF
;


static char rp_http_error_421_page[] =
"<html>" CRLF
"<head><title>421 Misdirected Request</title></head>" CRLF
"<body>" CRLF
"<center><h1>421 Misdirected Request</h1></center>" CRLF
;


static char rp_http_error_429_page[] =
"<html>" CRLF
"<head><title>429 Too Many Requests</title></head>" CRLF
"<body>" CRLF
"<center><h1>429 Too Many Requests</h1></center>" CRLF
;


static char rp_http_error_494_page[] =
"<html>" CRLF
"<head><title>400 Request Header Or Cookie Too Large</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>Request Header Or Cookie Too Large</center>" CRLF
;


static char rp_http_error_495_page[] =
"<html>" CRLF
"<head><title>400 The SSL certificate error</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The SSL certificate error</center>" CRLF
;


static char rp_http_error_496_page[] =
"<html>" CRLF
"<head><title>400 No required SSL certificate was sent</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>No required SSL certificate was sent</center>" CRLF
;


static char rp_http_error_497_page[] =
"<html>" CRLF
"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>"
CRLF
"<body>" CRLF
"<center><h1>400 Bad Request</h1></center>" CRLF
"<center>The plain HTTP request was sent to HTTPS port</center>" CRLF
;


static char rp_http_error_500_page[] =
"<html>" CRLF
"<head><title>500 Internal Server Error</title></head>" CRLF
"<body>" CRLF
"<center><h1>500 Internal Server Error</h1></center>" CRLF
;


static char rp_http_error_501_page[] =
"<html>" CRLF
"<head><title>501 Not Implemented</title></head>" CRLF
"<body>" CRLF
"<center><h1>501 Not Implemented</h1></center>" CRLF
;


static char rp_http_error_502_page[] =
"<html>" CRLF
"<head><title>502 Bad Gateway</title></head>" CRLF
"<body>" CRLF
"<center><h1>502 Bad Gateway</h1></center>" CRLF
;


static char rp_http_error_503_page[] =
"<html>" CRLF
"<head><title>503 Service Temporarily Unavailable</title></head>" CRLF
"<body>" CRLF
"<center><h1>503 Service Temporarily Unavailable</h1></center>" CRLF
;


static char rp_http_error_504_page[] =
"<html>" CRLF
"<head><title>504 Gateway Time-out</title></head>" CRLF
"<body>" CRLF
"<center><h1>504 Gateway Time-out</h1></center>" CRLF
;


static char rp_http_error_505_page[] =
"<html>" CRLF
"<head><title>505 HTTP Version Not Supported</title></head>" CRLF
"<body>" CRLF
"<center><h1>505 HTTP Version Not Supported</h1></center>" CRLF
;


static char rp_http_error_507_page[] =
"<html>" CRLF
"<head><title>507 Insufficient Storage</title></head>" CRLF
"<body>" CRLF
"<center><h1>507 Insufficient Storage</h1></center>" CRLF
;


static rp_str_t rp_http_error_pages[] = {

    rp_null_string,                     /* 201, 204 */

#define RP_HTTP_LAST_2XX  202
#define RP_HTTP_OFF_3XX   (RP_HTTP_LAST_2XX - 201)

    /* rp_null_string, */               /* 300 */
    rp_string(rp_http_error_301_page),
    rp_string(rp_http_error_302_page),
    rp_string(rp_http_error_303_page),
    rp_null_string,                     /* 304 */
    rp_null_string,                     /* 305 */
    rp_null_string,                     /* 306 */
    rp_string(rp_http_error_307_page),
    rp_string(rp_http_error_308_page),

#define RP_HTTP_LAST_3XX  309
#define RP_HTTP_OFF_4XX   (RP_HTTP_LAST_3XX - 301 + RP_HTTP_OFF_3XX)

    rp_string(rp_http_error_400_page),
    rp_string(rp_http_error_401_page),
    rp_string(rp_http_error_402_page),
    rp_string(rp_http_error_403_page),
    rp_string(rp_http_error_404_page),
    rp_string(rp_http_error_405_page),
    rp_string(rp_http_error_406_page),
    rp_null_string,                     /* 407 */
    rp_string(rp_http_error_408_page),
    rp_string(rp_http_error_409_page),
    rp_string(rp_http_error_410_page),
    rp_string(rp_http_error_411_page),
    rp_string(rp_http_error_412_page),
    rp_string(rp_http_error_413_page),
    rp_string(rp_http_error_414_page),
    rp_string(rp_http_error_415_page),
    rp_string(rp_http_error_416_page),
    rp_null_string,                     /* 417 */
    rp_null_string,                     /* 418 */
    rp_null_string,                     /* 419 */
    rp_null_string,                     /* 420 */
    rp_string(rp_http_error_421_page),
    rp_null_string,                     /* 422 */
    rp_null_string,                     /* 423 */
    rp_null_string,                     /* 424 */
    rp_null_string,                     /* 425 */
    rp_null_string,                     /* 426 */
    rp_null_string,                     /* 427 */
    rp_null_string,                     /* 428 */
    rp_string(rp_http_error_429_page),

#define RP_HTTP_LAST_4XX  430
#define RP_HTTP_OFF_5XX   (RP_HTTP_LAST_4XX - 400 + RP_HTTP_OFF_4XX)

    rp_string(rp_http_error_494_page), /* 494, request header too large */
    rp_string(rp_http_error_495_page), /* 495, https certificate error */
    rp_string(rp_http_error_496_page), /* 496, https no certificate */
    rp_string(rp_http_error_497_page), /* 497, http to https */
    rp_string(rp_http_error_404_page), /* 498, canceled */
    rp_null_string,                     /* 499, client has closed connection */

    rp_string(rp_http_error_500_page),
    rp_string(rp_http_error_501_page),
    rp_string(rp_http_error_502_page),
    rp_string(rp_http_error_503_page),
    rp_string(rp_http_error_504_page),
    rp_string(rp_http_error_505_page),
    rp_null_string,                     /* 506 */
    rp_string(rp_http_error_507_page)

#define RP_HTTP_LAST_5XX  508

};


rp_int_t
rp_http_special_response_handler(rp_http_request_t *r, rp_int_t error)
{
    rp_uint_t                 i, err;
    rp_http_err_page_t       *err_page;
    rp_http_core_loc_conf_t  *clcf;

    rp_log_debug3(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http special response: %i, \"%V?%V\"",
                   error, &r->uri, &r->args);

    r->err_status = error;

    if (r->keepalive) {
        switch (error) {
            case RP_HTTP_BAD_REQUEST:
            case RP_HTTP_REQUEST_ENTITY_TOO_LARGE:
            case RP_HTTP_REQUEST_URI_TOO_LARGE:
            case RP_HTTP_TO_HTTPS:
            case RP_HTTPS_CERT_ERROR:
            case RP_HTTPS_NO_CERT:
            case RP_HTTP_INTERNAL_SERVER_ERROR:
            case RP_HTTP_NOT_IMPLEMENTED:
                r->keepalive = 0;
        }
    }

    if (r->lingering_close) {
        switch (error) {
            case RP_HTTP_BAD_REQUEST:
            case RP_HTTP_TO_HTTPS:
            case RP_HTTPS_CERT_ERROR:
            case RP_HTTPS_NO_CERT:
                r->lingering_close = 0;
        }
    }

    r->headers_out.content_type.len = 0;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (!r->error_page && clcf->error_pages && r->uri_changes != 0) {

        if (clcf->recursive_error_pages == 0) {
            r->error_page = 1;
        }

        err_page = clcf->error_pages->elts;

        for (i = 0; i < clcf->error_pages->nelts; i++) {
            if (err_page[i].status == error) {
                return rp_http_send_error_page(r, &err_page[i]);
            }
        }
    }

    r->expect_tested = 1;

    if (rp_http_discard_request_body(r) != RP_OK) {
        r->keepalive = 0;
    }

    if (clcf->msie_refresh
        && r->headers_in.msie
        && (error == RP_HTTP_MOVED_PERMANENTLY
            || error == RP_HTTP_MOVED_TEMPORARILY))
    {
        return rp_http_send_refresh(r);
    }

    if (error == RP_HTTP_CREATED) {
        /* 201 */
        err = 0;

    } else if (error == RP_HTTP_NO_CONTENT) {
        /* 204 */
        err = 0;

    } else if (error >= RP_HTTP_MOVED_PERMANENTLY
               && error < RP_HTTP_LAST_3XX)
    {
        /* 3XX */
        err = error - RP_HTTP_MOVED_PERMANENTLY + RP_HTTP_OFF_3XX;

    } else if (error >= RP_HTTP_BAD_REQUEST
               && error < RP_HTTP_LAST_4XX)
    {
        /* 4XX */
        err = error - RP_HTTP_BAD_REQUEST + RP_HTTP_OFF_4XX;

    } else if (error >= RP_HTTP_RAP_CODES
               && error < RP_HTTP_LAST_5XX)
    {
        /* 49X, 5XX */
        err = error - RP_HTTP_RAP_CODES + RP_HTTP_OFF_5XX;
        switch (error) {
            case RP_HTTP_TO_HTTPS:
            case RP_HTTPS_CERT_ERROR:
            case RP_HTTPS_NO_CERT:
            case RP_HTTP_REQUEST_HEADER_TOO_LARGE:
                r->err_status = RP_HTTP_BAD_REQUEST;
        }

    } else {
        /* unknown code, zero body */
        err = 0;
    }

    return rp_http_send_special_response(r, clcf, err);
}


rp_int_t
rp_http_filter_finalize_request(rp_http_request_t *r, rp_module_t *m,
    rp_int_t error)
{
    void       *ctx;
    rp_int_t   rc;

    rp_http_clean_header(r);

    ctx = NULL;

    if (m) {
        ctx = r->ctx[m->ctx_index];
    }

    /* clear the modules contexts */
    rp_memzero(r->ctx, sizeof(void *) * rp_http_max_module);

    if (m) {
        r->ctx[m->ctx_index] = ctx;
    }

    r->filter_finalize = 1;

    rc = rp_http_special_response_handler(r, error);

    /* RP_ERROR resets any pending data */

    switch (rc) {

    case RP_OK:
    case RP_DONE:
        return RP_ERROR;

    default:
        return rc;
    }
}


void
rp_http_clean_header(rp_http_request_t *r)
{
    rp_memzero(&r->headers_out.status,
                sizeof(rp_http_headers_out_t)
                    - offsetof(rp_http_headers_out_t, status));

    r->headers_out.headers.part.nelts = 0;
    r->headers_out.headers.part.next = NULL;
    r->headers_out.headers.last = &r->headers_out.headers.part;

    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;
}


static rp_int_t
rp_http_send_error_page(rp_http_request_t *r, rp_http_err_page_t *err_page)
{
    rp_int_t                  overwrite;
    rp_str_t                  uri, args;
    rp_table_elt_t           *location;
    rp_http_core_loc_conf_t  *clcf;

    overwrite = err_page->overwrite;

    if (overwrite && overwrite != RP_HTTP_OK) {
        r->expect_tested = 1;
    }

    if (overwrite >= 0) {
        r->err_status = overwrite;
    }

    if (rp_http_complex_value(r, &err_page->value, &uri) != RP_OK) {
        return RP_ERROR;
    }

    if (uri.len && uri.data[0] == '/') {

        if (err_page->value.lengths) {
            rp_http_split_args(r, &uri, &args);

        } else {
            args = err_page->args;
        }

        if (r->method != RP_HTTP_HEAD) {
            r->method = RP_HTTP_GET;
            r->method_name = rp_http_core_get_method;
        }

        return rp_http_internal_redirect(r, &uri, &args);
    }

    if (uri.len && uri.data[0] == '@') {
        return rp_http_named_location(r, &uri);
    }

    r->expect_tested = 1;

    if (rp_http_discard_request_body(r) != RP_OK) {
        r->keepalive = 0;
    }

    location = rp_list_push(&r->headers_out.headers);

    if (location == NULL) {
        return RP_ERROR;
    }

    if (overwrite != RP_HTTP_MOVED_PERMANENTLY
        && overwrite != RP_HTTP_MOVED_TEMPORARILY
        && overwrite != RP_HTTP_SEE_OTHER
        && overwrite != RP_HTTP_TEMPORARY_REDIRECT
        && overwrite != RP_HTTP_PERMANENT_REDIRECT)
    {
        r->err_status = RP_HTTP_MOVED_TEMPORARILY;
    }

    location->hash = 1;
    rp_str_set(&location->key, "Location");
    location->value = uri;

    rp_http_clear_location(r);

    r->headers_out.location = location;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->msie_refresh && r->headers_in.msie) {
        return rp_http_send_refresh(r);
    }

    return rp_http_send_special_response(r, clcf, r->err_status
                                                   - RP_HTTP_MOVED_PERMANENTLY
                                                   + RP_HTTP_OFF_3XX);
}


static rp_int_t
rp_http_send_special_response(rp_http_request_t *r,
    rp_http_core_loc_conf_t *clcf, rp_uint_t err)
{
    u_char       *tail;
    size_t        len;
    rp_int_t     rc;
    rp_buf_t    *b;
    rp_uint_t    msie_padding;
    rp_chain_t   out[3];

    if (clcf->server_tokens == RP_HTTP_SERVER_TOKENS_ON) {
        len = sizeof(rp_http_error_full_tail) - 1;
        tail = rp_http_error_full_tail;

    } else if (clcf->server_tokens == RP_HTTP_SERVER_TOKENS_BUILD) {
        len = sizeof(rp_http_error_build_tail) - 1;
        tail = rp_http_error_build_tail;

    } else {
        len = sizeof(rp_http_error_tail) - 1;
        tail = rp_http_error_tail;
    }

    msie_padding = 0;

    if (rp_http_error_pages[err].len) {
        r->headers_out.content_length_n = rp_http_error_pages[err].len + len;
        if (clcf->msie_padding
            && (r->headers_in.msie || r->headers_in.chrome)
            && r->http_version >= RP_HTTP_VERSION_10
            && err >= RP_HTTP_OFF_4XX)
        {
            r->headers_out.content_length_n +=
                                         sizeof(rp_http_msie_padding) - 1;
            msie_padding = 1;
        }

        r->headers_out.content_type_len = sizeof("text/html") - 1;
        rp_str_set(&r->headers_out.content_type, "text/html");
        r->headers_out.content_type_lowcase = NULL;

    } else {
        r->headers_out.content_length_n = 0;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rp_http_clear_accept_ranges(r);
    rp_http_clear_last_modified(r);
    rp_http_clear_etag(r);

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || r->header_only) {
        return rc;
    }

    if (rp_http_error_pages[err].len == 0) {
        return rp_http_send_special(r, RP_HTTP_LAST);
    }

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_ERROR;
    }

    b->memory = 1;
    b->pos = rp_http_error_pages[err].data;
    b->last = rp_http_error_pages[err].data + rp_http_error_pages[err].len;

    out[0].buf = b;
    out[0].next = &out[1];

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_ERROR;
    }

    b->memory = 1;

    b->pos = tail;
    b->last = tail + len;

    out[1].buf = b;
    out[1].next = NULL;

    if (msie_padding) {
        b = rp_calloc_buf(r->pool);
        if (b == NULL) {
            return RP_ERROR;
        }

        b->memory = 1;
        b->pos = rp_http_msie_padding;
        b->last = rp_http_msie_padding + sizeof(rp_http_msie_padding) - 1;

        out[1].next = &out[2];
        out[2].buf = b;
        out[2].next = NULL;
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    return rp_http_output_filter(r, &out[0]);
}


static rp_int_t
rp_http_send_refresh(rp_http_request_t *r)
{
    u_char       *p, *location;
    size_t        len, size;
    uintptr_t     escape;
    rp_int_t     rc;
    rp_buf_t    *b;
    rp_chain_t   out;

    len = r->headers_out.location->value.len;
    location = r->headers_out.location->value.data;

    escape = 2 * rp_escape_uri(NULL, location, len, RP_ESCAPE_REFRESH);

    size = sizeof(rp_http_msie_refresh_head) - 1
           + escape + len
           + sizeof(rp_http_msie_refresh_tail) - 1;

    r->err_status = RP_HTTP_OK;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    rp_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_lowcase = NULL;

    r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;

    r->headers_out.content_length_n = size;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    rp_http_clear_accept_ranges(r);
    rp_http_clear_last_modified(r);
    rp_http_clear_etag(r);

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || r->header_only) {
        return rc;
    }

    b = rp_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return RP_ERROR;
    }

    p = rp_cpymem(b->pos, rp_http_msie_refresh_head,
                   sizeof(rp_http_msie_refresh_head) - 1);

    if (escape == 0) {
        p = rp_cpymem(p, location, len);

    } else {
        p = (u_char *) rp_escape_uri(p, location, len, RP_ESCAPE_REFRESH);
    }

    b->last = rp_cpymem(p, rp_http_msie_refresh_tail,
                         sizeof(rp_http_msie_refresh_tail) - 1);

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return rp_http_output_filter(r, &out);
}

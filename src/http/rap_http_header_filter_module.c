
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap.h>


static rap_int_t rap_http_header_filter_init(rap_conf_t *cf);
static rap_int_t rap_http_header_filter(rap_http_request_t *r);


static rap_http_module_t  rap_http_header_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_header_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


rap_module_t  rap_http_header_filter_module = {
    RAP_MODULE_V1,
    &rap_http_header_filter_module_ctx,    /* module context */
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


static u_char rap_http_server_string[] = "Server: rap" CRLF;
static u_char rap_http_server_full_string[] = "Server: " RAP_VER CRLF;
static u_char rap_http_server_build_string[] = "Server: " RAP_VER_BUILD CRLF;


static rap_str_t rap_http_status_lines[] = {

    rap_string("200 OK"),
    rap_string("201 Created"),
    rap_string("202 Accepted"),
    rap_null_string,  /* "203 Non-Authoritative Information" */
    rap_string("204 No Content"),
    rap_null_string,  /* "205 Reset Content" */
    rap_string("206 Partial Content"),

    /* rap_null_string, */  /* "207 Multi-Status" */

#define RAP_HTTP_LAST_2XX  207
#define RAP_HTTP_OFF_3XX   (RAP_HTTP_LAST_2XX - 200)

    /* rap_null_string, */  /* "300 Multiple Choices" */

    rap_string("301 Moved Permanently"),
    rap_string("302 Moved Temporarily"),
    rap_string("303 See Other"),
    rap_string("304 Not Modified"),
    rap_null_string,  /* "305 Use Proxy" */
    rap_null_string,  /* "306 unused" */
    rap_string("307 Temporary Redirect"),
    rap_string("308 Permanent Redirect"),

#define RAP_HTTP_LAST_3XX  309
#define RAP_HTTP_OFF_4XX   (RAP_HTTP_LAST_3XX - 301 + RAP_HTTP_OFF_3XX)

    rap_string("400 Bad Request"),
    rap_string("401 Unauthorized"),
    rap_string("402 Payment Required"),
    rap_string("403 Forbidden"),
    rap_string("404 Not Found"),
    rap_string("405 Not Allowed"),
    rap_string("406 Not Acceptable"),
    rap_null_string,  /* "407 Proxy Authentication Required" */
    rap_string("408 Request Time-out"),
    rap_string("409 Conflict"),
    rap_string("410 Gone"),
    rap_string("411 Length Required"),
    rap_string("412 Precondition Failed"),
    rap_string("413 Request Entity Too Large"),
    rap_string("414 Request-URI Too Large"),
    rap_string("415 Unsupported Media Type"),
    rap_string("416 Requested Range Not Satisfiable"),
    rap_null_string,  /* "417 Expectation Failed" */
    rap_null_string,  /* "418 unused" */
    rap_null_string,  /* "419 unused" */
    rap_null_string,  /* "420 unused" */
    rap_string("421 Misdirected Request"),
    rap_null_string,  /* "422 Unprocessable Entity" */
    rap_null_string,  /* "423 Locked" */
    rap_null_string,  /* "424 Failed Dependency" */
    rap_null_string,  /* "425 unused" */
    rap_null_string,  /* "426 Upgrade Required" */
    rap_null_string,  /* "427 unused" */
    rap_null_string,  /* "428 Precondition Required" */
    rap_string("429 Too Many Requests"),

#define RAP_HTTP_LAST_4XX  430
#define RAP_HTTP_OFF_5XX   (RAP_HTTP_LAST_4XX - 400 + RAP_HTTP_OFF_4XX)

    rap_string("500 Internal Server Error"),
    rap_string("501 Not Implemented"),
    rap_string("502 Bad Gateway"),
    rap_string("503 Service Temporarily Unavailable"),
    rap_string("504 Gateway Time-out"),
    rap_string("505 HTTP Version Not Supported"),
    rap_null_string,        /* "506 Variant Also Negotiates" */
    rap_string("507 Insufficient Storage"),

    /* rap_null_string, */  /* "508 unused" */
    /* rap_null_string, */  /* "509 unused" */
    /* rap_null_string, */  /* "510 Not Extended" */

#define RAP_HTTP_LAST_5XX  508

};


rap_http_header_out_t  rap_http_headers_out[] = {
    { rap_string("Server"), offsetof(rap_http_headers_out_t, server) },
    { rap_string("Date"), offsetof(rap_http_headers_out_t, date) },
    { rap_string("Content-Length"),
                 offsetof(rap_http_headers_out_t, content_length) },
    { rap_string("Content-Encoding"),
                 offsetof(rap_http_headers_out_t, content_encoding) },
    { rap_string("Location"), offsetof(rap_http_headers_out_t, location) },
    { rap_string("Last-Modified"),
                 offsetof(rap_http_headers_out_t, last_modified) },
    { rap_string("Accept-Ranges"),
                 offsetof(rap_http_headers_out_t, accept_ranges) },
    { rap_string("Expires"), offsetof(rap_http_headers_out_t, expires) },
    { rap_string("Cache-Control"),
                 offsetof(rap_http_headers_out_t, cache_control) },
    { rap_string("ETag"), offsetof(rap_http_headers_out_t, etag) },

    { rap_null_string, 0 }
};


static rap_int_t
rap_http_header_filter(rap_http_request_t *r)
{
    u_char                    *p;
    size_t                     len;
    rap_str_t                  host, *status_line;
    rap_buf_t                 *b;
    rap_uint_t                 status, i, port;
    rap_chain_t                out;
    rap_list_part_t           *part;
    rap_table_elt_t           *header;
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;
    rap_http_core_srv_conf_t  *cscf;
    u_char                     addr[RAP_SOCKADDR_STRLEN];

    if (r->header_sent) {
        return RAP_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return RAP_OK;
    }

    if (r->http_version < RAP_HTTP_VERSION_10) {
        return RAP_OK;
    }

    if (r->method == RAP_HTTP_HEAD) {
        r->header_only = 1;
    }

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != RAP_HTTP_OK
            && r->headers_out.status != RAP_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != RAP_HTTP_NOT_MODIFIED)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
    }

    len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
          /* the end of the header */
          + sizeof(CRLF) - 1;

    /* status line */

    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
        status_line = &r->headers_out.status_line;
#if (RAP_SUPPRESS_WARN)
        status = 0;
#endif

    } else {

        status = r->headers_out.status;

        if (status >= RAP_HTTP_OK
            && status < RAP_HTTP_LAST_2XX)
        {
            /* 2XX */

            if (status == RAP_HTTP_NO_CONTENT) {
                r->header_only = 1;
                rap_str_null(&r->headers_out.content_type);
                r->headers_out.last_modified_time = -1;
                r->headers_out.last_modified = NULL;
                r->headers_out.content_length = NULL;
                r->headers_out.content_length_n = -1;
            }

            status -= RAP_HTTP_OK;
            status_line = &rap_http_status_lines[status];
            len += rap_http_status_lines[status].len;

        } else if (status >= RAP_HTTP_MOVED_PERMANENTLY
                   && status < RAP_HTTP_LAST_3XX)
        {
            /* 3XX */

            if (status == RAP_HTTP_NOT_MODIFIED) {
                r->header_only = 1;
            }

            status = status - RAP_HTTP_MOVED_PERMANENTLY + RAP_HTTP_OFF_3XX;
            status_line = &rap_http_status_lines[status];
            len += rap_http_status_lines[status].len;

        } else if (status >= RAP_HTTP_BAD_REQUEST
                   && status < RAP_HTTP_LAST_4XX)
        {
            /* 4XX */
            status = status - RAP_HTTP_BAD_REQUEST
                            + RAP_HTTP_OFF_4XX;

            status_line = &rap_http_status_lines[status];
            len += rap_http_status_lines[status].len;

        } else if (status >= RAP_HTTP_INTERNAL_SERVER_ERROR
                   && status < RAP_HTTP_LAST_5XX)
        {
            /* 5XX */
            status = status - RAP_HTTP_INTERNAL_SERVER_ERROR
                            + RAP_HTTP_OFF_5XX;

            status_line = &rap_http_status_lines[status];
            len += rap_http_status_lines[status].len;

        } else {
            len += RAP_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }

        if (status_line && status_line->len == 0) {
            status = r->headers_out.status;
            len += RAP_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_ON) {
            len += sizeof(rap_http_server_full_string) - 1;

        } else if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_BUILD) {
            len += sizeof(rap_http_server_build_string) - 1;

        } else {
            len += sizeof(rap_http_server_string) - 1;
        }
    }

    if (r->headers_out.date == NULL) {
        len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type.len + 2;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += sizeof("Content-Length: ") - 1 + RAP_OFF_T_LEN + 2;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    c = r->connection;

    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/'
        && clcf->absolute_redirect)
    {
        r->headers_out.location->hash = 0;

        if (clcf->server_name_in_redirect) {
            cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
            host = cscf->server_name;

        } else if (r->headers_in.server.len) {
            host = r->headers_in.server;

        } else {
            host.len = RAP_SOCKADDR_STRLEN;
            host.data = addr;

            if (rap_connection_local_sockaddr(c, &host, 0) != RAP_OK) {
                return RAP_ERROR;
            }
        }

        port = rap_inet_get_port(c->local_sockaddr);

        len += sizeof("Location: https://") - 1
               + host.len
               + r->headers_out.location->value.len + 2;

        if (clcf->port_in_redirect) {

#if (RAP_HTTP_SSL)
            if (c->ssl)
                port = (port == 443) ? 0 : port;
            else
#endif
                port = (port == 80) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            len += sizeof(":65535") - 1;
        }

    } else {
        rap_str_null(&host);
        port = 0;
    }

    if (r->chunked) {
        len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
    }

    if (r->headers_out.status == RAP_HTTP_SWITCHING_PROTOCOLS) {
        len += sizeof("Connection: upgrade" CRLF) - 1;

    } else if (r->keepalive) {
        len += sizeof("Connection: keep-alive" CRLF) - 1;

        /*
         * MSIE and Opera ignore the "Keep-Alive: timeout=<N>" header.
         * MSIE keeps the connection alive for about 60-65 seconds.
         * Opera keeps the connection alive very long.
         * Mozilla keeps the connection alive for N plus about 1-10 seconds.
         * Konqueror keeps the connection alive for about N seconds.
         */

        if (clcf->keepalive_header) {
            len += sizeof("Keep-Alive: timeout=") - 1 + RAP_TIME_T_LEN + 2;
        }

    } else {
        len += sizeof("Connection: close" CRLF) - 1;
    }

#if (RAP_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += sizeof("Vary: Accept-Encoding" CRLF) - 1;

        } else {
            r->gzip_vary = 0;
        }
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
               + sizeof(CRLF) - 1;
    }

    b = rap_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return RAP_ERROR;
    }

    /* "HTTP/1.x " */
    b->last = rap_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (status_line) {
        b->last = rap_copy(b->last, status_line->data, status_line->len);

    } else {
        b->last = rap_sprintf(b->last, "%03ui ", status);
    }
    *b->last++ = CR; *b->last++ = LF;

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_ON) {
            p = rap_http_server_full_string;
            len = sizeof(rap_http_server_full_string) - 1;

        } else if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_BUILD) {
            p = rap_http_server_build_string;
            len = sizeof(rap_http_server_build_string) - 1;

        } else {
            p = rap_http_server_string;
            len = sizeof(rap_http_server_string) - 1;
        }

        b->last = rap_cpymem(b->last, p, len);
    }

    if (r->headers_out.date == NULL) {
        b->last = rap_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
        b->last = rap_cpymem(b->last, rap_cached_http_time.data,
                             rap_cached_http_time.len);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_type.len) {
        b->last = rap_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = b->last;
        b->last = rap_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = rap_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = rap_copy(b->last, r->headers_out.charset.data,
                               r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = b->last - p;
            r->headers_out.content_type.data = p;
        }

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        b->last = rap_sprintf(b->last, "Content-Length: %O" CRLF,
                              r->headers_out.content_length_n);
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        b->last = rap_cpymem(b->last, "Last-Modified: ",
                             sizeof("Last-Modified: ") - 1);
        b->last = rap_http_time(b->last, r->headers_out.last_modified_time);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (host.data) {

        p = b->last + sizeof("Location: ") - 1;

        b->last = rap_cpymem(b->last, "Location: http",
                             sizeof("Location: http") - 1);

#if (RAP_HTTP_SSL)
        if (c->ssl) {
            *b->last++ ='s';
        }
#endif

        *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';
        b->last = rap_copy(b->last, host.data, host.len);

        if (port) {
            b->last = rap_sprintf(b->last, ":%ui", port);
        }

        b->last = rap_copy(b->last, r->headers_out.location->value.data,
                           r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = b->last - p;
        r->headers_out.location->value.data = p;
        rap_str_set(&r->headers_out.location->key, "Location");

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->chunked) {
        b->last = rap_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    if (r->headers_out.status == RAP_HTTP_SWITCHING_PROTOCOLS) {
        b->last = rap_cpymem(b->last, "Connection: upgrade" CRLF,
                             sizeof("Connection: upgrade" CRLF) - 1);

    } else if (r->keepalive) {
        b->last = rap_cpymem(b->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

        if (clcf->keepalive_header) {
            b->last = rap_sprintf(b->last, "Keep-Alive: timeout=%T" CRLF,
                                  clcf->keepalive_header);
        }

    } else {
        b->last = rap_cpymem(b->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
    }

#if (RAP_HTTP_GZIP)
    if (r->gzip_vary) {
        b->last = rap_cpymem(b->last, "Vary: Accept-Encoding" CRLF,
                             sizeof("Vary: Accept-Encoding" CRLF) - 1);
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        b->last = rap_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = rap_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "%*s", (size_t) (b->last - b->pos), b->pos);

    /* the end of HTTP header */
    *b->last++ = CR; *b->last++ = LF;

    r->header_size = b->last - b->pos;

    if (r->header_only) {
        b->last_buf = 1;
    }

    out.buf = b;
    out.next = NULL;

    return rap_http_write_filter(r, &out);
}


static rap_int_t
rap_http_header_filter_init(rap_conf_t *cf)
{
    rap_http_top_header_filter = rap_http_header_filter;

    return RAP_OK;
}

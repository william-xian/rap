
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rap.h>


static rp_int_t rp_http_header_filter_init(rp_conf_t *cf);
static rp_int_t rp_http_header_filter(rp_http_request_t *r);


static rp_http_module_t  rp_http_header_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_header_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


rp_module_t  rp_http_header_filter_module = {
    RP_MODULE_V1,
    &rp_http_header_filter_module_ctx,    /* module context */
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


static u_char rp_http_server_string[] = "Server: rap" CRLF;
static u_char rp_http_server_full_string[] = "Server: " RAP_VER CRLF;
static u_char rp_http_server_build_string[] = "Server: " RAP_VER_BUILD CRLF;


static rp_str_t rp_http_status_lines[] = {

    rp_string("200 OK"),
    rp_string("201 Created"),
    rp_string("202 Accepted"),
    rp_null_string,  /* "203 Non-Authoritative Information" */
    rp_string("204 No Content"),
    rp_null_string,  /* "205 Reset Content" */
    rp_string("206 Partial Content"),

    /* rp_null_string, */  /* "207 Multi-Status" */

#define RP_HTTP_LAST_2XX  207
#define RP_HTTP_OFF_3XX   (RP_HTTP_LAST_2XX - 200)

    /* rp_null_string, */  /* "300 Multiple Choices" */

    rp_string("301 Moved Permanently"),
    rp_string("302 Moved Temporarily"),
    rp_string("303 See Other"),
    rp_string("304 Not Modified"),
    rp_null_string,  /* "305 Use Proxy" */
    rp_null_string,  /* "306 unused" */
    rp_string("307 Temporary Redirect"),
    rp_string("308 Permanent Redirect"),

#define RP_HTTP_LAST_3XX  309
#define RP_HTTP_OFF_4XX   (RP_HTTP_LAST_3XX - 301 + RP_HTTP_OFF_3XX)

    rp_string("400 Bad Request"),
    rp_string("401 Unauthorized"),
    rp_string("402 Payment Required"),
    rp_string("403 Forbidden"),
    rp_string("404 Not Found"),
    rp_string("405 Not Allowed"),
    rp_string("406 Not Acceptable"),
    rp_null_string,  /* "407 Proxy Authentication Required" */
    rp_string("408 Request Time-out"),
    rp_string("409 Conflict"),
    rp_string("410 Gone"),
    rp_string("411 Length Required"),
    rp_string("412 Precondition Failed"),
    rp_string("413 Request Entity Too Large"),
    rp_string("414 Request-URI Too Large"),
    rp_string("415 Unsupported Media Type"),
    rp_string("416 Requested Range Not Satisfiable"),
    rp_null_string,  /* "417 Expectation Failed" */
    rp_null_string,  /* "418 unused" */
    rp_null_string,  /* "419 unused" */
    rp_null_string,  /* "420 unused" */
    rp_string("421 Misdirected Request"),
    rp_null_string,  /* "422 Unprocessable Entity" */
    rp_null_string,  /* "423 Locked" */
    rp_null_string,  /* "424 Failed Dependency" */
    rp_null_string,  /* "425 unused" */
    rp_null_string,  /* "426 Upgrade Required" */
    rp_null_string,  /* "427 unused" */
    rp_null_string,  /* "428 Precondition Required" */
    rp_string("429 Too Many Requests"),

#define RP_HTTP_LAST_4XX  430
#define RP_HTTP_OFF_5XX   (RP_HTTP_LAST_4XX - 400 + RP_HTTP_OFF_4XX)

    rp_string("500 Internal Server Error"),
    rp_string("501 Not Implemented"),
    rp_string("502 Bad Gateway"),
    rp_string("503 Service Temporarily Unavailable"),
    rp_string("504 Gateway Time-out"),
    rp_string("505 HTTP Version Not Supported"),
    rp_null_string,        /* "506 Variant Also Negotiates" */
    rp_string("507 Insufficient Storage"),

    /* rp_null_string, */  /* "508 unused" */
    /* rp_null_string, */  /* "509 unused" */
    /* rp_null_string, */  /* "510 Not Extended" */

#define RP_HTTP_LAST_5XX  508

};


rp_http_header_out_t  rp_http_headers_out[] = {
    { rp_string("Server"), offsetof(rp_http_headers_out_t, server) },
    { rp_string("Date"), offsetof(rp_http_headers_out_t, date) },
    { rp_string("Content-Length"),
                 offsetof(rp_http_headers_out_t, content_length) },
    { rp_string("Content-Encoding"),
                 offsetof(rp_http_headers_out_t, content_encoding) },
    { rp_string("Location"), offsetof(rp_http_headers_out_t, location) },
    { rp_string("Last-Modified"),
                 offsetof(rp_http_headers_out_t, last_modified) },
    { rp_string("Accept-Ranges"),
                 offsetof(rp_http_headers_out_t, accept_ranges) },
    { rp_string("Expires"), offsetof(rp_http_headers_out_t, expires) },
    { rp_string("Cache-Control"),
                 offsetof(rp_http_headers_out_t, cache_control) },
    { rp_string("ETag"), offsetof(rp_http_headers_out_t, etag) },

    { rp_null_string, 0 }
};


static rp_int_t
rp_http_header_filter(rp_http_request_t *r)
{
    u_char                    *p;
    size_t                     len;
    rp_str_t                  host, *status_line;
    rp_buf_t                 *b;
    rp_uint_t                 status, i, port;
    rp_chain_t                out;
    rp_list_part_t           *part;
    rp_table_elt_t           *header;
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;
    rp_http_core_srv_conf_t  *cscf;
    u_char                     addr[RP_SOCKADDR_STRLEN];

    if (r->header_sent) {
        return RP_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return RP_OK;
    }

    if (r->http_version < RP_HTTP_VERSION_10) {
        return RP_OK;
    }

    if (r->method == RP_HTTP_HEAD) {
        r->header_only = 1;
    }

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != RP_HTTP_OK
            && r->headers_out.status != RP_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != RP_HTTP_NOT_MODIFIED)
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
#if (RP_SUPPRESS_WARN)
        status = 0;
#endif

    } else {

        status = r->headers_out.status;

        if (status >= RP_HTTP_OK
            && status < RP_HTTP_LAST_2XX)
        {
            /* 2XX */

            if (status == RP_HTTP_NO_CONTENT) {
                r->header_only = 1;
                rp_str_null(&r->headers_out.content_type);
                r->headers_out.last_modified_time = -1;
                r->headers_out.last_modified = NULL;
                r->headers_out.content_length = NULL;
                r->headers_out.content_length_n = -1;
            }

            status -= RP_HTTP_OK;
            status_line = &rp_http_status_lines[status];
            len += rp_http_status_lines[status].len;

        } else if (status >= RP_HTTP_MOVED_PERMANENTLY
                   && status < RP_HTTP_LAST_3XX)
        {
            /* 3XX */

            if (status == RP_HTTP_NOT_MODIFIED) {
                r->header_only = 1;
            }

            status = status - RP_HTTP_MOVED_PERMANENTLY + RP_HTTP_OFF_3XX;
            status_line = &rp_http_status_lines[status];
            len += rp_http_status_lines[status].len;

        } else if (status >= RP_HTTP_BAD_REQUEST
                   && status < RP_HTTP_LAST_4XX)
        {
            /* 4XX */
            status = status - RP_HTTP_BAD_REQUEST
                            + RP_HTTP_OFF_4XX;

            status_line = &rp_http_status_lines[status];
            len += rp_http_status_lines[status].len;

        } else if (status >= RP_HTTP_INTERNAL_SERVER_ERROR
                   && status < RP_HTTP_LAST_5XX)
        {
            /* 5XX */
            status = status - RP_HTTP_INTERNAL_SERVER_ERROR
                            + RP_HTTP_OFF_5XX;

            status_line = &rp_http_status_lines[status];
            len += rp_http_status_lines[status].len;

        } else {
            len += RP_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }

        if (status_line && status_line->len == 0) {
            status = r->headers_out.status;
            len += RP_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == RP_HTTP_SERVER_TOKENS_ON) {
            len += sizeof(rp_http_server_full_string) - 1;

        } else if (clcf->server_tokens == RP_HTTP_SERVER_TOKENS_BUILD) {
            len += sizeof(rp_http_server_build_string) - 1;

        } else {
            len += sizeof(rp_http_server_string) - 1;
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
        len += sizeof("Content-Length: ") - 1 + RP_OFF_T_LEN + 2;
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
            cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);
            host = cscf->server_name;

        } else if (r->headers_in.server.len) {
            host = r->headers_in.server;

        } else {
            host.len = RP_SOCKADDR_STRLEN;
            host.data = addr;

            if (rp_connection_local_sockaddr(c, &host, 0) != RP_OK) {
                return RP_ERROR;
            }
        }

        port = rp_inet_get_port(c->local_sockaddr);

        len += sizeof("Location: https://") - 1
               + host.len
               + r->headers_out.location->value.len + 2;

        if (clcf->port_in_redirect) {

#if (RP_HTTP_SSL)
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
        rp_str_null(&host);
        port = 0;
    }

    if (r->chunked) {
        len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
    }

    if (r->headers_out.status == RP_HTTP_SWITCHING_PROTOCOLS) {
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
            len += sizeof("Keep-Alive: timeout=") - 1 + RP_TIME_T_LEN + 2;
        }

    } else {
        len += sizeof("Connection: close" CRLF) - 1;
    }

#if (RP_HTTP_GZIP)
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

    b = rp_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return RP_ERROR;
    }

    /* "HTTP/1.x " */
    b->last = rp_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (status_line) {
        b->last = rp_copy(b->last, status_line->data, status_line->len);

    } else {
        b->last = rp_sprintf(b->last, "%03ui ", status);
    }
    *b->last++ = CR; *b->last++ = LF;

    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == RP_HTTP_SERVER_TOKENS_ON) {
            p = rp_http_server_full_string;
            len = sizeof(rp_http_server_full_string) - 1;

        } else if (clcf->server_tokens == RP_HTTP_SERVER_TOKENS_BUILD) {
            p = rp_http_server_build_string;
            len = sizeof(rp_http_server_build_string) - 1;

        } else {
            p = rp_http_server_string;
            len = sizeof(rp_http_server_string) - 1;
        }

        b->last = rp_cpymem(b->last, p, len);
    }

    if (r->headers_out.date == NULL) {
        b->last = rp_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
        b->last = rp_cpymem(b->last, rp_cached_http_time.data,
                             rp_cached_http_time.len);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->headers_out.content_type.len) {
        b->last = rp_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = b->last;
        b->last = rp_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = rp_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = rp_copy(b->last, r->headers_out.charset.data,
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
        b->last = rp_sprintf(b->last, "Content-Length: %O" CRLF,
                              r->headers_out.content_length_n);
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        b->last = rp_cpymem(b->last, "Last-Modified: ",
                             sizeof("Last-Modified: ") - 1);
        b->last = rp_http_time(b->last, r->headers_out.last_modified_time);

        *b->last++ = CR; *b->last++ = LF;
    }

    if (host.data) {

        p = b->last + sizeof("Location: ") - 1;

        b->last = rp_cpymem(b->last, "Location: http",
                             sizeof("Location: http") - 1);

#if (RP_HTTP_SSL)
        if (c->ssl) {
            *b->last++ ='s';
        }
#endif

        *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';
        b->last = rp_copy(b->last, host.data, host.len);

        if (port) {
            b->last = rp_sprintf(b->last, ":%ui", port);
        }

        b->last = rp_copy(b->last, r->headers_out.location->value.data,
                           r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = b->last - p;
        r->headers_out.location->value.data = p;
        rp_str_set(&r->headers_out.location->key, "Location");

        *b->last++ = CR; *b->last++ = LF;
    }

    if (r->chunked) {
        b->last = rp_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    if (r->headers_out.status == RP_HTTP_SWITCHING_PROTOCOLS) {
        b->last = rp_cpymem(b->last, "Connection: upgrade" CRLF,
                             sizeof("Connection: upgrade" CRLF) - 1);

    } else if (r->keepalive) {
        b->last = rp_cpymem(b->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

        if (clcf->keepalive_header) {
            b->last = rp_sprintf(b->last, "Keep-Alive: timeout=%T" CRLF,
                                  clcf->keepalive_header);
        }

    } else {
        b->last = rp_cpymem(b->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
    }

#if (RP_HTTP_GZIP)
    if (r->gzip_vary) {
        b->last = rp_cpymem(b->last, "Vary: Accept-Encoding" CRLF,
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

        b->last = rp_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = rp_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "%*s", (size_t) (b->last - b->pos), b->pos);

    /* the end of HTTP header */
    *b->last++ = CR; *b->last++ = LF;

    r->header_size = b->last - b->pos;

    if (r->header_only) {
        b->last_buf = 1;
    }

    out.buf = b;
    out.next = NULL;

    return rp_http_write_filter(r, &out);
}


static rp_int_t
rp_http_header_filter_init(rp_conf_t *cf)
{
    rp_http_top_header_filter = rp_http_header_filter;

    return RP_OK;
}

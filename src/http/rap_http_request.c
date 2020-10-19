
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static void rap_http_wait_request_handler(rap_event_t *ev);
static rap_http_request_t *rap_http_alloc_request(rap_connection_t *c);
static void rap_http_process_request_line(rap_event_t *rev);
static void rap_http_process_request_headers(rap_event_t *rev);
static ssize_t rap_http_read_request_header(rap_http_request_t *r);
static rap_int_t rap_http_alloc_large_header_buffer(rap_http_request_t *r,
    rap_uint_t request_line);

static rap_int_t rap_http_process_header_line(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_process_unique_header_line(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_process_multi_header_lines(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_process_host(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_process_connection(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_process_user_agent(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);

static rap_int_t rap_http_validate_host(rap_str_t *host, rap_pool_t *pool,
    rap_uint_t alloc);
static rap_int_t rap_http_set_virtual_server(rap_http_request_t *r,
    rap_str_t *host);
static rap_int_t rap_http_find_virtual_server(rap_connection_t *c,
    rap_http_virtual_names_t *virtual_names, rap_str_t *host,
    rap_http_request_t *r, rap_http_core_srv_conf_t **cscfp);

static void rap_http_request_handler(rap_event_t *ev);
static void rap_http_terminate_request(rap_http_request_t *r, rap_int_t rc);
static void rap_http_terminate_handler(rap_http_request_t *r);
static void rap_http_finalize_connection(rap_http_request_t *r);
static rap_int_t rap_http_set_write_handler(rap_http_request_t *r);
static void rap_http_writer(rap_http_request_t *r);
static void rap_http_request_finalizer(rap_http_request_t *r);

static void rap_http_set_keepalive(rap_http_request_t *r);
static void rap_http_keepalive_handler(rap_event_t *ev);
static void rap_http_set_lingering_close(rap_http_request_t *r);
static void rap_http_lingering_close_handler(rap_event_t *ev);
static rap_int_t rap_http_post_action(rap_http_request_t *r);
static void rap_http_close_request(rap_http_request_t *r, rap_int_t error);
static void rap_http_log_request(rap_http_request_t *r);

static u_char *rap_http_log_error(rap_log_t *log, u_char *buf, size_t len);
static u_char *rap_http_log_error_handler(rap_http_request_t *r,
    rap_http_request_t *sr, u_char *buf, size_t len);

#if (RAP_HTTP_SSL)
static void rap_http_ssl_handshake(rap_event_t *rev);
static void rap_http_ssl_handshake_handler(rap_connection_t *c);
#endif


static char *rap_http_client_errors[] = {

    /* RAP_HTTP_PARSE_INVALID_METHOD */
    "client sent invalid method",

    /* RAP_HTTP_PARSE_INVALID_REQUEST */
    "client sent invalid request",

    /* RAP_HTTP_PARSE_INVALID_VERSION */
    "client sent invalid version",

    /* RAP_HTTP_PARSE_INVALID_09_METHOD */
    "client sent invalid method in HTTP/0.9 request"
};


rap_http_header_t  rap_http_headers_in[] = {
    { rap_string("Host"), offsetof(rap_http_headers_in_t, host),
                 rap_http_process_host },

    { rap_string("Connection"), offsetof(rap_http_headers_in_t, connection),
                 rap_http_process_connection },

    { rap_string("If-Modified-Since"),
                 offsetof(rap_http_headers_in_t, if_modified_since),
                 rap_http_process_unique_header_line },

    { rap_string("If-Unmodified-Since"),
                 offsetof(rap_http_headers_in_t, if_unmodified_since),
                 rap_http_process_unique_header_line },

    { rap_string("If-Match"),
                 offsetof(rap_http_headers_in_t, if_match),
                 rap_http_process_unique_header_line },

    { rap_string("If-None-Match"),
                 offsetof(rap_http_headers_in_t, if_none_match),
                 rap_http_process_unique_header_line },

    { rap_string("User-Agent"), offsetof(rap_http_headers_in_t, user_agent),
                 rap_http_process_user_agent },

    { rap_string("Referer"), offsetof(rap_http_headers_in_t, referer),
                 rap_http_process_header_line },

    { rap_string("Content-Length"),
                 offsetof(rap_http_headers_in_t, content_length),
                 rap_http_process_unique_header_line },

    { rap_string("Content-Range"),
                 offsetof(rap_http_headers_in_t, content_range),
                 rap_http_process_unique_header_line },

    { rap_string("Content-Type"),
                 offsetof(rap_http_headers_in_t, content_type),
                 rap_http_process_header_line },

    { rap_string("Range"), offsetof(rap_http_headers_in_t, range),
                 rap_http_process_header_line },

    { rap_string("If-Range"),
                 offsetof(rap_http_headers_in_t, if_range),
                 rap_http_process_unique_header_line },

    { rap_string("Transfer-Encoding"),
                 offsetof(rap_http_headers_in_t, transfer_encoding),
                 rap_http_process_unique_header_line },

    { rap_string("TE"),
                 offsetof(rap_http_headers_in_t, te),
                 rap_http_process_header_line },

    { rap_string("Expect"),
                 offsetof(rap_http_headers_in_t, expect),
                 rap_http_process_unique_header_line },

    { rap_string("Upgrade"),
                 offsetof(rap_http_headers_in_t, upgrade),
                 rap_http_process_header_line },

#if (RAP_HTTP_GZIP || RAP_HTTP_HEADERS)
    { rap_string("Accept-Encoding"),
                 offsetof(rap_http_headers_in_t, accept_encoding),
                 rap_http_process_header_line },

    { rap_string("Via"), offsetof(rap_http_headers_in_t, via),
                 rap_http_process_header_line },
#endif

    { rap_string("Authorization"),
                 offsetof(rap_http_headers_in_t, authorization),
                 rap_http_process_unique_header_line },

    { rap_string("Keep-Alive"), offsetof(rap_http_headers_in_t, keep_alive),
                 rap_http_process_header_line },

#if (RAP_HTTP_X_FORWARDED_FOR)
    { rap_string("X-Forwarded-For"),
                 offsetof(rap_http_headers_in_t, x_forwarded_for),
                 rap_http_process_multi_header_lines },
#endif

#if (RAP_HTTP_REALIP)
    { rap_string("X-Real-IP"),
                 offsetof(rap_http_headers_in_t, x_real_ip),
                 rap_http_process_header_line },
#endif

#if (RAP_HTTP_HEADERS)
    { rap_string("Accept"), offsetof(rap_http_headers_in_t, accept),
                 rap_http_process_header_line },

    { rap_string("Accept-Language"),
                 offsetof(rap_http_headers_in_t, accept_language),
                 rap_http_process_header_line },
#endif

#if (RAP_HTTP_DAV)
    { rap_string("Depth"), offsetof(rap_http_headers_in_t, depth),
                 rap_http_process_header_line },

    { rap_string("Destination"), offsetof(rap_http_headers_in_t, destination),
                 rap_http_process_header_line },

    { rap_string("Overwrite"), offsetof(rap_http_headers_in_t, overwrite),
                 rap_http_process_header_line },

    { rap_string("Date"), offsetof(rap_http_headers_in_t, date),
                 rap_http_process_header_line },
#endif

    { rap_string("Cookie"), offsetof(rap_http_headers_in_t, cookies),
                 rap_http_process_multi_header_lines },

    { rap_null_string, 0, NULL }
};


void
rap_http_init_connection(rap_connection_t *c)
{
    rap_uint_t              i;
    rap_event_t            *rev;
    struct sockaddr_in     *sin;
    rap_http_port_t        *port;
    rap_http_in_addr_t     *addr;
    rap_http_log_ctx_t     *ctx;
    rap_http_connection_t  *hc;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6    *sin6;
    rap_http_in6_addr_t    *addr6;
#endif

    hc = rap_pcalloc(c->pool, sizeof(rap_http_connection_t));
    if (hc == NULL) {
        rap_http_close_connection(c);
        return;
    }

    c->data = hc;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in rap_http_server_addr()
         * is required to determine a server address
         */

        if (rap_connection_local_sockaddr(c, NULL, 0) != RAP_OK) {
            rap_http_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (rap_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            hc->addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            hc->addr_conf = &addr[i].conf;

            break;
        }

    } else {

        switch (c->local_sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            hc->addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            hc->addr_conf = &addr[0].conf;
            break;
        }
    }

    /* the default server configuration for the address:port */
    hc->conf_ctx = hc->addr_conf->default_server->ctx;

    ctx = rap_palloc(c->pool, sizeof(rap_http_log_ctx_t));
    if (ctx == NULL) {
        rap_http_close_connection(c);
        return;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log->connection = c->number;
    c->log->handler = rap_http_log_error;
    c->log->data = ctx;
    c->log->action = "waiting for request";

    c->log_error = RAP_ERROR_INFO;

    rev = c->read;
    rev->handler = rap_http_wait_request_handler;
    c->write->handler = rap_http_empty_handler;

#if (RAP_HTTP_V2)
    if (hc->addr_conf->http2) {
        rev->handler = rap_http_v2_init;
    }
#endif

#if (RAP_HTTP_SSL)
    {
    rap_http_ssl_srv_conf_t  *sscf;

    sscf = rap_http_get_module_srv_conf(hc->conf_ctx, rap_http_ssl_module);

    if (sscf->enable || hc->addr_conf->ssl) {
        hc->ssl = 1;
        c->log->action = "SSL handshaking";
        rev->handler = rap_http_ssl_handshake;
    }
    }
#endif

    if (hc->addr_conf->proxy_protocol) {
        hc->proxy_protocol = 1;
        c->log->action = "reading PROXY protocol";
    }

    if (rev->ready) {
        /* the deferred accept(), iocp */

        if (rap_use_accept_mutex) {
            rap_post_event(rev, &rap_posted_events);
            return;
        }

        rev->handler(rev);
        return;
    }

    rap_add_timer(rev, c->listening->post_accept_timeout);
    rap_reusable_connection(c, 1);

    if (rap_handle_read_event(rev, 0) != RAP_OK) {
        rap_http_close_connection(c);
        return;
    }
}


static void
rap_http_wait_request_handler(rap_event_t *rev)
{
    u_char                    *p;
    size_t                     size;
    ssize_t                    n;
    rap_buf_t                 *b;
    rap_connection_t          *c;
    rap_http_connection_t     *hc;
    rap_http_core_srv_conf_t  *cscf;

    c = rev->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        rap_http_close_connection(c);
        return;
    }

    if (c->close) {
        rap_http_close_connection(c);
        return;
    }

    hc = c->data;
    cscf = rap_http_get_module_srv_conf(hc->conf_ctx, rap_http_core_module);

    size = cscf->client_header_buffer_size;

    b = c->buffer;

    if (b == NULL) {
        b = rap_create_temp_buf(c->pool, size);
        if (b == NULL) {
            rap_http_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = rap_palloc(c->pool, size);
        if (b->start == NULL) {
            rap_http_close_connection(c);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    n = c->recv(c, b->last, size);

    if (n == RAP_AGAIN) {

        if (!rev->timer_set) {
            rap_add_timer(rev, c->listening->post_accept_timeout);
            rap_reusable_connection(c, 1);
        }

        if (rap_handle_read_event(rev, 0) != RAP_OK) {
            rap_http_close_connection(c);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        if (rap_pfree(c->pool, b->start) == RAP_OK) {
            b->start = NULL;
        }

        return;
    }

    if (n == RAP_ERROR) {
        rap_http_close_connection(c);
        return;
    }

    if (n == 0) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "client closed connection");
        rap_http_close_connection(c);
        return;
    }

    b->last += n;

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = rap_proxy_protocol_read(c, b->pos, b->last);

        if (p == NULL) {
            rap_http_close_connection(c);
            return;
        }

        b->pos = p;

        if (b->pos == b->last) {
            c->log->action = "waiting for request";
            b->pos = b->start;
            b->last = b->start;
            rap_post_event(rev, &rap_posted_events);
            return;
        }
    }

    c->log->action = "reading client request line";

    rap_reusable_connection(c, 0);

    c->data = rap_http_create_request(c);
    if (c->data == NULL) {
        rap_http_close_connection(c);
        return;
    }

    rev->handler = rap_http_process_request_line;
    rap_http_process_request_line(rev);
}


rap_http_request_t *
rap_http_create_request(rap_connection_t *c)
{
    rap_http_request_t        *r;
    rap_http_log_ctx_t        *ctx;
    rap_http_core_loc_conf_t  *clcf;

    r = rap_http_alloc_request(c);
    if (r == NULL) {
        return NULL;
    }

    c->requests++;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rap_set_connection_log(c, clcf->error_log);

    ctx = c->log->data;
    ctx->request = r;
    ctx->current_request = r;

#if (RAP_STAT_STUB)
    (void) rap_atomic_fetch_add(rap_stat_reading, 1);
    r->stat_reading = 1;
    (void) rap_atomic_fetch_add(rap_stat_requests, 1);
#endif

    return r;
}


static rap_http_request_t *
rap_http_alloc_request(rap_connection_t *c)
{
    rap_pool_t                 *pool;
    rap_time_t                 *tp;
    rap_http_request_t         *r;
    rap_http_connection_t      *hc;
    rap_http_core_srv_conf_t   *cscf;
    rap_http_core_main_conf_t  *cmcf;

    hc = c->data;

    cscf = rap_http_get_module_srv_conf(hc->conf_ctx, rap_http_core_module);

    pool = rap_create_pool(cscf->request_pool_size, c->log);
    if (pool == NULL) {
        return NULL;
    }

    r = rap_pcalloc(pool, sizeof(rap_http_request_t));
    if (r == NULL) {
        rap_destroy_pool(pool);
        return NULL;
    }

    r->pool = pool;

    r->http_connection = hc;
    r->signature = RAP_HTTP_MODULE;
    r->connection = c;

    r->main_conf = hc->conf_ctx->main_conf;
    r->srv_conf = hc->conf_ctx->srv_conf;
    r->loc_conf = hc->conf_ctx->loc_conf;

    r->read_event_handler = rap_http_block_reading;

    r->header_in = hc->busy ? hc->busy->buf : c->buffer;

    if (rap_list_init(&r->headers_out.headers, r->pool, 20,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        rap_destroy_pool(r->pool);
        return NULL;
    }

    if (rap_list_init(&r->headers_out.trailers, r->pool, 4,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        rap_destroy_pool(r->pool);
        return NULL;
    }

    r->ctx = rap_pcalloc(r->pool, sizeof(void *) * rap_http_max_module);
    if (r->ctx == NULL) {
        rap_destroy_pool(r->pool);
        return NULL;
    }

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    r->variables = rap_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(rap_http_variable_value_t));
    if (r->variables == NULL) {
        rap_destroy_pool(r->pool);
        return NULL;
    }

#if (RAP_HTTP_SSL)
    if (c->ssl) {
        r->main_filter_need_in_memory = 1;
    }
#endif

    r->main = r;
    r->count = 1;

    tp = rap_timeofday();
    r->start_sec = tp->sec;
    r->start_msec = tp->msec;

    r->method = RAP_HTTP_UNKNOWN;
    r->http_version = RAP_HTTP_VERSION_10;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->uri_changes = RAP_HTTP_MAX_URI_CHANGES + 1;
    r->subrequests = RAP_HTTP_MAX_SUBREQUESTS + 1;

    r->http_state = RAP_HTTP_READING_REQUEST_STATE;

    r->log_handler = rap_http_log_error_handler;

    return r;
}


#if (RAP_HTTP_SSL)

static void
rap_http_ssl_handshake(rap_event_t *rev)
{
    u_char                    *p, buf[RAP_PROXY_PROTOCOL_MAX_HEADER + 1];
    size_t                     size;
    ssize_t                    n;
    rap_err_t                  err;
    rap_int_t                  rc;
    rap_connection_t          *c;
    rap_http_connection_t     *hc;
    rap_http_ssl_srv_conf_t   *sscf;
    rap_http_core_loc_conf_t  *clcf;

    c = rev->data;
    hc = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http check ssl handshake");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        rap_http_close_connection(c);
        return;
    }

    if (c->close) {
        rap_http_close_connection(c);
        return;
    }

    size = hc->proxy_protocol ? sizeof(buf) : 1;

    n = recv(c->fd, (char *) buf, size, MSG_PEEK);

    err = rap_socket_errno;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, rev->log, 0, "http recv(): %z", n);

    if (n == -1) {
        if (err == RAP_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                rap_add_timer(rev, c->listening->post_accept_timeout);
                rap_reusable_connection(c, 1);
            }

            if (rap_handle_read_event(rev, 0) != RAP_OK) {
                rap_http_close_connection(c);
            }

            return;
        }

        rap_connection_error(c, err, "recv() failed");
        rap_http_close_connection(c);

        return;
    }

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = rap_proxy_protocol_read(c, buf, buf + n);

        if (p == NULL) {
            rap_http_close_connection(c);
            return;
        }

        size = p - buf;

        if (c->recv(c, buf, size) != (ssize_t) size) {
            rap_http_close_connection(c);
            return;
        }

        c->log->action = "SSL handshaking";

        if (n == (ssize_t) size) {
            rap_post_event(rev, &rap_posted_events);
            return;
        }

        n = 1;
        buf[0] = *p;
    }

    if (n == 1) {
        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, rev->log, 0,
                           "https ssl handshake: 0x%02Xd", buf[0]);

            clcf = rap_http_get_module_loc_conf(hc->conf_ctx,
                                                rap_http_core_module);

            if (clcf->tcp_nodelay && rap_tcp_nodelay(c) != RAP_OK) {
                rap_http_close_connection(c);
                return;
            }

            sscf = rap_http_get_module_srv_conf(hc->conf_ctx,
                                                rap_http_ssl_module);

            if (rap_ssl_create_connection(&sscf->ssl, c, RAP_SSL_BUFFER)
                != RAP_OK)
            {
                rap_http_close_connection(c);
                return;
            }

            rap_reusable_connection(c, 0);

            rc = rap_ssl_handshake(c);

            if (rc == RAP_AGAIN) {

                if (!rev->timer_set) {
                    rap_add_timer(rev, c->listening->post_accept_timeout);
                }

                c->ssl->handler = rap_http_ssl_handshake_handler;
                return;
            }

            rap_http_ssl_handshake_handler(c);

            return;
        }

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, rev->log, 0, "plain http");

        c->log->action = "waiting for request";

        rev->handler = rap_http_wait_request_handler;
        rap_http_wait_request_handler(rev);

        return;
    }

    rap_log_error(RAP_LOG_INFO, c->log, 0, "client closed connection");
    rap_http_close_connection(c);
}


static void
rap_http_ssl_handshake_handler(rap_connection_t *c)
{
    if (c->ssl->handshaked) {

        /*
         * The majority of browsers do not send the "close notify" alert.
         * Among them are MSIE, old Mozilla, Netscape 4, Konqueror,
         * and Links.  And what is more, MSIE ignores the server's alert.
         *
         * Opera and recent Mozilla send the alert.
         */

        c->ssl->no_wait_shutdown = 1;

#if (RAP_HTTP_V2                                                              \
     && (defined TLSEXT_TYPE_application_layer_protocol_negotiation           \
         || defined TLSEXT_TYPE_next_proto_neg))
        {
        unsigned int            len;
        const unsigned char    *data;
        rap_http_connection_t  *hc;

        hc = c->data;

        if (hc->addr_conf->http2) {

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
            SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

#ifdef TLSEXT_TYPE_next_proto_neg
            if (len == 0) {
                SSL_get0_next_proto_negotiated(c->ssl->connection, &data, &len);
            }
#endif

#else /* TLSEXT_TYPE_next_proto_neg */
            SSL_get0_next_proto_negotiated(c->ssl->connection, &data, &len);
#endif

            if (len == 2 && data[0] == 'h' && data[1] == '2') {
                rap_http_v2_init(c->read);
                return;
            }
        }
        }
#endif

        c->log->action = "waiting for request";

        c->read->handler = rap_http_wait_request_handler;
        /* STUB: epoll edge */ c->write->handler = rap_http_empty_handler;

        rap_reusable_connection(c, 1);

        rap_http_wait_request_handler(c->read);

        return;
    }

    if (c->read->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
    }

    rap_http_close_connection(c);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
rap_http_ssl_servername(rap_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    rap_int_t                  rc;
    rap_str_t                  host;
    const char                *servername;
    rap_connection_t          *c;
    rap_http_connection_t     *hc;
    rap_http_ssl_srv_conf_t   *sscf;
    rap_http_core_loc_conf_t  *clcf;
    rap_http_core_srv_conf_t  *cscf;

    c = rap_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        *ad = SSL_AD_NO_RENEGOTIATION;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL) {
        return SSL_TLSEXT_ERR_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL server name: \"%s\"", servername);

    host.len = rap_strlen(servername);

    if (host.len == 0) {
        return SSL_TLSEXT_ERR_OK;
    }

    host.data = (u_char *) servername;

    rc = rap_http_validate_host(&host, c->pool, 1);

    if (rc == RAP_ERROR) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (rc == RAP_DECLINED) {
        return SSL_TLSEXT_ERR_OK;
    }

    hc = c->data;

    rc = rap_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
                                      NULL, &cscf);

    if (rc == RAP_ERROR) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (rc == RAP_DECLINED) {
        return SSL_TLSEXT_ERR_OK;
    }

    hc->ssl_servername = rap_palloc(c->pool, sizeof(rap_str_t));
    if (hc->ssl_servername == NULL) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    *hc->ssl_servername = host;

    hc->conf_ctx = cscf->ctx;

    clcf = rap_http_get_module_loc_conf(hc->conf_ctx, rap_http_core_module);

    rap_set_connection_log(c, clcf->error_log);

    sscf = rap_http_get_module_srv_conf(hc->conf_ctx, rap_http_ssl_module);

    c->ssl->buffer_size = sscf->buffer_size;

    if (sscf->ssl.ctx) {
        SSL_set_SSL_CTX(ssl_conn, sscf->ssl.ctx);

        /*
         * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
         * adjust other things we care about
         */

        SSL_set_verify(ssl_conn, SSL_CTX_get_verify_mode(sscf->ssl.ctx),
                       SSL_CTX_get_verify_callback(sscf->ssl.ctx));

        SSL_set_verify_depth(ssl_conn, SSL_CTX_get_verify_depth(sscf->ssl.ctx));

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
        /* only in 0.9.8m+ */
        SSL_clear_options(ssl_conn, SSL_get_options(ssl_conn) &
                                    ~SSL_CTX_get_options(sscf->ssl.ctx));
#endif

        SSL_set_options(ssl_conn, SSL_CTX_get_options(sscf->ssl.ctx));

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(ssl_conn, SSL_OP_NO_RENEGOTIATION);
#endif
    }

    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

int
rap_http_ssl_certificate(rap_ssl_conn_t *ssl_conn, void *arg)
{
    rap_str_t                  cert, key;
    rap_uint_t                 i, nelts;
    rap_connection_t          *c;
    rap_http_request_t        *r;
    rap_http_ssl_srv_conf_t   *sscf;
    rap_http_complex_value_t  *certs, *keys;

    c = rap_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    r = rap_http_alloc_request(c);
    if (r == NULL) {
        return 0;
    }

    r->logged = 1;

    sscf = arg;

    nelts = sscf->certificate_values->nelts;
    certs = sscf->certificate_values->elts;
    keys = sscf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (rap_http_complex_value(r, &certs[i], &cert) != RAP_OK) {
            goto failed;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (rap_http_complex_value(r, &keys[i], &key) != RAP_OK) {
            goto failed;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (rap_ssl_connection_certificate(c, r->pool, &cert, &key,
                                           sscf->passwords)
            != RAP_OK)
        {
            goto failed;
        }
    }

    rap_http_free_request(r, 0);
    c->destroyed = 0;
    return 1;

failed:

    rap_http_free_request(r, 0);
    c->destroyed = 0;
    return 0;
}

#endif

#endif


static void
rap_http_process_request_line(rap_event_t *rev)
{
    ssize_t              n;
    rap_int_t            rc, rv;
    rap_str_t            host;
    rap_connection_t    *c;
    rap_http_request_t  *r;

    c = rev->data;
    r = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rap_http_close_request(r, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = RAP_AGAIN;

    for ( ;; ) {

        if (rc == RAP_AGAIN) {
            n = rap_http_read_request_header(r);

            if (n == RAP_AGAIN || n == RAP_ERROR) {
                break;
            }
        }

        rc = rap_http_parse_request_line(r, r->header_in);

        if (rc == RAP_OK) {

            /* the request line has been parsed successfully */

            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
            r->request_length = r->header_in->pos - r->request_start;

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%V\"", &r->request_line);

            r->method_name.len = r->method_end - r->request_start + 1;
            r->method_name.data = r->request_line.data;

            if (r->http_protocol.data) {
                r->http_protocol.len = r->request_end - r->http_protocol.data;
            }

            if (rap_http_process_request_uri(r) != RAP_OK) {
                break;
            }

            if (r->schema_end) {
                r->schema.len = r->schema_end - r->schema_start;
                r->schema.data = r->schema_start;
            }

            if (r->host_end) {

                host.len = r->host_end - r->host_start;
                host.data = r->host_start;

                rc = rap_http_validate_host(&host, r->pool, 0);

                if (rc == RAP_DECLINED) {
                    rap_log_error(RAP_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line");
                    rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
                    break;
                }

                if (rc == RAP_ERROR) {
                    rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (rap_http_set_virtual_server(r, &host) == RAP_ERROR) {
                    break;
                }

                r->headers_in.server = host;
            }

            if (r->http_version < RAP_HTTP_VERSION_10) {

                if (r->headers_in.server.len == 0
                    && rap_http_set_virtual_server(r, &r->headers_in.server)
                       == RAP_ERROR)
                {
                    break;
                }

                rap_http_process_request(r);
                break;
            }


            if (rap_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(rap_table_elt_t))
                != RAP_OK)
            {
                rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            c->log->action = "reading client request headers";

            rev->handler = rap_http_process_request_headers;
            rap_http_process_request_headers(rev);

            break;
        }

        if (rc != RAP_AGAIN) {

            /* there was error while a request line parsing */

            rap_log_error(RAP_LOG_INFO, c->log, 0,
                          rap_http_client_errors[rc - RAP_HTTP_CLIENT_ERROR]);

            if (rc == RAP_HTTP_PARSE_INVALID_VERSION) {
                rap_http_finalize_request(r, RAP_HTTP_VERSION_NOT_SUPPORTED);

            } else {
                rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
            }

            break;
        }

        /* RAP_AGAIN: a request line parsing is still incomplete */

        if (r->header_in->pos == r->header_in->end) {

            rv = rap_http_alloc_large_header_buffer(r, 1);

            if (rv == RAP_ERROR) {
                rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (rv == RAP_DECLINED) {
                r->request_line.len = r->header_in->end - r->request_start;
                r->request_line.data = r->request_start;

                rap_log_error(RAP_LOG_INFO, c->log, 0,
                              "client sent too long URI");
                rap_http_finalize_request(r, RAP_HTTP_REQUEST_URI_TOO_LARGE);
                break;
            }
        }
    }

    rap_http_run_posted_requests(c);
}


rap_int_t
rap_http_process_request_uri(rap_http_request_t *r)
{
    rap_http_core_srv_conf_t  *cscf;

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->uri_end - r->uri_start;
    }

    if (r->complex_uri || r->quoted_uri) {

        r->uri.data = rap_pnalloc(r->pool, r->uri.len + 1);
        if (r->uri.data == NULL) {
            rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
            return RAP_ERROR;
        }

        cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

        if (rap_http_parse_complex_uri(r, cscf->merge_slashes) != RAP_OK) {
            r->uri.len = 0;

            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid request");
            rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
            return RAP_ERROR;
        }

    } else {
        r->uri.data = r->uri_start;
    }

    r->unparsed_uri.len = r->uri_end - r->uri_start;
    r->unparsed_uri.data = r->uri_start;

    r->valid_unparsed_uri = r->space_in_uri ? 0 : 1;

    if (r->uri_ext) {
        if (r->args_start) {
            r->exten.len = r->args_start - 1 - r->uri_ext;
        } else {
            r->exten.len = r->uri_end - r->uri_ext;
        }

        r->exten.data = r->uri_ext;
    }

    if (r->args_start && r->uri_end > r->args_start) {
        r->args.len = r->uri_end - r->args_start;
        r->args.data = r->args_start;
    }

#if (RAP_WIN32)
    {
    u_char  *p, *last;

    p = r->uri.data;
    last = r->uri.data + r->uri.len;

    while (p < last) {

        if (*p++ == ':') {

            /*
             * this check covers "::$data", "::$index_allocation" and
             * ":$i30:$index_allocation"
             */

            if (p < last && *p == '$') {
                rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                              "client sent unsafe win32 URI");
                rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
                return RAP_ERROR;
            }
        }
    }

    p = r->uri.data + r->uri.len - 1;

    while (p > r->uri.data) {

        if (*p == ' ') {
            p--;
            continue;
        }

        if (*p == '.') {
            p--;
            continue;
        }

        break;
    }

    if (p != r->uri.data + r->uri.len - 1) {
        r->uri.len = p + 1 - r->uri.data;
        rap_http_set_exten(r);
    }

    }
#endif

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uri: \"%V\"", &r->uri);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http args: \"%V\"", &r->args);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http exten: \"%V\"", &r->exten);

    return RAP_OK;
}


static void
rap_http_process_request_headers(rap_event_t *rev)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    rap_int_t                   rc, rv;
    rap_table_elt_t            *h;
    rap_connection_t           *c;
    rap_http_header_t          *hh;
    rap_http_request_t         *r;
    rap_http_core_srv_conf_t   *cscf;
    rap_http_core_main_conf_t  *cmcf;

    c = rev->data;
    r = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rap_http_close_request(r, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    rc = RAP_AGAIN;

    for ( ;; ) {

        if (rc == RAP_AGAIN) {

            if (r->header_in->pos == r->header_in->end) {

                rv = rap_http_alloc_large_header_buffer(r, 0);

                if (rv == RAP_ERROR) {
                    rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (rv == RAP_DECLINED) {
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        rap_log_error(RAP_LOG_INFO, c->log, 0,
                                      "client sent too large request");
                        rap_http_finalize_request(r,
                                            RAP_HTTP_REQUEST_HEADER_TOO_LARGE);
                        break;
                    }

                    len = r->header_in->end - p;

                    if (len > RAP_MAX_ERROR_STR - 300) {
                        len = RAP_MAX_ERROR_STR - 300;
                    }

                    rap_log_error(RAP_LOG_INFO, c->log, 0,
                                "client sent too long header line: \"%*s...\"",
                                len, r->header_name_start);

                    rap_http_finalize_request(r,
                                            RAP_HTTP_REQUEST_HEADER_TOO_LARGE);
                    break;
                }
            }

            n = rap_http_read_request_header(r);

            if (n == RAP_AGAIN || n == RAP_ERROR) {
                break;
            }
        }

        /* the host header could change the server configuration context */
        cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

        rc = rap_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == RAP_OK) {

            r->request_length += r->header_in->pos - r->header_name_start;

            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                rap_log_error(RAP_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            h = rap_list_push(&r->headers_in.headers);
            if (h == NULL) {
                rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = rap_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (h->key.len == r->lowcase_index) {
                rap_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                rap_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = rap_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != RAP_OK) {
                break;
            }

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == RAP_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            r->http_state = RAP_HTTP_PROCESS_REQUEST_STATE;

            rc = rap_http_process_request_header(r);

            if (rc != RAP_OK) {
                break;
            }

            rap_http_process_request(r);

            break;
        }

        if (rc == RAP_AGAIN) {

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == RAP_HTTP_PARSE_INVALID_HEADER */

        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "client sent invalid header line");

        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        break;
    }

    rap_http_run_posted_requests(c);
}


static ssize_t
rap_http_read_request_header(rap_http_request_t *r)
{
    ssize_t                    n;
    rap_event_t               *rev;
    rap_connection_t          *c;
    rap_http_core_srv_conf_t  *cscf;

    c = r->connection;
    rev = c->read;

    n = r->header_in->last - r->header_in->pos;

    if (n > 0) {
        return n;
    }

    if (rev->ready) {
        n = c->recv(c, r->header_in->last,
                    r->header_in->end - r->header_in->last);
    } else {
        n = RAP_AGAIN;
    }

    if (n == RAP_AGAIN) {
        if (!rev->timer_set) {
            cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
            rap_add_timer(rev, cscf->client_header_timeout);
        }

        if (rap_handle_read_event(rev, 0) != RAP_OK) {
            rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
            return RAP_ERROR;
        }

        return RAP_AGAIN;
    }

    if (n == 0) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    if (n == 0 || n == RAP_ERROR) {
        c->error = 1;
        c->log->action = "reading client request headers";

        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        return RAP_ERROR;
    }

    r->header_in->last += n;

    return n;
}


static rap_int_t
rap_http_alloc_large_header_buffer(rap_http_request_t *r,
    rap_uint_t request_line)
{
    u_char                    *old, *new;
    rap_buf_t                 *b;
    rap_chain_t               *cl;
    rap_http_connection_t     *hc;
    rap_http_core_srv_conf_t  *cscf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http alloc large header buffer");

    if (request_line && r->state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return RAP_OK;
    }

    old = request_line ? r->request_start : r->header_name_start;

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return RAP_DECLINED;
    }

    hc = r->http_connection;

    if (hc->free) {
        cl = hc->free;
        hc->free = cl->next;

        b = cl->buf;

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header free: %p %uz",
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        b = rap_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return RAP_ERROR;
        }

        cl = rap_alloc_chain_link(r->connection->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        cl->buf = b;

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header alloc: %p %uz",
                       b->pos, b->end - b->last);

    } else {
        return RAP_DECLINED;
    }

    cl->next = hc->busy;
    hc->busy = cl;
    hc->nbusy++;

    if (r->state == 0) {
        /*
         * r->state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->header_in = b;

        return RAP_OK;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http large header copy: %uz", r->header_in->pos - old);

    new = b->start;

    rap_memcpy(new, old, r->header_in->pos - old);

    b->pos = new + (r->header_in->pos - old);
    b->last = new + (r->header_in->pos - old);

    if (request_line) {
        r->request_start = new;

        if (r->request_end) {
            r->request_end = new + (r->request_end - old);
        }

        r->method_end = new + (r->method_end - old);

        r->uri_start = new + (r->uri_start - old);
        r->uri_end = new + (r->uri_end - old);

        if (r->schema_start) {
            r->schema_start = new + (r->schema_start - old);
            r->schema_end = new + (r->schema_end - old);
        }

        if (r->host_start) {
            r->host_start = new + (r->host_start - old);
            if (r->host_end) {
                r->host_end = new + (r->host_end - old);
            }
        }

        if (r->port_start) {
            r->port_start = new + (r->port_start - old);
            r->port_end = new + (r->port_end - old);
        }

        if (r->uri_ext) {
            r->uri_ext = new + (r->uri_ext - old);
        }

        if (r->args_start) {
            r->args_start = new + (r->args_start - old);
        }

        if (r->http_protocol.data) {
            r->http_protocol.data = new + (r->http_protocol.data - old);
        }

    } else {
        r->header_name_start = new;
        r->header_name_end = new + (r->header_name_end - old);
        r->header_start = new + (r->header_start - old);
        r->header_end = new + (r->header_end - old);
    }

    r->header_in = b;

    return RAP_OK;
}


static rap_int_t
rap_http_process_header_line(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_table_elt_t  **ph;

    ph = (rap_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_process_unique_header_line(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_table_elt_t  **ph;

    ph = (rap_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                  "client sent duplicate header line: \"%V: %V\", "
                  "previous value: \"%V: %V\"",
                  &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);

    return RAP_ERROR;
}


static rap_int_t
rap_http_process_host(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_int_t  rc;
    rap_str_t  host;

    if (r->headers_in.host) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate host header: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value, &r->headers_in.host->key,
                      &r->headers_in.host->value);
        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        return RAP_ERROR;
    }

    r->headers_in.host = h;

    host = h->value;

    rc = rap_http_validate_host(&host, r->pool, 0);

    if (rc == RAP_DECLINED) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        return RAP_ERROR;
    }

    if (rc == RAP_ERROR) {
        rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

    if (r->headers_in.server.len) {
        return RAP_OK;
    }

    if (rap_http_set_virtual_server(r, &host) == RAP_ERROR) {
        return RAP_ERROR;
    }

    r->headers_in.server = host;

    return RAP_OK;
}


static rap_int_t
rap_http_process_connection(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    if (rap_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->headers_in.connection_type = RAP_HTTP_CONNECTION_CLOSE;

    } else if (rap_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = RAP_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_process_user_agent(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (r->headers_in.user_agent) {
        return RAP_OK;
    }

    r->headers_in.user_agent = h;

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    msie = rap_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (rap_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }

#if 0
        /* MSIE ignores the SSL "close notify" alert */
        if (c->ssl) {
            c->ssl->no_send_shutdown = 1;
        }
#endif
    }

    if (rap_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (rap_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (rap_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (rap_strstrn(user_agent, "Safari/", 7 - 1)
                   && rap_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (rap_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_process_multi_header_lines(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_array_t       *headers;
    rap_table_elt_t  **ph;

    headers = (rap_array_t *) ((char *) &r->headers_in + offset);

    if (headers->elts == NULL) {
        if (rap_array_init(headers, r->pool, 1, sizeof(rap_table_elt_t *))
            != RAP_OK)
        {
            rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
            return RAP_ERROR;
        }
    }

    ph = rap_array_push(headers);
    if (ph == NULL) {
        rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

    *ph = h;
    return RAP_OK;
}


rap_int_t
rap_http_process_request_header(rap_http_request_t *r)
{
    if (r->headers_in.server.len == 0
        && rap_http_set_virtual_server(r, &r->headers_in.server)
           == RAP_ERROR)
    {
        return RAP_ERROR;
    }

    if (r->headers_in.host == NULL && r->http_version > RAP_HTTP_VERSION_10) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                   "client sent HTTP/1.1 request without \"Host\" header");
        rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
        return RAP_ERROR;
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            rap_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == RAP_ERROR) {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            rap_http_finalize_request(r, RAP_HTTP_BAD_REQUEST);
            return RAP_ERROR;
        }
    }

    if (r->method == RAP_HTTP_TRACE) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "client sent TRACE method");
        rap_http_finalize_request(r, RAP_HTTP_NOT_ALLOWED);
        return RAP_ERROR;
    }

    if (r->headers_in.transfer_encoding) {
        if (r->headers_in.transfer_encoding->value.len == 7
            && rap_strncasecmp(r->headers_in.transfer_encoding->value.data,
                               (u_char *) "chunked", 7) == 0)
        {
            r->headers_in.content_length = NULL;
            r->headers_in.content_length_n = -1;
            r->headers_in.chunked = 1;

        } else {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client sent unknown \"Transfer-Encoding\": \"%V\"",
                          &r->headers_in.transfer_encoding->value);
            rap_http_finalize_request(r, RAP_HTTP_NOT_IMPLEMENTED);
            return RAP_ERROR;
        }
    }

    if (r->headers_in.connection_type == RAP_HTTP_CONNECTION_KEEP_ALIVE) {
        if (r->headers_in.keep_alive) {
            r->headers_in.keep_alive_n =
                            rap_atotm(r->headers_in.keep_alive->value.data,
                                      r->headers_in.keep_alive->value.len);
        }
    }

    return RAP_OK;
}


void
rap_http_process_request(rap_http_request_t *r)
{
    rap_connection_t  *c;

    c = r->connection;

#if (RAP_HTTP_SSL)

    if (r->http_connection->ssl) {
        long                      rc;
        X509                     *cert;
        rap_http_ssl_srv_conf_t  *sscf;

        if (c->ssl == NULL) {
            rap_log_error(RAP_LOG_INFO, c->log, 0,
                          "client sent plain HTTP request to HTTPS port");
            rap_http_finalize_request(r, RAP_HTTP_TO_HTTPS);
            return;
        }

        sscf = rap_http_get_module_srv_conf(r, rap_http_ssl_module);

        if (sscf->verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK
                && (sscf->verify != 3 || !rap_ssl_verify_error_optional(rc)))
            {
                rap_log_error(RAP_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));

                rap_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                rap_http_finalize_request(r, RAP_HTTPS_CERT_ERROR);
                return;
            }

            if (sscf->verify == 1) {
                cert = SSL_get_peer_certificate(c->ssl->connection);

                if (cert == NULL) {
                    rap_log_error(RAP_LOG_INFO, c->log, 0,
                                  "client sent no required SSL certificate");

                    rap_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                    rap_http_finalize_request(r, RAP_HTTPS_NO_CERT);
                    return;
                }

                X509_free(cert);
            }
        }
    }

#endif

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

#if (RAP_STAT_STUB)
    (void) rap_atomic_fetch_add(rap_stat_reading, -1);
    r->stat_reading = 0;
    (void) rap_atomic_fetch_add(rap_stat_writing, 1);
    r->stat_writing = 1;
#endif

    c->read->handler = rap_http_request_handler;
    c->write->handler = rap_http_request_handler;
    r->read_event_handler = rap_http_block_reading;

    rap_http_handler(r);
}


static rap_int_t
rap_http_validate_host(rap_str_t *host, rap_pool_t *pool, rap_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return RAP_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return RAP_DECLINED;

        default:

            if (rap_path_separator(ch)) {
                return RAP_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return RAP_DECLINED;
    }

    if (alloc) {
        host->data = rap_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return RAP_ERROR;
        }

        rap_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return RAP_OK;
}


static rap_int_t
rap_http_set_virtual_server(rap_http_request_t *r, rap_str_t *host)
{
    rap_int_t                  rc;
    rap_http_connection_t     *hc;
    rap_http_core_loc_conf_t  *clcf;
    rap_http_core_srv_conf_t  *cscf;

#if (RAP_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

#if (RAP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        if (hc->ssl_servername->len == host->len
            && rap_strncmp(hc->ssl_servername->data,
                           host->data, host->len) == 0)
        {
#if (RAP_PCRE)
            if (hc->ssl_servername_regex
                && rap_http_regex_exec(r, hc->ssl_servername_regex,
                                          hc->ssl_servername) != RAP_OK)
            {
                rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                return RAP_ERROR;
            }
#endif
            return RAP_OK;
        }
    }

#endif

    rc = rap_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == RAP_ERROR) {
        rap_http_close_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return RAP_ERROR;
    }

#if (RAP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        rap_http_ssl_srv_conf_t  *sscf;

        if (rc == RAP_DECLINED) {
            cscf = hc->addr_conf->default_server;
            rc = RAP_OK;
        }

        sscf = rap_http_get_module_srv_conf(cscf->ctx, rap_http_ssl_module);

        if (sscf->verify) {
            rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from the one that was negotiated");
            rap_http_finalize_request(r, RAP_HTTP_MISDIRECTED_REQUEST);
            return RAP_ERROR;
        }
    }

#endif

    if (rc == RAP_DECLINED) {
        return RAP_OK;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rap_set_connection_log(r->connection, clcf->error_log);

    return RAP_OK;
}


static rap_int_t
rap_http_find_virtual_server(rap_connection_t *c,
    rap_http_virtual_names_t *virtual_names, rap_str_t *host,
    rap_http_request_t *r, rap_http_core_srv_conf_t **cscfp)
{
    rap_http_core_srv_conf_t  *cscf;

    if (virtual_names == NULL) {
        return RAP_DECLINED;
    }

    cscf = rap_hash_find_combined(&virtual_names->names,
                                  rap_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return RAP_OK;
    }

#if (RAP_PCRE)

    if (host->len && virtual_names->nregex) {
        rap_int_t                n;
        rap_uint_t               i;
        rap_http_server_name_t  *sn;

        sn = virtual_names->regex;

#if (RAP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

        if (r == NULL) {
            rap_http_connection_t  *hc;

            for (i = 0; i < virtual_names->nregex; i++) {

                n = rap_regex_exec(sn[i].regex->regex, host, NULL, 0);

                if (n == RAP_REGEX_NO_MATCHED) {
                    continue;
                }

                if (n >= 0) {
                    hc = c->data;
                    hc->ssl_servername_regex = sn[i].regex;

                    *cscfp = sn[i].server;
                    return RAP_OK;
                }

                rap_log_error(RAP_LOG_ALERT, c->log, 0,
                              rap_regex_exec_n " failed: %i "
                              "on \"%V\" using \"%V\"",
                              n, host, &sn[i].regex->name);

                return RAP_ERROR;
            }

            return RAP_DECLINED;
        }

#endif /* RAP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */

        for (i = 0; i < virtual_names->nregex; i++) {

            n = rap_http_regex_exec(r, sn[i].regex, host);

            if (n == RAP_DECLINED) {
                continue;
            }

            if (n == RAP_OK) {
                *cscfp = sn[i].server;
                return RAP_OK;
            }

            return RAP_ERROR;
        }
    }

#endif /* RAP_PCRE */

    return RAP_DECLINED;
}


static void
rap_http_request_handler(rap_event_t *ev)
{
    rap_connection_t    *c;
    rap_http_request_t  *r;

    c = ev->data;
    r = c->data;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http run request: \"%V?%V\"", &r->uri, &r->args);

    if (c->close) {
        r->main->count++;
        rap_http_terminate_request(r, 0);
        rap_http_run_posted_requests(c);
        return;
    }

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }

    rap_http_run_posted_requests(c);
}


void
rap_http_run_posted_requests(rap_connection_t *c)
{
    rap_http_request_t         *r;
    rap_http_posted_request_t  *pr;

    for ( ;; ) {

        if (c->destroyed) {
            return;
        }

        r = c->data;
        pr = r->main->posted_requests;

        if (pr == NULL) {
            return;
        }

        r->main->posted_requests = pr->next;

        r = pr->request;

        rap_http_set_log_request(c->log, r);

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "http posted request: \"%V?%V\"", &r->uri, &r->args);

        r->write_event_handler(r);
    }
}


rap_int_t
rap_http_post_request(rap_http_request_t *r, rap_http_posted_request_t *pr)
{
    rap_http_posted_request_t  **p;

    if (pr == NULL) {
        pr = rap_palloc(r->pool, sizeof(rap_http_posted_request_t));
        if (pr == NULL) {
            return RAP_ERROR;
        }
    }

    pr->request = r;
    pr->next = NULL;

    for (p = &r->main->posted_requests; *p; p = &(*p)->next) { /* void */ }

    *p = pr;

    return RAP_OK;
}


void
rap_http_finalize_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_connection_t          *c;
    rap_http_request_t        *pr;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;

    rap_log_debug5(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http finalize request: %i, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    if (rc == RAP_DONE) {
        rap_http_finalize_connection(r);
        return;
    }

    if (rc == RAP_OK && r->filter_finalize) {
        c->error = 1;
    }

    if (rc == RAP_DECLINED) {
        r->content_handler = NULL;
        r->write_event_handler = rap_http_core_run_phases;
        rap_http_core_run_phases(r);
        return;
    }

    if (r != r->main && r->post_subrequest) {
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    if (rc == RAP_ERROR
        || rc == RAP_HTTP_REQUEST_TIME_OUT
        || rc == RAP_HTTP_CLIENT_CLOSED_REQUEST
        || c->error)
    {
        if (rap_http_post_action(r) == RAP_OK) {
            return;
        }

        rap_http_terminate_request(r, rc);
        return;
    }

    if (rc >= RAP_HTTP_SPECIAL_RESPONSE
        || rc == RAP_HTTP_CREATED
        || rc == RAP_HTTP_NO_CONTENT)
    {
        if (rc == RAP_HTTP_CLOSE) {
            c->timedout = 1;
            rap_http_terminate_request(r, rc);
            return;
        }

        if (r == r->main) {
            if (c->read->timer_set) {
                rap_del_timer(c->read);
            }

            if (c->write->timer_set) {
                rap_del_timer(c->write);
            }
        }

        c->read->handler = rap_http_request_handler;
        c->write->handler = rap_http_request_handler;

        rap_http_finalize_request(r, rap_http_special_response_handler(r, rc));
        return;
    }

    if (r != r->main) {

        if (r->buffered || r->postponed) {

            if (rap_http_set_write_handler(r) != RAP_OK) {
                rap_http_terminate_request(r, 0);
            }

            return;
        }

        pr = r->parent;

        if (r == c->data || r->background) {

            if (!r->logged) {

                clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

                if (clcf->log_subrequest) {
                    rap_http_log_request(r);
                }

                r->logged = 1;

            } else {
                rap_log_error(RAP_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (r->background) {
                rap_http_finalize_connection(r);
                return;
            }

            r->main->count--;

            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            c->data = pr;

        } else {

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                           "http finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = rap_http_request_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        if (rap_http_post_request(pr, NULL) != RAP_OK) {
            r->main->count++;
            rap_http_terminate_request(r, 0);
            return;
        }

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "http wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

    if (r->buffered || c->buffered || r->postponed) {

        if (rap_http_set_write_handler(r) != RAP_OK) {
            rap_http_terminate_request(r, 0);
        }

        return;
    }

    if (r != c->data) {
        rap_log_error(RAP_LOG_ALERT, c->log, 0,
                      "http finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;

    r->read_event_handler = rap_http_block_reading;
    r->write_event_handler = rap_http_request_empty_handler;

    if (!r->post_action) {
        r->request_complete = 1;
    }

    if (rap_http_post_action(r) == RAP_OK) {
        return;
    }

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        rap_del_timer(c->write);
    }

    if (c->read->eof) {
        rap_http_close_request(r, 0);
        return;
    }

    rap_http_finalize_connection(r);
}


static void
rap_http_terminate_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_http_cleanup_t    *cln;
    rap_http_request_t    *mr;
    rap_http_ephemeral_t  *e;

    mr = r->main;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate request count:%d", mr->count);

    if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
        mr->headers_out.status = rc;
    }

    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    if (mr->write_event_handler) {

        if (mr->blocked) {
            r->connection->error = 1;
            r->write_event_handler = rap_http_request_finalizer;
            return;
        }

        e = rap_http_ephemeral(mr);
        mr->posted_requests = NULL;
        mr->write_event_handler = rap_http_terminate_handler;
        (void) rap_http_post_request(mr, &e->terminal_posted_request);
        return;
    }

    rap_http_close_request(mr, rc);
}


static void
rap_http_terminate_handler(rap_http_request_t *r)
{
    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate handler count:%d", r->count);

    r->count = 1;

    rap_http_close_request(r, 0);
}


static void
rap_http_finalize_connection(rap_http_request_t *r)
{
    rap_http_core_loc_conf_t  *clcf;

#if (RAP_HTTP_V2)
    if (r->stream) {
        rap_http_close_request(r, 0);
        return;
    }
#endif

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (r->main->count != 1) {

        if (r->discard_body) {
            r->read_event_handler = rap_http_discarded_request_body_handler;
            rap_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = rap_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

        rap_http_close_request(r, 0);
        return;
    }

    r = r->main;

    if (r->reading_body) {
        r->keepalive = 0;
        r->lingering_close = 1;
    }

    if (!rap_terminate
         && !rap_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        rap_http_set_keepalive(r);
        return;
    }

    if (clcf->lingering_close == RAP_HTTP_LINGERING_ALWAYS
        || (clcf->lingering_close == RAP_HTTP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready)))
    {
        rap_http_set_lingering_close(r);
        return;
    }

    rap_http_close_request(r, 0);
}


static rap_int_t
rap_http_set_write_handler(rap_http_request_t *r)
{
    rap_event_t               *wev;
    rap_http_core_loc_conf_t  *clcf;

    r->http_state = RAP_HTTP_WRITING_REQUEST_STATE;

    r->read_event_handler = r->discard_body ?
                                rap_http_discarded_request_body_handler:
                                rap_http_test_reading;
    r->write_event_handler = rap_http_writer;

    wev = r->connection->write;

    if (wev->ready && wev->delayed) {
        return RAP_OK;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
    if (!wev->delayed) {
        rap_add_timer(wev, clcf->send_timeout);
    }

    if (rap_handle_write_event(wev, clcf->send_lowat) != RAP_OK) {
        rap_http_close_request(r, 0);
        return RAP_ERROR;
    }

    return RAP_OK;
}


static void
rap_http_writer(rap_http_request_t *r)
{
    rap_int_t                  rc;
    rap_event_t               *wev;
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;
    wev = c->write;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer handler: \"%V?%V\"", &r->uri, &r->args);

    clcf = rap_http_get_module_loc_conf(r->main, rap_http_core_module);

    if (wev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;

        rap_http_finalize_request(r, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (wev->delayed || r->aio) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, wev->log, 0,
                       "http writer delayed");

        if (!wev->delayed) {
            rap_add_timer(wev, clcf->send_timeout);
        }

        if (rap_handle_write_event(wev, clcf->send_lowat) != RAP_OK) {
            rap_http_close_request(r, 0);
        }

        return;
    }

    rc = rap_http_output_filter(r, NULL);

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http writer output filter: %i, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    if (rc == RAP_ERROR) {
        rap_http_finalize_request(r, rc);
        return;
    }

    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

        if (!wev->delayed) {
            rap_add_timer(wev, clcf->send_timeout);
        }

        if (rap_handle_write_event(wev, clcf->send_lowat) != RAP_OK) {
            rap_http_close_request(r, 0);
        }

        return;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer done: \"%V?%V\"", &r->uri, &r->args);

    r->write_event_handler = rap_http_request_empty_handler;

    rap_http_finalize_request(r, rc);
}


static void
rap_http_request_finalizer(rap_http_request_t *r)
{
    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalizer done: \"%V?%V\"", &r->uri, &r->args);

    rap_http_finalize_request(r, 0);
}


void
rap_http_block_reading(rap_http_request_t *r)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reading blocked");

    /* aio does not call this handler */

    if ((rap_event_flags & RAP_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (rap_del_event(r->connection->read, RAP_READ_EVENT, 0) != RAP_OK) {
            rap_http_close_request(r, 0);
        }
    }
}


void
rap_http_test_reading(rap_http_request_t *r)
{
    int                n;
    char               buf[1];
    rap_err_t          err;
    rap_event_t       *rev;
    rap_connection_t  *c;

    c = r->connection;
    rev = c->read;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "http test reading");

#if (RAP_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (RAP_HAVE_EPOLLRDHUP)

    if ((rap_event_flags & RAP_USE_EPOLL_EVENT) && rap_use_epoll_rdhup) {
        socklen_t  len;

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(rap_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = rap_socket_errno;
        }

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = rap_socket_errno;

        if (err != RAP_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((rap_event_flags & RAP_USE_LEVEL_EVENT) && rev->active) {

        if (rap_del_event(rev, RAP_READ_EVENT, 0) != RAP_OK) {
            rap_http_close_request(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    rap_log_error(RAP_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    rap_http_finalize_request(r, RAP_HTTP_CLIENT_CLOSED_REQUEST);
}


static void
rap_http_set_keepalive(rap_http_request_t *r)
{
    int                        tcp_nodelay;
    rap_buf_t                 *b, *f;
    rap_chain_t               *cl, *ln;
    rap_event_t               *rev, *wev;
    rap_connection_t          *c;
    rap_http_connection_t     *hc;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    if (r->discard_body) {
        r->write_event_handler = rap_http_request_empty_handler;
        r->lingering_time = rap_time() + (time_t) (clcf->lingering_time / 1000);
        rap_add_timer(rev, clcf->lingering_timeout);
        return;
    }

    c->log->action = "closing request";

    hc = r->http_connection;
    b = r->header_in;

    if (b->pos < b->last) {

        /* the pipelined request */

        if (b != c->buffer) {

            /*
             * If the large header buffers were allocated while the previous
             * request processing then we do not use c->buffer for
             * the pipelined request (see rap_http_create_request()).
             *
             * Now we would move the large header buffers to the free list.
             */

            for (cl = hc->busy; cl; /* void */) {
                ln = cl;
                cl = cl->next;

                if (ln->buf == b) {
                    rap_free_chain(c->pool, ln);
                    continue;
                }

                f = ln->buf;
                f->pos = f->start;
                f->last = f->start;

                ln->next = hc->free;
                hc->free = ln;
            }

            cl = rap_alloc_chain_link(c->pool);
            if (cl == NULL) {
                rap_http_close_request(r, 0);
                return;
            }

            cl->buf = b;
            cl->next = NULL;

            hc->busy = cl;
            hc->nbusy = 1;
        }
    }

    /* guard against recursive call from rap_http_finalize_connection() */
    r->keepalive = 0;

    rap_http_free_request(r, 0);

    c->data = hc;

    if (rap_handle_read_event(rev, 0) != RAP_OK) {
        rap_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = rap_http_empty_handler;

    if (b->pos < b->last) {

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        c->log->action = "reading client pipelined request line";

        r = rap_http_create_request(c);
        if (r == NULL) {
            rap_http_close_connection(c);
            return;
        }

        r->pipeline = 1;

        c->data = r;

        c->sent = 0;
        c->destroyed = 0;

        if (rev->timer_set) {
            rap_del_timer(rev);
        }

        rev->handler = rap_http_process_request_line;
        rap_post_event(rev, &rap_posted_events);
        return;
    }

    /*
     * To keep a memory footprint as small as possible for an idle keepalive
     * connection we try to free c->buffer's memory if it was allocated outside
     * the c->pool.  The large header buffers are always allocated outside the
     * c->pool and are freed too.
     */

    b = c->buffer;

    if (rap_pfree(c->pool, b->start) == RAP_OK) {

        /*
         * the special note for rap_http_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0, "hc free: %p",
                   hc->free);

    if (hc->free) {
        for (cl = hc->free; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            rap_pfree(c->pool, ln->buf->start);
            rap_free_chain(c->pool, ln);
        }

        hc->free = NULL;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0, "hc busy: %p %i",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (cl = hc->busy; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            rap_pfree(c->pool, ln->buf->start);
            rap_free_chain(c->pool, ln);
        }

        hc->busy = NULL;
        hc->nbusy = 0;
    }

#if (RAP_HTTP_SSL)
    if (c->ssl) {
        rap_ssl_free_buffer(c);
    }
#endif

    rev->handler = rap_http_keepalive_handler;

    if (wev->active && (rap_event_flags & RAP_USE_LEVEL_EVENT)) {
        if (rap_del_event(wev, RAP_WRITE_EVENT, 0) != RAP_OK) {
            rap_http_close_connection(c);
            return;
        }
    }

    c->log->action = "keepalive";

    if (c->tcp_nopush == RAP_TCP_NOPUSH_SET) {
        if (rap_tcp_push(c->fd) == -1) {
            rap_connection_error(c, rap_socket_errno, rap_tcp_push_n " failed");
            rap_http_close_connection(c);
            return;
        }

        c->tcp_nopush = RAP_TCP_NOPUSH_UNSET;
        tcp_nodelay = rap_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && rap_tcp_nodelay(c) != RAP_OK) {
        rap_http_close_connection(c);
        return;
    }

#if 0
    /* if rap_http_request_t was freed then we need some other place */
    r->http_state = RAP_HTTP_KEEPALIVE_STATE;
#endif

    c->idle = 1;
    rap_reusable_connection(c, 1);

    rap_add_timer(rev, clcf->keepalive_timeout);

    if (rev->ready) {
        rap_post_event(rev, &rap_posted_events);
    }
}


static void
rap_http_keepalive_handler(rap_event_t *rev)
{
    size_t             size;
    ssize_t            n;
    rap_buf_t         *b;
    rap_connection_t  *c;

    c = rev->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (rev->timedout || c->close) {
        rap_http_close_connection(c);
        return;
    }

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            rap_log_error(RAP_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (RAP_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            rap_http_close_connection(c);
            return;
        }
    }

#endif

    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The c->buffer's memory was freed by rap_http_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = rap_palloc(c->pool, size);
        if (b->pos == NULL) {
            rap_http_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    c->log_error = RAP_ERROR_IGNORE_ECONNRESET;
    rap_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = RAP_ERROR_INFO;

    if (n == RAP_AGAIN) {
        if (rap_handle_read_event(rev, 0) != RAP_OK) {
            rap_http_close_connection(c);
            return;
        }

        /*
         * Like rap_http_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (rap_pfree(c->pool, b->start) == RAP_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == RAP_ERROR) {
        rap_http_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        rap_log_error(RAP_LOG_INFO, c->log, rap_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        rap_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->handler = rap_http_log_error;
    c->log->action = "reading client request line";

    c->idle = 0;
    rap_reusable_connection(c, 0);

    c->data = rap_http_create_request(c);
    if (c->data == NULL) {
        rap_http_close_connection(c);
        return;
    }

    c->sent = 0;
    c->destroyed = 0;

    rap_del_timer(rev);

    rev->handler = rap_http_process_request_line;
    rap_http_process_request_line(rev);
}


static void
rap_http_set_lingering_close(rap_http_request_t *r)
{
    rap_event_t               *rev, *wev;
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rev = c->read;
    rev->handler = rap_http_lingering_close_handler;

    r->lingering_time = rap_time() + (time_t) (clcf->lingering_time / 1000);
    rap_add_timer(rev, clcf->lingering_timeout);

    if (rap_handle_read_event(rev, 0) != RAP_OK) {
        rap_http_close_request(r, 0);
        return;
    }

    wev = c->write;
    wev->handler = rap_http_empty_handler;

    if (wev->active && (rap_event_flags & RAP_USE_LEVEL_EVENT)) {
        if (rap_del_event(wev, RAP_WRITE_EVENT, 0) != RAP_OK) {
            rap_http_close_request(r, 0);
            return;
        }
    }

    if (rap_shutdown_socket(c->fd, RAP_WRITE_SHUTDOWN) == -1) {
        rap_connection_error(c, rap_socket_errno,
                             rap_shutdown_socket_n " failed");
        rap_http_close_request(r, 0);
        return;
    }

    if (rev->ready) {
        rap_http_lingering_close_handler(rev);
    }
}


static void
rap_http_lingering_close_handler(rap_event_t *rev)
{
    ssize_t                    n;
    rap_msec_t                 timer;
    rap_connection_t          *c;
    rap_http_request_t        *r;
    rap_http_core_loc_conf_t  *clcf;
    u_char                     buffer[RAP_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    r = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    if (rev->timedout) {
        rap_http_close_request(r, 0);
        return;
    }

    timer = (rap_msec_t) r->lingering_time - (rap_msec_t) rap_time();
    if ((rap_msec_int_t) timer <= 0) {
        rap_http_close_request(r, 0);
        return;
    }

    do {
        n = c->recv(c, buffer, RAP_HTTP_LINGERING_BUFFER_SIZE);

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == RAP_AGAIN) {
            break;
        }

        if (n == RAP_ERROR || n == 0) {
            rap_http_close_request(r, 0);
            return;
        }

    } while (rev->ready);

    if (rap_handle_read_event(rev, 0) != RAP_OK) {
        rap_http_close_request(r, 0);
        return;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    rap_add_timer(rev, timer);
}


void
rap_http_empty_handler(rap_event_t *wev)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");

    return;
}


void
rap_http_request_empty_handler(rap_http_request_t *r)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http request empty handler");

    return;
}


rap_int_t
rap_http_send_special(rap_http_request_t *r, rap_uint_t flags)
{
    rap_buf_t    *b;
    rap_chain_t   out;

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return RAP_ERROR;
    }

    if (flags & RAP_HTTP_LAST) {

        if (r == r->main && !r->post_action) {
            b->last_buf = 1;

        } else {
            b->sync = 1;
            b->last_in_chain = 1;
        }
    }

    if (flags & RAP_HTTP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return rap_http_output_filter(r, &out);
}


static rap_int_t
rap_http_post_action(rap_http_request_t *r)
{
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->post_action.data == NULL) {
        return RAP_DECLINED;
    }

    if (r->post_action && r->uri_changes == 0) {
        return RAP_DECLINED;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post action: \"%V\"", &clcf->post_action);

    r->main->count--;

    r->http_version = RAP_HTTP_VERSION_9;
    r->header_only = 1;
    r->post_action = 1;

    r->read_event_handler = rap_http_block_reading;

    if (clcf->post_action.data[0] == '/') {
        rap_http_internal_redirect(r, &clcf->post_action, NULL);

    } else {
        rap_http_named_location(r, &clcf->post_action);
    }

    return RAP_OK;
}


static void
rap_http_close_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_connection_t  *c;

    r = r->main;
    c = r->connection;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        rap_log_error(RAP_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    r->count--;

    if (r->count || r->blocked) {
        return;
    }

#if (RAP_HTTP_V2)
    if (r->stream) {
        rap_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif

    rap_http_free_request(r, rc);
    rap_http_close_connection(c);
}


void
rap_http_free_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_log_t                 *log;
    rap_pool_t                *pool;
    struct linger              linger;
    rap_http_cleanup_t        *cln;
    rap_http_log_ctx_t        *ctx;
    rap_http_core_loc_conf_t  *clcf;

    log = r->connection->log;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        rap_log_error(RAP_LOG_ALERT, log, 0, "http request already closed");
        return;
    }

    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

#if (RAP_STAT_STUB)

    if (r->stat_reading) {
        (void) rap_atomic_fetch_add(rap_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) rap_atomic_fetch_add(rap_stat_writing, -1);
    }

#endif

    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    if (!r->logged) {
        log->action = "logging request";

        rap_http_log_request(r);
    }

    log->action = "closing request";

    if (r->connection->timedout) {
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                rap_log_error(RAP_LOG_ALERT, log, rap_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* the various request strings were allocated from r->pool */
    ctx = log->data;
    ctx->request = NULL;

    r->request_line.len = 0;

    r->connection->destroyed = 1;

    /*
     * Setting r->pool to NULL will increase probability to catch double close
     * of request since the request object is allocated from its own pool.
     */

    pool = r->pool;
    r->pool = NULL;

    rap_destroy_pool(pool);
}


static void
rap_http_log_request(rap_http_request_t *r)
{
    rap_uint_t                  i, n;
    rap_http_handler_pt        *log_handler;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    log_handler = cmcf->phases[RAP_HTTP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[RAP_HTTP_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


void
rap_http_close_connection(rap_connection_t *c)
{
    rap_pool_t  *pool;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (RAP_HTTP_SSL)

    if (c->ssl) {
        if (rap_ssl_shutdown(c) == RAP_AGAIN) {
            c->ssl->handler = rap_http_close_connection;
            return;
        }
    }

#endif

#if (RAP_STAT_STUB)
    (void) rap_atomic_fetch_add(rap_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    rap_close_connection(c);

    rap_destroy_pool(pool);
}


static u_char *
rap_http_log_error(rap_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    rap_http_request_t  *r;
    rap_http_log_ctx_t  *ctx;

    if (log->action) {
        p = rap_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = rap_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->request;

    if (r) {
        return r->log_handler(r, ctx->current_request, p, len);

    } else {
        p = rap_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}


static u_char *
rap_http_log_error_handler(rap_http_request_t *r, rap_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    rap_http_upstream_t       *u;
    rap_http_core_srv_conf_t  *cscf;

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

    p = rap_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = rap_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = rap_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (RAP_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = rap_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = rap_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = rap_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}

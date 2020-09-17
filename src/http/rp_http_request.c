
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static void rp_http_wait_request_handler(rp_event_t *ev);
static rp_http_request_t *rp_http_alloc_request(rp_connection_t *c);
static void rp_http_process_request_line(rp_event_t *rev);
static void rp_http_process_request_headers(rp_event_t *rev);
static ssize_t rp_http_read_request_header(rp_http_request_t *r);
static rp_int_t rp_http_alloc_large_header_buffer(rp_http_request_t *r,
    rp_uint_t request_line);

static rp_int_t rp_http_process_header_line(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_process_unique_header_line(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_process_multi_header_lines(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_process_host(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_process_connection(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_process_user_agent(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);

static rp_int_t rp_http_validate_host(rp_str_t *host, rp_pool_t *pool,
    rp_uint_t alloc);
static rp_int_t rp_http_set_virtual_server(rp_http_request_t *r,
    rp_str_t *host);
static rp_int_t rp_http_find_virtual_server(rp_connection_t *c,
    rp_http_virtual_names_t *virtual_names, rp_str_t *host,
    rp_http_request_t *r, rp_http_core_srv_conf_t **cscfp);

static void rp_http_request_handler(rp_event_t *ev);
static void rp_http_terminate_request(rp_http_request_t *r, rp_int_t rc);
static void rp_http_terminate_handler(rp_http_request_t *r);
static void rp_http_finalize_connection(rp_http_request_t *r);
static rp_int_t rp_http_set_write_handler(rp_http_request_t *r);
static void rp_http_writer(rp_http_request_t *r);
static void rp_http_request_finalizer(rp_http_request_t *r);

static void rp_http_set_keepalive(rp_http_request_t *r);
static void rp_http_keepalive_handler(rp_event_t *ev);
static void rp_http_set_lingering_close(rp_http_request_t *r);
static void rp_http_lingering_close_handler(rp_event_t *ev);
static rp_int_t rp_http_post_action(rp_http_request_t *r);
static void rp_http_close_request(rp_http_request_t *r, rp_int_t error);
static void rp_http_log_request(rp_http_request_t *r);

static u_char *rp_http_log_error(rp_log_t *log, u_char *buf, size_t len);
static u_char *rp_http_log_error_handler(rp_http_request_t *r,
    rp_http_request_t *sr, u_char *buf, size_t len);

#if (RP_HTTP_SSL)
static void rp_http_ssl_handshake(rp_event_t *rev);
static void rp_http_ssl_handshake_handler(rp_connection_t *c);
#endif


static char *rp_http_client_errors[] = {

    /* RP_HTTP_PARSE_INVALID_METHOD */
    "client sent invalid method",

    /* RP_HTTP_PARSE_INVALID_REQUEST */
    "client sent invalid request",

    /* RP_HTTP_PARSE_INVALID_VERSION */
    "client sent invalid version",

    /* RP_HTTP_PARSE_INVALID_09_METHOD */
    "client sent invalid method in HTTP/0.9 request"
};


rp_http_header_t  rp_http_headers_in[] = {
    { rp_string("Host"), offsetof(rp_http_headers_in_t, host),
                 rp_http_process_host },

    { rp_string("Connection"), offsetof(rp_http_headers_in_t, connection),
                 rp_http_process_connection },

    { rp_string("If-Modified-Since"),
                 offsetof(rp_http_headers_in_t, if_modified_since),
                 rp_http_process_unique_header_line },

    { rp_string("If-Unmodified-Since"),
                 offsetof(rp_http_headers_in_t, if_unmodified_since),
                 rp_http_process_unique_header_line },

    { rp_string("If-Match"),
                 offsetof(rp_http_headers_in_t, if_match),
                 rp_http_process_unique_header_line },

    { rp_string("If-None-Match"),
                 offsetof(rp_http_headers_in_t, if_none_match),
                 rp_http_process_unique_header_line },

    { rp_string("User-Agent"), offsetof(rp_http_headers_in_t, user_agent),
                 rp_http_process_user_agent },

    { rp_string("Referer"), offsetof(rp_http_headers_in_t, referer),
                 rp_http_process_header_line },

    { rp_string("Content-Length"),
                 offsetof(rp_http_headers_in_t, content_length),
                 rp_http_process_unique_header_line },

    { rp_string("Content-Range"),
                 offsetof(rp_http_headers_in_t, content_range),
                 rp_http_process_unique_header_line },

    { rp_string("Content-Type"),
                 offsetof(rp_http_headers_in_t, content_type),
                 rp_http_process_header_line },

    { rp_string("Range"), offsetof(rp_http_headers_in_t, range),
                 rp_http_process_header_line },

    { rp_string("If-Range"),
                 offsetof(rp_http_headers_in_t, if_range),
                 rp_http_process_unique_header_line },

    { rp_string("Transfer-Encoding"),
                 offsetof(rp_http_headers_in_t, transfer_encoding),
                 rp_http_process_unique_header_line },

    { rp_string("TE"),
                 offsetof(rp_http_headers_in_t, te),
                 rp_http_process_header_line },

    { rp_string("Expect"),
                 offsetof(rp_http_headers_in_t, expect),
                 rp_http_process_unique_header_line },

    { rp_string("Upgrade"),
                 offsetof(rp_http_headers_in_t, upgrade),
                 rp_http_process_header_line },

#if (RP_HTTP_GZIP || RP_HTTP_HEADERS)
    { rp_string("Accept-Encoding"),
                 offsetof(rp_http_headers_in_t, accept_encoding),
                 rp_http_process_header_line },

    { rp_string("Via"), offsetof(rp_http_headers_in_t, via),
                 rp_http_process_header_line },
#endif

    { rp_string("Authorization"),
                 offsetof(rp_http_headers_in_t, authorization),
                 rp_http_process_unique_header_line },

    { rp_string("Keep-Alive"), offsetof(rp_http_headers_in_t, keep_alive),
                 rp_http_process_header_line },

#if (RP_HTTP_X_FORWARDED_FOR)
    { rp_string("X-Forwarded-For"),
                 offsetof(rp_http_headers_in_t, x_forwarded_for),
                 rp_http_process_multi_header_lines },
#endif

#if (RP_HTTP_REALIP)
    { rp_string("X-Real-IP"),
                 offsetof(rp_http_headers_in_t, x_real_ip),
                 rp_http_process_header_line },
#endif

#if (RP_HTTP_HEADERS)
    { rp_string("Accept"), offsetof(rp_http_headers_in_t, accept),
                 rp_http_process_header_line },

    { rp_string("Accept-Language"),
                 offsetof(rp_http_headers_in_t, accept_language),
                 rp_http_process_header_line },
#endif

#if (RP_HTTP_DAV)
    { rp_string("Depth"), offsetof(rp_http_headers_in_t, depth),
                 rp_http_process_header_line },

    { rp_string("Destination"), offsetof(rp_http_headers_in_t, destination),
                 rp_http_process_header_line },

    { rp_string("Overwrite"), offsetof(rp_http_headers_in_t, overwrite),
                 rp_http_process_header_line },

    { rp_string("Date"), offsetof(rp_http_headers_in_t, date),
                 rp_http_process_header_line },
#endif

    { rp_string("Cookie"), offsetof(rp_http_headers_in_t, cookies),
                 rp_http_process_multi_header_lines },

    { rp_null_string, 0, NULL }
};


void
rp_http_init_connection(rp_connection_t *c)
{
    rp_uint_t              i;
    rp_event_t            *rev;
    struct sockaddr_in     *sin;
    rp_http_port_t        *port;
    rp_http_in_addr_t     *addr;
    rp_http_log_ctx_t     *ctx;
    rp_http_connection_t  *hc;
#if (RP_HAVE_INET6)
    struct sockaddr_in6    *sin6;
    rp_http_in6_addr_t    *addr6;
#endif

    hc = rp_pcalloc(c->pool, sizeof(rp_http_connection_t));
    if (hc == NULL) {
        rp_http_close_connection(c);
        return;
    }

    c->data = hc;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in rp_http_server_addr()
         * is required to determine a server address
         */

        if (rp_connection_local_sockaddr(c, NULL, 0) != RP_OK) {
            rp_http_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (rp_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
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

#if (RP_HAVE_INET6)
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

    ctx = rp_palloc(c->pool, sizeof(rp_http_log_ctx_t));
    if (ctx == NULL) {
        rp_http_close_connection(c);
        return;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log->connection = c->number;
    c->log->handler = rp_http_log_error;
    c->log->data = ctx;
    c->log->action = "waiting for request";

    c->log_error = RP_ERROR_INFO;

    rev = c->read;
    rev->handler = rp_http_wait_request_handler;
    c->write->handler = rp_http_empty_handler;

#if (RP_HTTP_V2)
    if (hc->addr_conf->http2) {
        rev->handler = rp_http_v2_init;
    }
#endif

#if (RP_HTTP_SSL)
    {
    rp_http_ssl_srv_conf_t  *sscf;

    sscf = rp_http_get_module_srv_conf(hc->conf_ctx, rp_http_ssl_module);

    if (sscf->enable || hc->addr_conf->ssl) {
        hc->ssl = 1;
        c->log->action = "SSL handshaking";
        rev->handler = rp_http_ssl_handshake;
    }
    }
#endif

    if (hc->addr_conf->proxy_protocol) {
        hc->proxy_protocol = 1;
        c->log->action = "reading PROXY protocol";
    }

    if (rev->ready) {
        /* the deferred accept(), iocp */

        if (rp_use_accept_mutex) {
            rp_post_event(rev, &rp_posted_events);
            return;
        }

        rev->handler(rev);
        return;
    }

    rp_add_timer(rev, c->listening->post_accept_timeout);
    rp_reusable_connection(c, 1);

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        rp_http_close_connection(c);
        return;
    }
}


static void
rp_http_wait_request_handler(rp_event_t *rev)
{
    u_char                    *p;
    size_t                     size;
    ssize_t                    n;
    rp_buf_t                 *b;
    rp_connection_t          *c;
    rp_http_connection_t     *hc;
    rp_http_core_srv_conf_t  *cscf;

    c = rev->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        rp_http_close_connection(c);
        return;
    }

    if (c->close) {
        rp_http_close_connection(c);
        return;
    }

    hc = c->data;
    cscf = rp_http_get_module_srv_conf(hc->conf_ctx, rp_http_core_module);

    size = cscf->client_header_buffer_size;

    b = c->buffer;

    if (b == NULL) {
        b = rp_create_temp_buf(c->pool, size);
        if (b == NULL) {
            rp_http_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = rp_palloc(c->pool, size);
        if (b->start == NULL) {
            rp_http_close_connection(c);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    n = c->recv(c, b->last, size);

    if (n == RP_AGAIN) {

        if (!rev->timer_set) {
            rp_add_timer(rev, c->listening->post_accept_timeout);
            rp_reusable_connection(c, 1);
        }

        if (rp_handle_read_event(rev, 0) != RP_OK) {
            rp_http_close_connection(c);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        if (rp_pfree(c->pool, b->start) == RP_OK) {
            b->start = NULL;
        }

        return;
    }

    if (n == RP_ERROR) {
        rp_http_close_connection(c);
        return;
    }

    if (n == 0) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "client closed connection");
        rp_http_close_connection(c);
        return;
    }

    b->last += n;

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = rp_proxy_protocol_read(c, b->pos, b->last);

        if (p == NULL) {
            rp_http_close_connection(c);
            return;
        }

        b->pos = p;

        if (b->pos == b->last) {
            c->log->action = "waiting for request";
            b->pos = b->start;
            b->last = b->start;
            rp_post_event(rev, &rp_posted_events);
            return;
        }
    }

    c->log->action = "reading client request line";

    rp_reusable_connection(c, 0);

    c->data = rp_http_create_request(c);
    if (c->data == NULL) {
        rp_http_close_connection(c);
        return;
    }

    rev->handler = rp_http_process_request_line;
    rp_http_process_request_line(rev);
}


rp_http_request_t *
rp_http_create_request(rp_connection_t *c)
{
    rp_http_request_t        *r;
    rp_http_log_ctx_t        *ctx;
    rp_http_core_loc_conf_t  *clcf;

    r = rp_http_alloc_request(c);
    if (r == NULL) {
        return NULL;
    }

    c->requests++;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rp_set_connection_log(c, clcf->error_log);

    ctx = c->log->data;
    ctx->request = r;
    ctx->current_request = r;

#if (RP_STAT_STUB)
    (void) rp_atomic_fetch_add(rp_stat_reading, 1);
    r->stat_reading = 1;
    (void) rp_atomic_fetch_add(rp_stat_requests, 1);
#endif

    return r;
}


static rp_http_request_t *
rp_http_alloc_request(rp_connection_t *c)
{
    rp_pool_t                 *pool;
    rp_time_t                 *tp;
    rp_http_request_t         *r;
    rp_http_connection_t      *hc;
    rp_http_core_srv_conf_t   *cscf;
    rp_http_core_main_conf_t  *cmcf;

    hc = c->data;

    cscf = rp_http_get_module_srv_conf(hc->conf_ctx, rp_http_core_module);

    pool = rp_create_pool(cscf->request_pool_size, c->log);
    if (pool == NULL) {
        return NULL;
    }

    r = rp_pcalloc(pool, sizeof(rp_http_request_t));
    if (r == NULL) {
        rp_destroy_pool(pool);
        return NULL;
    }

    r->pool = pool;

    r->http_connection = hc;
    r->signature = RP_HTTP_MODULE;
    r->connection = c;

    r->main_conf = hc->conf_ctx->main_conf;
    r->srv_conf = hc->conf_ctx->srv_conf;
    r->loc_conf = hc->conf_ctx->loc_conf;

    r->read_event_handler = rp_http_block_reading;

    r->header_in = hc->busy ? hc->busy->buf : c->buffer;

    if (rp_list_init(&r->headers_out.headers, r->pool, 20,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        rp_destroy_pool(r->pool);
        return NULL;
    }

    if (rp_list_init(&r->headers_out.trailers, r->pool, 4,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        rp_destroy_pool(r->pool);
        return NULL;
    }

    r->ctx = rp_pcalloc(r->pool, sizeof(void *) * rp_http_max_module);
    if (r->ctx == NULL) {
        rp_destroy_pool(r->pool);
        return NULL;
    }

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    r->variables = rp_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(rp_http_variable_value_t));
    if (r->variables == NULL) {
        rp_destroy_pool(r->pool);
        return NULL;
    }

#if (RP_HTTP_SSL)
    if (c->ssl) {
        r->main_filter_need_in_memory = 1;
    }
#endif

    r->main = r;
    r->count = 1;

    tp = rp_timeofday();
    r->start_sec = tp->sec;
    r->start_msec = tp->msec;

    r->method = RP_HTTP_UNKNOWN;
    r->http_version = RP_HTTP_VERSION_10;

    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    r->uri_changes = RP_HTTP_MAX_URI_CHANGES + 1;
    r->subrequests = RP_HTTP_MAX_SUBREQUESTS + 1;

    r->http_state = RP_HTTP_READING_REQUEST_STATE;

    r->log_handler = rp_http_log_error_handler;

    return r;
}


#if (RP_HTTP_SSL)

static void
rp_http_ssl_handshake(rp_event_t *rev)
{
    u_char                    *p, buf[RP_PROXY_PROTOCOL_MAX_HEADER + 1];
    size_t                     size;
    ssize_t                    n;
    rp_err_t                  err;
    rp_int_t                  rc;
    rp_connection_t          *c;
    rp_http_connection_t     *hc;
    rp_http_ssl_srv_conf_t   *sscf;
    rp_http_core_loc_conf_t  *clcf;

    c = rev->data;
    hc = c->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http check ssl handshake");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        rp_http_close_connection(c);
        return;
    }

    if (c->close) {
        rp_http_close_connection(c);
        return;
    }

    size = hc->proxy_protocol ? sizeof(buf) : 1;

    n = recv(c->fd, (char *) buf, size, MSG_PEEK);

    err = rp_socket_errno;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, rev->log, 0, "http recv(): %z", n);

    if (n == -1) {
        if (err == RP_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                rp_add_timer(rev, c->listening->post_accept_timeout);
                rp_reusable_connection(c, 1);
            }

            if (rp_handle_read_event(rev, 0) != RP_OK) {
                rp_http_close_connection(c);
            }

            return;
        }

        rp_connection_error(c, err, "recv() failed");
        rp_http_close_connection(c);

        return;
    }

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = rp_proxy_protocol_read(c, buf, buf + n);

        if (p == NULL) {
            rp_http_close_connection(c);
            return;
        }

        size = p - buf;

        if (c->recv(c, buf, size) != (ssize_t) size) {
            rp_http_close_connection(c);
            return;
        }

        c->log->action = "SSL handshaking";

        if (n == (ssize_t) size) {
            rp_post_event(rev, &rp_posted_events);
            return;
        }

        n = 1;
        buf[0] = *p;
    }

    if (n == 1) {
        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            rp_log_debug1(RP_LOG_DEBUG_HTTP, rev->log, 0,
                           "https ssl handshake: 0x%02Xd", buf[0]);

            clcf = rp_http_get_module_loc_conf(hc->conf_ctx,
                                                rp_http_core_module);

            if (clcf->tcp_nodelay && rp_tcp_nodelay(c) != RP_OK) {
                rp_http_close_connection(c);
                return;
            }

            sscf = rp_http_get_module_srv_conf(hc->conf_ctx,
                                                rp_http_ssl_module);

            if (rp_ssl_create_connection(&sscf->ssl, c, RP_SSL_BUFFER)
                != RP_OK)
            {
                rp_http_close_connection(c);
                return;
            }

            rp_reusable_connection(c, 0);

            rc = rp_ssl_handshake(c);

            if (rc == RP_AGAIN) {

                if (!rev->timer_set) {
                    rp_add_timer(rev, c->listening->post_accept_timeout);
                }

                c->ssl->handler = rp_http_ssl_handshake_handler;
                return;
            }

            rp_http_ssl_handshake_handler(c);

            return;
        }

        rp_log_debug0(RP_LOG_DEBUG_HTTP, rev->log, 0, "plain http");

        c->log->action = "waiting for request";

        rev->handler = rp_http_wait_request_handler;
        rp_http_wait_request_handler(rev);

        return;
    }

    rp_log_error(RP_LOG_INFO, c->log, 0, "client closed connection");
    rp_http_close_connection(c);
}


static void
rp_http_ssl_handshake_handler(rp_connection_t *c)
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

#if (RP_HTTP_V2                                                              \
     && (defined TLSEXT_TYPE_application_layer_protocol_negotiation           \
         || defined TLSEXT_TYPE_next_proto_neg))
        {
        unsigned int            len;
        const unsigned char    *data;
        rp_http_connection_t  *hc;

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
                rp_http_v2_init(c->read);
                return;
            }
        }
        }
#endif

        c->log->action = "waiting for request";

        c->read->handler = rp_http_wait_request_handler;
        /* STUB: epoll edge */ c->write->handler = rp_http_empty_handler;

        rp_reusable_connection(c, 1);

        rp_http_wait_request_handler(c->read);

        return;
    }

    if (c->read->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
    }

    rp_http_close_connection(c);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
rp_http_ssl_servername(rp_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    rp_int_t                  rc;
    rp_str_t                  host;
    const char                *servername;
    rp_connection_t          *c;
    rp_http_connection_t     *hc;
    rp_http_ssl_srv_conf_t   *sscf;
    rp_http_core_loc_conf_t  *clcf;
    rp_http_core_srv_conf_t  *cscf;

    c = rp_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        *ad = SSL_AD_NO_RENEGOTIATION;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL) {
        return SSL_TLSEXT_ERR_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL server name: \"%s\"", servername);

    host.len = rp_strlen(servername);

    if (host.len == 0) {
        return SSL_TLSEXT_ERR_OK;
    }

    host.data = (u_char *) servername;

    rc = rp_http_validate_host(&host, c->pool, 1);

    if (rc == RP_ERROR) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (rc == RP_DECLINED) {
        return SSL_TLSEXT_ERR_OK;
    }

    hc = c->data;

    rc = rp_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
                                      NULL, &cscf);

    if (rc == RP_ERROR) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (rc == RP_DECLINED) {
        return SSL_TLSEXT_ERR_OK;
    }

    hc->ssl_servername = rp_palloc(c->pool, sizeof(rp_str_t));
    if (hc->ssl_servername == NULL) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    *hc->ssl_servername = host;

    hc->conf_ctx = cscf->ctx;

    clcf = rp_http_get_module_loc_conf(hc->conf_ctx, rp_http_core_module);

    rp_set_connection_log(c, clcf->error_log);

    sscf = rp_http_get_module_srv_conf(hc->conf_ctx, rp_http_ssl_module);

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
rp_http_ssl_certificate(rp_ssl_conn_t *ssl_conn, void *arg)
{
    rp_str_t                  cert, key;
    rp_uint_t                 i, nelts;
    rp_connection_t          *c;
    rp_http_request_t        *r;
    rp_http_ssl_srv_conf_t   *sscf;
    rp_http_complex_value_t  *certs, *keys;

    c = rp_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    r = rp_http_alloc_request(c);
    if (r == NULL) {
        return 0;
    }

    r->logged = 1;

    sscf = arg;

    nelts = sscf->certificate_values->nelts;
    certs = sscf->certificate_values->elts;
    keys = sscf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (rp_http_complex_value(r, &certs[i], &cert) != RP_OK) {
            goto failed;
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (rp_http_complex_value(r, &keys[i], &key) != RP_OK) {
            goto failed;
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (rp_ssl_connection_certificate(c, r->pool, &cert, &key,
                                           sscf->passwords)
            != RP_OK)
        {
            goto failed;
        }
    }

    rp_http_free_request(r, 0);
    c->destroyed = 0;
    return 1;

failed:

    rp_http_free_request(r, 0);
    c->destroyed = 0;
    return 0;
}

#endif

#endif


static void
rp_http_process_request_line(rp_event_t *rev)
{
    ssize_t              n;
    rp_int_t            rc, rv;
    rp_str_t            host;
    rp_connection_t    *c;
    rp_http_request_t  *r;

    c = rev->data;
    r = c->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rp_http_close_request(r, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = RP_AGAIN;

    for ( ;; ) {

        if (rc == RP_AGAIN) {
            n = rp_http_read_request_header(r);

            if (n == RP_AGAIN || n == RP_ERROR) {
                break;
            }
        }

        rc = rp_http_parse_request_line(r, r->header_in);

        if (rc == RP_OK) {

            /* the request line has been parsed successfully */

            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
            r->request_length = r->header_in->pos - r->request_start;

            rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%V\"", &r->request_line);

            r->method_name.len = r->method_end - r->request_start + 1;
            r->method_name.data = r->request_line.data;

            if (r->http_protocol.data) {
                r->http_protocol.len = r->request_end - r->http_protocol.data;
            }

            if (rp_http_process_request_uri(r) != RP_OK) {
                break;
            }

            if (r->schema_end) {
                r->schema.len = r->schema_end - r->schema_start;
                r->schema.data = r->schema_start;
            }

            if (r->host_end) {

                host.len = r->host_end - r->host_start;
                host.data = r->host_start;

                rc = rp_http_validate_host(&host, r->pool, 0);

                if (rc == RP_DECLINED) {
                    rp_log_error(RP_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line");
                    rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
                    break;
                }

                if (rc == RP_ERROR) {
                    rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (rp_http_set_virtual_server(r, &host) == RP_ERROR) {
                    break;
                }

                r->headers_in.server = host;
            }

            if (r->http_version < RP_HTTP_VERSION_10) {

                if (r->headers_in.server.len == 0
                    && rp_http_set_virtual_server(r, &r->headers_in.server)
                       == RP_ERROR)
                {
                    break;
                }

                rp_http_process_request(r);
                break;
            }


            if (rp_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(rp_table_elt_t))
                != RP_OK)
            {
                rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            c->log->action = "reading client request headers";

            rev->handler = rp_http_process_request_headers;
            rp_http_process_request_headers(rev);

            break;
        }

        if (rc != RP_AGAIN) {

            /* there was error while a request line parsing */

            rp_log_error(RP_LOG_INFO, c->log, 0,
                          rp_http_client_errors[rc - RP_HTTP_CLIENT_ERROR]);

            if (rc == RP_HTTP_PARSE_INVALID_VERSION) {
                rp_http_finalize_request(r, RP_HTTP_VERSION_NOT_SUPPORTED);

            } else {
                rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
            }

            break;
        }

        /* RP_AGAIN: a request line parsing is still incomplete */

        if (r->header_in->pos == r->header_in->end) {

            rv = rp_http_alloc_large_header_buffer(r, 1);

            if (rv == RP_ERROR) {
                rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (rv == RP_DECLINED) {
                r->request_line.len = r->header_in->end - r->request_start;
                r->request_line.data = r->request_start;

                rp_log_error(RP_LOG_INFO, c->log, 0,
                              "client sent too long URI");
                rp_http_finalize_request(r, RP_HTTP_REQUEST_URI_TOO_LARGE);
                break;
            }
        }
    }

    rp_http_run_posted_requests(c);
}


rp_int_t
rp_http_process_request_uri(rp_http_request_t *r)
{
    rp_http_core_srv_conf_t  *cscf;

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->uri_end - r->uri_start;
    }

    if (r->complex_uri || r->quoted_uri) {

        r->uri.data = rp_pnalloc(r->pool, r->uri.len + 1);
        if (r->uri.data == NULL) {
            rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
            return RP_ERROR;
        }

        cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

        if (rp_http_parse_complex_uri(r, cscf->merge_slashes) != RP_OK) {
            r->uri.len = 0;

            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid request");
            rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
            return RP_ERROR;
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

#if (RP_WIN32)
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
                rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                              "client sent unsafe win32 URI");
                rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
                return RP_ERROR;
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
        rp_http_set_exten(r);
    }

    }
#endif

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uri: \"%V\"", &r->uri);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http args: \"%V\"", &r->args);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http exten: \"%V\"", &r->exten);

    return RP_OK;
}


static void
rp_http_process_request_headers(rp_event_t *rev)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    rp_int_t                   rc, rv;
    rp_table_elt_t            *h;
    rp_connection_t           *c;
    rp_http_header_t          *hh;
    rp_http_request_t         *r;
    rp_http_core_srv_conf_t   *cscf;
    rp_http_core_main_conf_t  *cmcf;

    c = rev->data;
    r = c->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rp_http_close_request(r, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    rc = RP_AGAIN;

    for ( ;; ) {

        if (rc == RP_AGAIN) {

            if (r->header_in->pos == r->header_in->end) {

                rv = rp_http_alloc_large_header_buffer(r, 0);

                if (rv == RP_ERROR) {
                    rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                if (rv == RP_DECLINED) {
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        rp_log_error(RP_LOG_INFO, c->log, 0,
                                      "client sent too large request");
                        rp_http_finalize_request(r,
                                            RP_HTTP_REQUEST_HEADER_TOO_LARGE);
                        break;
                    }

                    len = r->header_in->end - p;

                    if (len > RP_MAX_ERROR_STR - 300) {
                        len = RP_MAX_ERROR_STR - 300;
                    }

                    rp_log_error(RP_LOG_INFO, c->log, 0,
                                "client sent too long header line: \"%*s...\"",
                                len, r->header_name_start);

                    rp_http_finalize_request(r,
                                            RP_HTTP_REQUEST_HEADER_TOO_LARGE);
                    break;
                }
            }

            n = rp_http_read_request_header(r);

            if (n == RP_AGAIN || n == RP_ERROR) {
                break;
            }
        }

        /* the host header could change the server configuration context */
        cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

        rc = rp_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == RP_OK) {

            r->request_length += r->header_in->pos - r->header_name_start;

            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                rp_log_error(RP_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            h = rp_list_push(&r->headers_in.headers);
            if (h == NULL) {
                rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = rp_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (h->key.len == r->lowcase_index) {
                rp_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                rp_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = rp_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != RP_OK) {
                break;
            }

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == RP_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            r->http_state = RP_HTTP_PROCESS_REQUEST_STATE;

            rc = rp_http_process_request_header(r);

            if (rc != RP_OK) {
                break;
            }

            rp_http_process_request(r);

            break;
        }

        if (rc == RP_AGAIN) {

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == RP_HTTP_PARSE_INVALID_HEADER */

        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "client sent invalid header line");

        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        break;
    }

    rp_http_run_posted_requests(c);
}


static ssize_t
rp_http_read_request_header(rp_http_request_t *r)
{
    ssize_t                    n;
    rp_event_t               *rev;
    rp_connection_t          *c;
    rp_http_core_srv_conf_t  *cscf;

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
        n = RP_AGAIN;
    }

    if (n == RP_AGAIN) {
        if (!rev->timer_set) {
            cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);
            rp_add_timer(rev, cscf->client_header_timeout);
        }

        if (rp_handle_read_event(rev, 0) != RP_OK) {
            rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
            return RP_ERROR;
        }

        return RP_AGAIN;
    }

    if (n == 0) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    if (n == 0 || n == RP_ERROR) {
        c->error = 1;
        c->log->action = "reading client request headers";

        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        return RP_ERROR;
    }

    r->header_in->last += n;

    return n;
}


static rp_int_t
rp_http_alloc_large_header_buffer(rp_http_request_t *r,
    rp_uint_t request_line)
{
    u_char                    *old, *new;
    rp_buf_t                 *b;
    rp_chain_t               *cl;
    rp_http_connection_t     *hc;
    rp_http_core_srv_conf_t  *cscf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http alloc large header buffer");

    if (request_line && r->state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return RP_OK;
    }

    old = request_line ? r->request_start : r->header_name_start;

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return RP_DECLINED;
    }

    hc = r->http_connection;

    if (hc->free) {
        cl = hc->free;
        hc->free = cl->next;

        b = cl->buf;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header free: %p %uz",
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        b = rp_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return RP_ERROR;
        }

        cl = rp_alloc_chain_link(r->connection->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        cl->buf = b;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header alloc: %p %uz",
                       b->pos, b->end - b->last);

    } else {
        return RP_DECLINED;
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

        return RP_OK;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http large header copy: %uz", r->header_in->pos - old);

    new = b->start;

    rp_memcpy(new, old, r->header_in->pos - old);

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

    return RP_OK;
}


static rp_int_t
rp_http_process_header_line(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_table_elt_t  **ph;

    ph = (rp_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return RP_OK;
}


static rp_int_t
rp_http_process_unique_header_line(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_table_elt_t  **ph;

    ph = (rp_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
        return RP_OK;
    }

    rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                  "client sent duplicate header line: \"%V: %V\", "
                  "previous value: \"%V: %V\"",
                  &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);

    return RP_ERROR;
}


static rp_int_t
rp_http_process_host(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_int_t  rc;
    rp_str_t  host;

    if (r->headers_in.host) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate host header: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value, &r->headers_in.host->key,
                      &r->headers_in.host->value);
        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        return RP_ERROR;
    }

    r->headers_in.host = h;

    host = h->value;

    rc = rp_http_validate_host(&host, r->pool, 0);

    if (rc == RP_DECLINED) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        return RP_ERROR;
    }

    if (rc == RP_ERROR) {
        rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

    if (r->headers_in.server.len) {
        return RP_OK;
    }

    if (rp_http_set_virtual_server(r, &host) == RP_ERROR) {
        return RP_ERROR;
    }

    r->headers_in.server = host;

    return RP_OK;
}


static rp_int_t
rp_http_process_connection(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    if (rp_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->headers_in.connection_type = RP_HTTP_CONNECTION_CLOSE;

    } else if (rp_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = RP_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return RP_OK;
}


static rp_int_t
rp_http_process_user_agent(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (r->headers_in.user_agent) {
        return RP_OK;
    }

    r->headers_in.user_agent = h;

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    msie = rp_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (rp_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
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

    if (rp_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (rp_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (rp_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (rp_strstrn(user_agent, "Safari/", 7 - 1)
                   && rp_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (rp_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_process_multi_header_lines(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_array_t       *headers;
    rp_table_elt_t  **ph;

    headers = (rp_array_t *) ((char *) &r->headers_in + offset);

    if (headers->elts == NULL) {
        if (rp_array_init(headers, r->pool, 1, sizeof(rp_table_elt_t *))
            != RP_OK)
        {
            rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
            return RP_ERROR;
        }
    }

    ph = rp_array_push(headers);
    if (ph == NULL) {
        rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

    *ph = h;
    return RP_OK;
}


rp_int_t
rp_http_process_request_header(rp_http_request_t *r)
{
    if (r->headers_in.server.len == 0
        && rp_http_set_virtual_server(r, &r->headers_in.server)
           == RP_ERROR)
    {
        return RP_ERROR;
    }

    if (r->headers_in.host == NULL && r->http_version > RP_HTTP_VERSION_10) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                   "client sent HTTP/1.1 request without \"Host\" header");
        rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
        return RP_ERROR;
    }

    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            rp_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == RP_ERROR) {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            rp_http_finalize_request(r, RP_HTTP_BAD_REQUEST);
            return RP_ERROR;
        }
    }

    if (r->method == RP_HTTP_TRACE) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "client sent TRACE method");
        rp_http_finalize_request(r, RP_HTTP_NOT_ALLOWED);
        return RP_ERROR;
    }

    if (r->headers_in.transfer_encoding) {
        if (r->headers_in.transfer_encoding->value.len == 7
            && rp_strncasecmp(r->headers_in.transfer_encoding->value.data,
                               (u_char *) "chunked", 7) == 0)
        {
            r->headers_in.content_length = NULL;
            r->headers_in.content_length_n = -1;
            r->headers_in.chunked = 1;

        } else {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client sent unknown \"Transfer-Encoding\": \"%V\"",
                          &r->headers_in.transfer_encoding->value);
            rp_http_finalize_request(r, RP_HTTP_NOT_IMPLEMENTED);
            return RP_ERROR;
        }
    }

    if (r->headers_in.connection_type == RP_HTTP_CONNECTION_KEEP_ALIVE) {
        if (r->headers_in.keep_alive) {
            r->headers_in.keep_alive_n =
                            rp_atotm(r->headers_in.keep_alive->value.data,
                                      r->headers_in.keep_alive->value.len);
        }
    }

    return RP_OK;
}


void
rp_http_process_request(rp_http_request_t *r)
{
    rp_connection_t  *c;

    c = r->connection;

#if (RP_HTTP_SSL)

    if (r->http_connection->ssl) {
        long                      rc;
        X509                     *cert;
        rp_http_ssl_srv_conf_t  *sscf;

        if (c->ssl == NULL) {
            rp_log_error(RP_LOG_INFO, c->log, 0,
                          "client sent plain HTTP request to HTTPS port");
            rp_http_finalize_request(r, RP_HTTP_TO_HTTPS);
            return;
        }

        sscf = rp_http_get_module_srv_conf(r, rp_http_ssl_module);

        if (sscf->verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK
                && (sscf->verify != 3 || !rp_ssl_verify_error_optional(rc)))
            {
                rp_log_error(RP_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));

                rp_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                rp_http_finalize_request(r, RP_HTTPS_CERT_ERROR);
                return;
            }

            if (sscf->verify == 1) {
                cert = SSL_get_peer_certificate(c->ssl->connection);

                if (cert == NULL) {
                    rp_log_error(RP_LOG_INFO, c->log, 0,
                                  "client sent no required SSL certificate");

                    rp_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                    rp_http_finalize_request(r, RP_HTTPS_NO_CERT);
                    return;
                }

                X509_free(cert);
            }
        }
    }

#endif

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

#if (RP_STAT_STUB)
    (void) rp_atomic_fetch_add(rp_stat_reading, -1);
    r->stat_reading = 0;
    (void) rp_atomic_fetch_add(rp_stat_writing, 1);
    r->stat_writing = 1;
#endif

    c->read->handler = rp_http_request_handler;
    c->write->handler = rp_http_request_handler;
    r->read_event_handler = rp_http_block_reading;

    rp_http_handler(r);
}


static rp_int_t
rp_http_validate_host(rp_str_t *host, rp_pool_t *pool, rp_uint_t alloc)
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
                return RP_DECLINED;
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
            return RP_DECLINED;

        default:

            if (rp_path_separator(ch)) {
                return RP_DECLINED;
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
        return RP_DECLINED;
    }

    if (alloc) {
        host->data = rp_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return RP_ERROR;
        }

        rp_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return RP_OK;
}


static rp_int_t
rp_http_set_virtual_server(rp_http_request_t *r, rp_str_t *host)
{
    rp_int_t                  rc;
    rp_http_connection_t     *hc;
    rp_http_core_loc_conf_t  *clcf;
    rp_http_core_srv_conf_t  *cscf;

#if (RP_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

#if (RP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        if (hc->ssl_servername->len == host->len
            && rp_strncmp(hc->ssl_servername->data,
                           host->data, host->len) == 0)
        {
#if (RP_PCRE)
            if (hc->ssl_servername_regex
                && rp_http_regex_exec(r, hc->ssl_servername_regex,
                                          hc->ssl_servername) != RP_OK)
            {
                rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                return RP_ERROR;
            }
#endif
            return RP_OK;
        }
    }

#endif

    rc = rp_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == RP_ERROR) {
        rp_http_close_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return RP_ERROR;
    }

#if (RP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        rp_http_ssl_srv_conf_t  *sscf;

        if (rc == RP_DECLINED) {
            cscf = hc->addr_conf->default_server;
            rc = RP_OK;
        }

        sscf = rp_http_get_module_srv_conf(cscf->ctx, rp_http_ssl_module);

        if (sscf->verify) {
            rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from the one that was negotiated");
            rp_http_finalize_request(r, RP_HTTP_MISDIRECTED_REQUEST);
            return RP_ERROR;
        }
    }

#endif

    if (rc == RP_DECLINED) {
        return RP_OK;
    }

    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rp_set_connection_log(r->connection, clcf->error_log);

    return RP_OK;
}


static rp_int_t
rp_http_find_virtual_server(rp_connection_t *c,
    rp_http_virtual_names_t *virtual_names, rp_str_t *host,
    rp_http_request_t *r, rp_http_core_srv_conf_t **cscfp)
{
    rp_http_core_srv_conf_t  *cscf;

    if (virtual_names == NULL) {
        return RP_DECLINED;
    }

    cscf = rp_hash_find_combined(&virtual_names->names,
                                  rp_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return RP_OK;
    }

#if (RP_PCRE)

    if (host->len && virtual_names->nregex) {
        rp_int_t                n;
        rp_uint_t               i;
        rp_http_server_name_t  *sn;

        sn = virtual_names->regex;

#if (RP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

        if (r == NULL) {
            rp_http_connection_t  *hc;

            for (i = 0; i < virtual_names->nregex; i++) {

                n = rp_regex_exec(sn[i].regex->regex, host, NULL, 0);

                if (n == RP_REGEX_NO_MATCHED) {
                    continue;
                }

                if (n >= 0) {
                    hc = c->data;
                    hc->ssl_servername_regex = sn[i].regex;

                    *cscfp = sn[i].server;
                    return RP_OK;
                }

                rp_log_error(RP_LOG_ALERT, c->log, 0,
                              rp_regex_exec_n " failed: %i "
                              "on \"%V\" using \"%V\"",
                              n, host, &sn[i].regex->name);

                return RP_ERROR;
            }

            return RP_DECLINED;
        }

#endif /* RP_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */

        for (i = 0; i < virtual_names->nregex; i++) {

            n = rp_http_regex_exec(r, sn[i].regex, host);

            if (n == RP_DECLINED) {
                continue;
            }

            if (n == RP_OK) {
                *cscfp = sn[i].server;
                return RP_OK;
            }

            return RP_ERROR;
        }
    }

#endif /* RP_PCRE */

    return RP_DECLINED;
}


static void
rp_http_request_handler(rp_event_t *ev)
{
    rp_connection_t    *c;
    rp_http_request_t  *r;

    c = ev->data;
    r = c->data;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http run request: \"%V?%V\"", &r->uri, &r->args);

    if (c->close) {
        r->main->count++;
        rp_http_terminate_request(r, 0);
        rp_http_run_posted_requests(c);
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

    rp_http_run_posted_requests(c);
}


void
rp_http_run_posted_requests(rp_connection_t *c)
{
    rp_http_request_t         *r;
    rp_http_posted_request_t  *pr;

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

        rp_http_set_log_request(c->log, r);

        rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "http posted request: \"%V?%V\"", &r->uri, &r->args);

        r->write_event_handler(r);
    }
}


rp_int_t
rp_http_post_request(rp_http_request_t *r, rp_http_posted_request_t *pr)
{
    rp_http_posted_request_t  **p;

    if (pr == NULL) {
        pr = rp_palloc(r->pool, sizeof(rp_http_posted_request_t));
        if (pr == NULL) {
            return RP_ERROR;
        }
    }

    pr->request = r;
    pr->next = NULL;

    for (p = &r->main->posted_requests; *p; p = &(*p)->next) { /* void */ }

    *p = pr;

    return RP_OK;
}


void
rp_http_finalize_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_connection_t          *c;
    rp_http_request_t        *pr;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;

    rp_log_debug5(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http finalize request: %i, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    if (rc == RP_DONE) {
        rp_http_finalize_connection(r);
        return;
    }

    if (rc == RP_OK && r->filter_finalize) {
        c->error = 1;
    }

    if (rc == RP_DECLINED) {
        r->content_handler = NULL;
        r->write_event_handler = rp_http_core_run_phases;
        rp_http_core_run_phases(r);
        return;
    }

    if (r != r->main && r->post_subrequest) {
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    if (rc == RP_ERROR
        || rc == RP_HTTP_REQUEST_TIME_OUT
        || rc == RP_HTTP_CLIENT_CLOSED_REQUEST
        || c->error)
    {
        if (rp_http_post_action(r) == RP_OK) {
            return;
        }

        rp_http_terminate_request(r, rc);
        return;
    }

    if (rc >= RP_HTTP_SPECIAL_RESPONSE
        || rc == RP_HTTP_CREATED
        || rc == RP_HTTP_NO_CONTENT)
    {
        if (rc == RP_HTTP_CLOSE) {
            c->timedout = 1;
            rp_http_terminate_request(r, rc);
            return;
        }

        if (r == r->main) {
            if (c->read->timer_set) {
                rp_del_timer(c->read);
            }

            if (c->write->timer_set) {
                rp_del_timer(c->write);
            }
        }

        c->read->handler = rp_http_request_handler;
        c->write->handler = rp_http_request_handler;

        rp_http_finalize_request(r, rp_http_special_response_handler(r, rc));
        return;
    }

    if (r != r->main) {

        if (r->buffered || r->postponed) {

            if (rp_http_set_write_handler(r) != RP_OK) {
                rp_http_terminate_request(r, 0);
            }

            return;
        }

        pr = r->parent;

        if (r == c->data || r->background) {

            if (!r->logged) {

                clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

                if (clcf->log_subrequest) {
                    rp_http_log_request(r);
                }

                r->logged = 1;

            } else {
                rp_log_error(RP_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (r->background) {
                rp_http_finalize_connection(r);
                return;
            }

            r->main->count--;

            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            c->data = pr;

        } else {

            rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                           "http finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = rp_http_request_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        if (rp_http_post_request(pr, NULL) != RP_OK) {
            r->main->count++;
            rp_http_terminate_request(r, 0);
            return;
        }

        rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "http wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

    if (r->buffered || c->buffered || r->postponed) {

        if (rp_http_set_write_handler(r) != RP_OK) {
            rp_http_terminate_request(r, 0);
        }

        return;
    }

    if (r != c->data) {
        rp_log_error(RP_LOG_ALERT, c->log, 0,
                      "http finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;

    r->read_event_handler = rp_http_block_reading;
    r->write_event_handler = rp_http_request_empty_handler;

    if (!r->post_action) {
        r->request_complete = 1;
    }

    if (rp_http_post_action(r) == RP_OK) {
        return;
    }

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        rp_del_timer(c->write);
    }

    if (c->read->eof) {
        rp_http_close_request(r, 0);
        return;
    }

    rp_http_finalize_connection(r);
}


static void
rp_http_terminate_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_http_cleanup_t    *cln;
    rp_http_request_t    *mr;
    rp_http_ephemeral_t  *e;

    mr = r->main;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    if (mr->write_event_handler) {

        if (mr->blocked) {
            r->connection->error = 1;
            r->write_event_handler = rp_http_request_finalizer;
            return;
        }

        e = rp_http_ephemeral(mr);
        mr->posted_requests = NULL;
        mr->write_event_handler = rp_http_terminate_handler;
        (void) rp_http_post_request(mr, &e->terminal_posted_request);
        return;
    }

    rp_http_close_request(mr, rc);
}


static void
rp_http_terminate_handler(rp_http_request_t *r)
{
    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate handler count:%d", r->count);

    r->count = 1;

    rp_http_close_request(r, 0);
}


static void
rp_http_finalize_connection(rp_http_request_t *r)
{
    rp_http_core_loc_conf_t  *clcf;

#if (RP_HTTP_V2)
    if (r->stream) {
        rp_http_close_request(r, 0);
        return;
    }
#endif

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (r->main->count != 1) {

        if (r->discard_body) {
            r->read_event_handler = rp_http_discarded_request_body_handler;
            rp_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = rp_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

        rp_http_close_request(r, 0);
        return;
    }

    r = r->main;

    if (r->reading_body) {
        r->keepalive = 0;
        r->lingering_close = 1;
    }

    if (!rp_terminate
         && !rp_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        rp_http_set_keepalive(r);
        return;
    }

    if (clcf->lingering_close == RP_HTTP_LINGERING_ALWAYS
        || (clcf->lingering_close == RP_HTTP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready)))
    {
        rp_http_set_lingering_close(r);
        return;
    }

    rp_http_close_request(r, 0);
}


static rp_int_t
rp_http_set_write_handler(rp_http_request_t *r)
{
    rp_event_t               *wev;
    rp_http_core_loc_conf_t  *clcf;

    r->http_state = RP_HTTP_WRITING_REQUEST_STATE;

    r->read_event_handler = r->discard_body ?
                                rp_http_discarded_request_body_handler:
                                rp_http_test_reading;
    r->write_event_handler = rp_http_writer;

    wev = r->connection->write;

    if (wev->ready && wev->delayed) {
        return RP_OK;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
    if (!wev->delayed) {
        rp_add_timer(wev, clcf->send_timeout);
    }

    if (rp_handle_write_event(wev, clcf->send_lowat) != RP_OK) {
        rp_http_close_request(r, 0);
        return RP_ERROR;
    }

    return RP_OK;
}


static void
rp_http_writer(rp_http_request_t *r)
{
    rp_int_t                  rc;
    rp_event_t               *wev;
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;
    wev = c->write;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer handler: \"%V?%V\"", &r->uri, &r->args);

    clcf = rp_http_get_module_loc_conf(r->main, rp_http_core_module);

    if (wev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;

        rp_http_finalize_request(r, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (wev->delayed || r->aio) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, wev->log, 0,
                       "http writer delayed");

        if (!wev->delayed) {
            rp_add_timer(wev, clcf->send_timeout);
        }

        if (rp_handle_write_event(wev, clcf->send_lowat) != RP_OK) {
            rp_http_close_request(r, 0);
        }

        return;
    }

    rc = rp_http_output_filter(r, NULL);

    rp_log_debug3(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http writer output filter: %i, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    if (rc == RP_ERROR) {
        rp_http_finalize_request(r, rc);
        return;
    }

    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

        if (!wev->delayed) {
            rp_add_timer(wev, clcf->send_timeout);
        }

        if (rp_handle_write_event(wev, clcf->send_lowat) != RP_OK) {
            rp_http_close_request(r, 0);
        }

        return;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer done: \"%V?%V\"", &r->uri, &r->args);

    r->write_event_handler = rp_http_request_empty_handler;

    rp_http_finalize_request(r, rc);
}


static void
rp_http_request_finalizer(rp_http_request_t *r)
{
    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalizer done: \"%V?%V\"", &r->uri, &r->args);

    rp_http_finalize_request(r, 0);
}


void
rp_http_block_reading(rp_http_request_t *r)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reading blocked");

    /* aio does not call this handler */

    if ((rp_event_flags & RP_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (rp_del_event(r->connection->read, RP_READ_EVENT, 0) != RP_OK) {
            rp_http_close_request(r, 0);
        }
    }
}


void
rp_http_test_reading(rp_http_request_t *r)
{
    int                n;
    char               buf[1];
    rp_err_t          err;
    rp_event_t       *rev;
    rp_connection_t  *c;

    c = r->connection;
    rev = c->read;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "http test reading");

#if (RP_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (RP_HAVE_EPOLLRDHUP)

    if ((rp_event_flags & RP_USE_EPOLL_EVENT) && rp_use_epoll_rdhup) {
        socklen_t  len;

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(rp_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = rp_socket_errno;
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
        err = rp_socket_errno;

        if (err != RP_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((rp_event_flags & RP_USE_LEVEL_EVENT) && rev->active) {

        if (rp_del_event(rev, RP_READ_EVENT, 0) != RP_OK) {
            rp_http_close_request(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    rp_log_error(RP_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    rp_http_finalize_request(r, RP_HTTP_CLIENT_CLOSED_REQUEST);
}


static void
rp_http_set_keepalive(rp_http_request_t *r)
{
    int                        tcp_nodelay;
    rp_buf_t                 *b, *f;
    rp_chain_t               *cl, *ln;
    rp_event_t               *rev, *wev;
    rp_connection_t          *c;
    rp_http_connection_t     *hc;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    if (r->discard_body) {
        r->write_event_handler = rp_http_request_empty_handler;
        r->lingering_time = rp_time() + (time_t) (clcf->lingering_time / 1000);
        rp_add_timer(rev, clcf->lingering_timeout);
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
             * the pipelined request (see rp_http_create_request()).
             *
             * Now we would move the large header buffers to the free list.
             */

            for (cl = hc->busy; cl; /* void */) {
                ln = cl;
                cl = cl->next;

                if (ln->buf == b) {
                    rp_free_chain(c->pool, ln);
                    continue;
                }

                f = ln->buf;
                f->pos = f->start;
                f->last = f->start;

                ln->next = hc->free;
                hc->free = ln;
            }

            cl = rp_alloc_chain_link(c->pool);
            if (cl == NULL) {
                rp_http_close_request(r, 0);
                return;
            }

            cl->buf = b;
            cl->next = NULL;

            hc->busy = cl;
            hc->nbusy = 1;
        }
    }

    /* guard against recursive call from rp_http_finalize_connection() */
    r->keepalive = 0;

    rp_http_free_request(r, 0);

    c->data = hc;

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        rp_http_close_connection(c);
        return;
    }

    wev = c->write;
    wev->handler = rp_http_empty_handler;

    if (b->pos < b->last) {

        rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        c->log->action = "reading client pipelined request line";

        r = rp_http_create_request(c);
        if (r == NULL) {
            rp_http_close_connection(c);
            return;
        }

        r->pipeline = 1;

        c->data = r;

        c->sent = 0;
        c->destroyed = 0;

        if (rev->timer_set) {
            rp_del_timer(rev);
        }

        rev->handler = rp_http_process_request_line;
        rp_post_event(rev, &rp_posted_events);
        return;
    }

    /*
     * To keep a memory footprint as small as possible for an idle keepalive
     * connection we try to free c->buffer's memory if it was allocated outside
     * the c->pool.  The large header buffers are always allocated outside the
     * c->pool and are freed too.
     */

    b = c->buffer;

    if (rp_pfree(c->pool, b->start) == RP_OK) {

        /*
         * the special note for rp_http_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0, "hc free: %p",
                   hc->free);

    if (hc->free) {
        for (cl = hc->free; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            rp_pfree(c->pool, ln->buf->start);
            rp_free_chain(c->pool, ln);
        }

        hc->free = NULL;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0, "hc busy: %p %i",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (cl = hc->busy; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            rp_pfree(c->pool, ln->buf->start);
            rp_free_chain(c->pool, ln);
        }

        hc->busy = NULL;
        hc->nbusy = 0;
    }

#if (RP_HTTP_SSL)
    if (c->ssl) {
        rp_ssl_free_buffer(c);
    }
#endif

    rev->handler = rp_http_keepalive_handler;

    if (wev->active && (rp_event_flags & RP_USE_LEVEL_EVENT)) {
        if (rp_del_event(wev, RP_WRITE_EVENT, 0) != RP_OK) {
            rp_http_close_connection(c);
            return;
        }
    }

    c->log->action = "keepalive";

    if (c->tcp_nopush == RP_TCP_NOPUSH_SET) {
        if (rp_tcp_push(c->fd) == -1) {
            rp_connection_error(c, rp_socket_errno, rp_tcp_push_n " failed");
            rp_http_close_connection(c);
            return;
        }

        c->tcp_nopush = RP_TCP_NOPUSH_UNSET;
        tcp_nodelay = rp_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    if (tcp_nodelay && clcf->tcp_nodelay && rp_tcp_nodelay(c) != RP_OK) {
        rp_http_close_connection(c);
        return;
    }

#if 0
    /* if rp_http_request_t was freed then we need some other place */
    r->http_state = RP_HTTP_KEEPALIVE_STATE;
#endif

    c->idle = 1;
    rp_reusable_connection(c, 1);

    rp_add_timer(rev, clcf->keepalive_timeout);

    if (rev->ready) {
        rp_post_event(rev, &rp_posted_events);
    }
}


static void
rp_http_keepalive_handler(rp_event_t *rev)
{
    size_t             size;
    ssize_t            n;
    rp_buf_t         *b;
    rp_connection_t  *c;

    c = rev->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (rev->timedout || c->close) {
        rp_http_close_connection(c);
        return;
    }

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            rp_log_error(RP_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (RP_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            rp_http_close_connection(c);
            return;
        }
    }

#endif

    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The c->buffer's memory was freed by rp_http_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = rp_palloc(c->pool, size);
        if (b->pos == NULL) {
            rp_http_close_connection(c);
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

    c->log_error = RP_ERROR_IGNORE_ECONNRESET;
    rp_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = RP_ERROR_INFO;

    if (n == RP_AGAIN) {
        if (rp_handle_read_event(rev, 0) != RP_OK) {
            rp_http_close_connection(c);
            return;
        }

        /*
         * Like rp_http_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (rp_pfree(c->pool, b->start) == RP_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == RP_ERROR) {
        rp_http_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        rp_log_error(RP_LOG_INFO, c->log, rp_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        rp_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->handler = rp_http_log_error;
    c->log->action = "reading client request line";

    c->idle = 0;
    rp_reusable_connection(c, 0);

    c->data = rp_http_create_request(c);
    if (c->data == NULL) {
        rp_http_close_connection(c);
        return;
    }

    c->sent = 0;
    c->destroyed = 0;

    rp_del_timer(rev);

    rev->handler = rp_http_process_request_line;
    rp_http_process_request_line(rev);
}


static void
rp_http_set_lingering_close(rp_http_request_t *r)
{
    rp_event_t               *rev, *wev;
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rev = c->read;
    rev->handler = rp_http_lingering_close_handler;

    r->lingering_time = rp_time() + (time_t) (clcf->lingering_time / 1000);
    rp_add_timer(rev, clcf->lingering_timeout);

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        rp_http_close_request(r, 0);
        return;
    }

    wev = c->write;
    wev->handler = rp_http_empty_handler;

    if (wev->active && (rp_event_flags & RP_USE_LEVEL_EVENT)) {
        if (rp_del_event(wev, RP_WRITE_EVENT, 0) != RP_OK) {
            rp_http_close_request(r, 0);
            return;
        }
    }

    if (rp_shutdown_socket(c->fd, RP_WRITE_SHUTDOWN) == -1) {
        rp_connection_error(c, rp_socket_errno,
                             rp_shutdown_socket_n " failed");
        rp_http_close_request(r, 0);
        return;
    }

    if (rev->ready) {
        rp_http_lingering_close_handler(rev);
    }
}


static void
rp_http_lingering_close_handler(rp_event_t *rev)
{
    ssize_t                    n;
    rp_msec_t                 timer;
    rp_connection_t          *c;
    rp_http_request_t        *r;
    rp_http_core_loc_conf_t  *clcf;
    u_char                     buffer[RP_HTTP_LINGERING_BUFFER_SIZE];

    c = rev->data;
    r = c->data;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    if (rev->timedout) {
        rp_http_close_request(r, 0);
        return;
    }

    timer = (rp_msec_t) r->lingering_time - (rp_msec_t) rp_time();
    if ((rp_msec_int_t) timer <= 0) {
        rp_http_close_request(r, 0);
        return;
    }

    do {
        n = c->recv(c, buffer, RP_HTTP_LINGERING_BUFFER_SIZE);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == RP_AGAIN) {
            break;
        }

        if (n == RP_ERROR || n == 0) {
            rp_http_close_request(r, 0);
            return;
        }

    } while (rev->ready);

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        rp_http_close_request(r, 0);
        return;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    rp_add_timer(rev, timer);
}


void
rp_http_empty_handler(rp_event_t *wev)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");

    return;
}


void
rp_http_request_empty_handler(rp_http_request_t *r)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http request empty handler");

    return;
}


rp_int_t
rp_http_send_special(rp_http_request_t *r, rp_uint_t flags)
{
    rp_buf_t    *b;
    rp_chain_t   out;

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_ERROR;
    }

    if (flags & RP_HTTP_LAST) {

        if (r == r->main && !r->post_action) {
            b->last_buf = 1;

        } else {
            b->sync = 1;
            b->last_in_chain = 1;
        }
    }

    if (flags & RP_HTTP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    return rp_http_output_filter(r, &out);
}


static rp_int_t
rp_http_post_action(rp_http_request_t *r)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->post_action.data == NULL) {
        return RP_DECLINED;
    }

    if (r->post_action && r->uri_changes == 0) {
        return RP_DECLINED;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post action: \"%V\"", &clcf->post_action);

    r->main->count--;

    r->http_version = RP_HTTP_VERSION_9;
    r->header_only = 1;
    r->post_action = 1;

    r->read_event_handler = rp_http_block_reading;

    if (clcf->post_action.data[0] == '/') {
        rp_http_internal_redirect(r, &clcf->post_action, NULL);

    } else {
        rp_http_named_location(r, &clcf->post_action);
    }

    return RP_OK;
}


static void
rp_http_close_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_connection_t  *c;

    r = r->main;
    c = r->connection;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        rp_log_error(RP_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    r->count--;

    if (r->count || r->blocked) {
        return;
    }

#if (RP_HTTP_V2)
    if (r->stream) {
        rp_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif

    rp_http_free_request(r, rc);
    rp_http_close_connection(c);
}


void
rp_http_free_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_log_t                 *log;
    rp_pool_t                *pool;
    struct linger              linger;
    rp_http_cleanup_t        *cln;
    rp_http_log_ctx_t        *ctx;
    rp_http_core_loc_conf_t  *clcf;

    log = r->connection->log;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        rp_log_error(RP_LOG_ALERT, log, 0, "http request already closed");
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

#if (RP_STAT_STUB)

    if (r->stat_reading) {
        (void) rp_atomic_fetch_add(rp_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) rp_atomic_fetch_add(rp_stat_writing, -1);
    }

#endif

    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    if (!r->logged) {
        log->action = "logging request";

        rp_http_log_request(r);
    }

    log->action = "closing request";

    if (r->connection->timedout) {
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                rp_log_error(RP_LOG_ALERT, log, rp_socket_errno,
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

    rp_destroy_pool(pool);
}


static void
rp_http_log_request(rp_http_request_t *r)
{
    rp_uint_t                  i, n;
    rp_http_handler_pt        *log_handler;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    log_handler = cmcf->phases[RP_HTTP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[RP_HTTP_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


void
rp_http_close_connection(rp_connection_t *c)
{
    rp_pool_t  *pool;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (RP_HTTP_SSL)

    if (c->ssl) {
        if (rp_ssl_shutdown(c) == RP_AGAIN) {
            c->ssl->handler = rp_http_close_connection;
            return;
        }
    }

#endif

#if (RP_STAT_STUB)
    (void) rp_atomic_fetch_add(rp_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    rp_close_connection(c);

    rp_destroy_pool(pool);
}


static u_char *
rp_http_log_error(rp_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    rp_http_request_t  *r;
    rp_http_log_ctx_t  *ctx;

    if (log->action) {
        p = rp_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = rp_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->request;

    if (r) {
        return r->log_handler(r, ctx->current_request, p, len);

    } else {
        p = rp_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}


static u_char *
rp_http_log_error_handler(rp_http_request_t *r, rp_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    rp_http_upstream_t       *u;
    rp_http_core_srv_conf_t  *cscf;

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

    p = rp_snprintf(buf, len, ", server: %V", &cscf->server_name);
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
        p = rp_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = rp_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (RP_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = rp_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = rp_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = rp_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}

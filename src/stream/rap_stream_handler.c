
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_stream.h>


static void rap_stream_log_session(rap_stream_session_t *s);
static void rap_stream_close_connection(rap_connection_t *c);
static u_char *rap_stream_log_error(rap_log_t *log, u_char *buf, size_t len);
static void rap_stream_proxy_protocol_handler(rap_event_t *rev);


void
rap_stream_init_connection(rap_connection_t *c)
{
    u_char                        text[RAP_SOCKADDR_STRLEN];
    size_t                        len;
    rap_uint_t                    i;
    rap_time_t                   *tp;
    rap_event_t                  *rev;
    struct sockaddr              *sa;
    rap_stream_port_t            *port;
    struct sockaddr_in           *sin;
    rap_stream_in_addr_t         *addr;
    rap_stream_session_t         *s;
    rap_stream_addr_conf_t       *addr_conf;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6          *sin6;
    rap_stream_in6_addr_t        *addr6;
#endif
    rap_stream_core_srv_conf_t   *cscf;
    rap_stream_core_main_conf_t  *cmcf;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() and recvmsg() already gave this address.
         */

        if (rap_connection_local_sockaddr(c, NULL, 0) != RAP_OK) {
            rap_stream_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (rap_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = rap_pcalloc(c->pool, sizeof(rap_stream_session_t));
    if (s == NULL) {
        rap_stream_close_connection(c);
        return;
    }

    s->signature = RAP_STREAM_MODULE;
    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

#if (RAP_STREAM_SSL)
    s->ssl = addr_conf->ssl;
#endif

    if (c->buffer) {
        s->received += c->buffer->last - c->buffer->pos;
    }

    s->connection = c;
    c->data = s;

    cscf = rap_stream_get_module_srv_conf(s, rap_stream_core_module);

    rap_set_connection_log(c, cscf->error_log);

    len = rap_sock_ntop(c->sockaddr, c->socklen, text, RAP_SOCKADDR_STRLEN, 1);

    rap_log_error(RAP_LOG_INFO, c->log, 0, "*%uA %sclient %*s connected to %V",
                  c->number, c->type == SOCK_DGRAM ? "udp " : "",
                  len, text, &addr_conf->addr_text);

    c->log->connection = c->number;
    c->log->handler = rap_stream_log_error;
    c->log->data = s;
    c->log->action = "initializing session";
    c->log_error = RAP_ERROR_INFO;

    s->ctx = rap_pcalloc(c->pool, sizeof(void *) * rap_stream_max_module);
    if (s->ctx == NULL) {
        rap_stream_close_connection(c);
        return;
    }

    cmcf = rap_stream_get_module_main_conf(s, rap_stream_core_module);

    s->variables = rap_pcalloc(s->connection->pool,
                               cmcf->variables.nelts
                               * sizeof(rap_stream_variable_value_t));

    if (s->variables == NULL) {
        rap_stream_close_connection(c);
        return;
    }

    tp = rap_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    rev = c->read;
    rev->handler = rap_stream_session_handler;

    if (addr_conf->proxy_protocol) {
        c->log->action = "reading PROXY protocol";

        rev->handler = rap_stream_proxy_protocol_handler;

        if (!rev->ready) {
            rap_add_timer(rev, cscf->proxy_protocol_timeout);

            if (rap_handle_read_event(rev, 0) != RAP_OK) {
                rap_stream_finalize_session(s,
                                            RAP_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    if (rap_use_accept_mutex) {
        rap_post_event(rev, &rap_posted_events);
        return;
    }

    rev->handler(rev);
}


static void
rap_stream_proxy_protocol_handler(rap_event_t *rev)
{
    u_char                      *p, buf[RAP_PROXY_PROTOCOL_MAX_HEADER];
    size_t                       size;
    ssize_t                      n;
    rap_err_t                    err;
    rap_connection_t            *c;
    rap_stream_session_t        *s;
    rap_stream_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream PROXY protocol handler");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        rap_stream_finalize_session(s, RAP_STREAM_OK);
        return;
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = rap_socket_errno;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0, "recv(): %z", n);

    if (n == -1) {
        if (err == RAP_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = rap_stream_get_module_srv_conf(s,
                                                      rap_stream_core_module);

                rap_add_timer(rev, cscf->proxy_protocol_timeout);
            }

            if (rap_handle_read_event(rev, 0) != RAP_OK) {
                rap_stream_finalize_session(s,
                                            RAP_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }

        rap_connection_error(c, err, "recv() failed");

        rap_stream_finalize_session(s, RAP_STREAM_OK);
        return;
    }

    if (rev->timer_set) {
        rap_del_timer(rev);
    }

    p = rap_proxy_protocol_read(c, buf, buf + n);

    if (p == NULL) {
        rap_stream_finalize_session(s, RAP_STREAM_BAD_REQUEST);
        return;
    }

    size = p - buf;

    if (c->recv(c, buf, size) != (ssize_t) size) {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->log->action = "initializing session";

    rap_stream_session_handler(rev);
}


void
rap_stream_session_handler(rap_event_t *rev)
{
    rap_connection_t      *c;
    rap_stream_session_t  *s;

    c = rev->data;
    s = c->data;

    rap_stream_core_run_phases(s);
}


void
rap_stream_finalize_session(rap_stream_session_t *s, rap_uint_t rc)
{
    rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream session: %i", rc);

    s->status = rc;

    rap_stream_log_session(s);

    rap_stream_close_connection(s->connection);
}


static void
rap_stream_log_session(rap_stream_session_t *s)
{
    rap_uint_t                    i, n;
    rap_stream_handler_pt        *log_handler;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_get_module_main_conf(s, rap_stream_core_module);

    log_handler = cmcf->phases[RAP_STREAM_LOG_PHASE].handlers.elts;
    n = cmcf->phases[RAP_STREAM_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }
}


static void
rap_stream_close_connection(rap_connection_t *c)
{
    rap_pool_t  *pool;

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, c->log, 0,
                   "close stream connection: %d", c->fd);

#if (RAP_STREAM_SSL)

    if (c->ssl) {
        if (rap_ssl_shutdown(c) == RAP_AGAIN) {
            c->ssl->handler = rap_stream_close_connection;
            return;
        }
    }

#endif

#if (RAP_STAT_STUB)
    (void) rap_atomic_fetch_add(rap_stat_active, -1);
#endif

    pool = c->pool;

    rap_close_connection(c);

    rap_destroy_pool(pool);
}


static u_char *
rap_stream_log_error(rap_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    rap_stream_session_t  *s;

    if (log->action) {
        p = rap_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    p = rap_snprintf(buf, len, ", %sclient: %V, server: %V",
                     s->connection->type == SOCK_DGRAM ? "udp " : "",
                     &s->connection->addr_text,
                     &s->connection->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (s->log_handler) {
        p = s->log_handler(log, buf, len);
    }

    return p;
}

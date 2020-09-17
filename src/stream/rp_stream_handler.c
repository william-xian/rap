
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_stream.h>


static void rp_stream_log_session(rp_stream_session_t *s);
static void rp_stream_close_connection(rp_connection_t *c);
static u_char *rp_stream_log_error(rp_log_t *log, u_char *buf, size_t len);
static void rp_stream_proxy_protocol_handler(rp_event_t *rev);


void
rp_stream_init_connection(rp_connection_t *c)
{
    u_char                        text[RP_SOCKADDR_STRLEN];
    size_t                        len;
    rp_uint_t                    i;
    rp_time_t                   *tp;
    rp_event_t                  *rev;
    struct sockaddr              *sa;
    rp_stream_port_t            *port;
    struct sockaddr_in           *sin;
    rp_stream_in_addr_t         *addr;
    rp_stream_session_t         *s;
    rp_stream_addr_conf_t       *addr_conf;
#if (RP_HAVE_INET6)
    struct sockaddr_in6          *sin6;
    rp_stream_in6_addr_t        *addr6;
#endif
    rp_stream_core_srv_conf_t   *cscf;
    rp_stream_core_main_conf_t  *cmcf;

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

        if (rp_connection_local_sockaddr(c, NULL, 0) != RP_OK) {
            rp_stream_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (rp_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
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

#if (RP_HAVE_INET6)
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

    s = rp_pcalloc(c->pool, sizeof(rp_stream_session_t));
    if (s == NULL) {
        rp_stream_close_connection(c);
        return;
    }

    s->signature = RP_STREAM_MODULE;
    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

#if (RP_STREAM_SSL)
    s->ssl = addr_conf->ssl;
#endif

    if (c->buffer) {
        s->received += c->buffer->last - c->buffer->pos;
    }

    s->connection = c;
    c->data = s;

    cscf = rp_stream_get_module_srv_conf(s, rp_stream_core_module);

    rp_set_connection_log(c, cscf->error_log);

    len = rp_sock_ntop(c->sockaddr, c->socklen, text, RP_SOCKADDR_STRLEN, 1);

    rp_log_error(RP_LOG_INFO, c->log, 0, "*%uA %sclient %*s connected to %V",
                  c->number, c->type == SOCK_DGRAM ? "udp " : "",
                  len, text, &addr_conf->addr_text);

    c->log->connection = c->number;
    c->log->handler = rp_stream_log_error;
    c->log->data = s;
    c->log->action = "initializing session";
    c->log_error = RP_ERROR_INFO;

    s->ctx = rp_pcalloc(c->pool, sizeof(void *) * rp_stream_max_module);
    if (s->ctx == NULL) {
        rp_stream_close_connection(c);
        return;
    }

    cmcf = rp_stream_get_module_main_conf(s, rp_stream_core_module);

    s->variables = rp_pcalloc(s->connection->pool,
                               cmcf->variables.nelts
                               * sizeof(rp_stream_variable_value_t));

    if (s->variables == NULL) {
        rp_stream_close_connection(c);
        return;
    }

    tp = rp_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    rev = c->read;
    rev->handler = rp_stream_session_handler;

    if (addr_conf->proxy_protocol) {
        c->log->action = "reading PROXY protocol";

        rev->handler = rp_stream_proxy_protocol_handler;

        if (!rev->ready) {
            rp_add_timer(rev, cscf->proxy_protocol_timeout);

            if (rp_handle_read_event(rev, 0) != RP_OK) {
                rp_stream_finalize_session(s,
                                            RP_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    if (rp_use_accept_mutex) {
        rp_post_event(rev, &rp_posted_events);
        return;
    }

    rev->handler(rev);
}


static void
rp_stream_proxy_protocol_handler(rp_event_t *rev)
{
    u_char                      *p, buf[RP_PROXY_PROTOCOL_MAX_HEADER];
    size_t                       size;
    ssize_t                      n;
    rp_err_t                    err;
    rp_connection_t            *c;
    rp_stream_session_t        *s;
    rp_stream_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    rp_log_debug0(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "stream PROXY protocol handler");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        rp_stream_finalize_session(s, RP_STREAM_OK);
        return;
    }

    n = recv(c->fd, (char *) buf, sizeof(buf), MSG_PEEK);

    err = rp_socket_errno;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0, "recv(): %z", n);

    if (n == -1) {
        if (err == RP_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                cscf = rp_stream_get_module_srv_conf(s,
                                                      rp_stream_core_module);

                rp_add_timer(rev, cscf->proxy_protocol_timeout);
            }

            if (rp_handle_read_event(rev, 0) != RP_OK) {
                rp_stream_finalize_session(s,
                                            RP_STREAM_INTERNAL_SERVER_ERROR);
            }

            return;
        }

        rp_connection_error(c, err, "recv() failed");

        rp_stream_finalize_session(s, RP_STREAM_OK);
        return;
    }

    if (rev->timer_set) {
        rp_del_timer(rev);
    }

    p = rp_proxy_protocol_read(c, buf, buf + n);

    if (p == NULL) {
        rp_stream_finalize_session(s, RP_STREAM_BAD_REQUEST);
        return;
    }

    size = p - buf;

    if (c->recv(c, buf, size) != (ssize_t) size) {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->log->action = "initializing session";

    rp_stream_session_handler(rev);
}


void
rp_stream_session_handler(rp_event_t *rev)
{
    rp_connection_t      *c;
    rp_stream_session_t  *s;

    c = rev->data;
    s = c->data;

    rp_stream_core_run_phases(s);
}


void
rp_stream_finalize_session(rp_stream_session_t *s, rp_uint_t rc)
{
    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream session: %i", rc);

    s->status = rc;

    rp_stream_log_session(s);

    rp_stream_close_connection(s->connection);
}


static void
rp_stream_log_session(rp_stream_session_t *s)
{
    rp_uint_t                    i, n;
    rp_stream_handler_pt        *log_handler;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_get_module_main_conf(s, rp_stream_core_module);

    log_handler = cmcf->phases[RP_STREAM_LOG_PHASE].handlers.elts;
    n = cmcf->phases[RP_STREAM_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }
}


static void
rp_stream_close_connection(rp_connection_t *c)
{
    rp_pool_t  *pool;

    rp_log_debug1(RP_LOG_DEBUG_STREAM, c->log, 0,
                   "close stream connection: %d", c->fd);

#if (RP_STREAM_SSL)

    if (c->ssl) {
        if (rp_ssl_shutdown(c) == RP_AGAIN) {
            c->ssl->handler = rp_stream_close_connection;
            return;
        }
    }

#endif

#if (RP_STAT_STUB)
    (void) rp_atomic_fetch_add(rp_stat_active, -1);
#endif

    pool = c->pool;

    rp_close_connection(c);

    rp_destroy_pool(pool);
}


static u_char *
rp_stream_log_error(rp_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    rp_stream_session_t  *s;

    if (log->action) {
        p = rp_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    p = rp_snprintf(buf, len, ", %sclient: %V, server: %V",
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

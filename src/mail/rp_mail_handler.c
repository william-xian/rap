
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>


static void rp_mail_init_session(rp_connection_t *c);

#if (RP_MAIL_SSL)
static void rp_mail_ssl_init_connection(rp_ssl_t *ssl, rp_connection_t *c);
static void rp_mail_ssl_handshake_handler(rp_connection_t *c);
static rp_int_t rp_mail_verify_cert(rp_mail_session_t *s,
    rp_connection_t *c);
#endif


void
rp_mail_init_connection(rp_connection_t *c)
{
    size_t                     len;
    rp_uint_t                 i;
    rp_mail_port_t           *port;
    struct sockaddr           *sa;
    struct sockaddr_in        *sin;
    rp_mail_log_ctx_t        *ctx;
    rp_mail_in_addr_t        *addr;
    rp_mail_session_t        *s;
    rp_mail_addr_conf_t      *addr_conf;
    rp_mail_core_srv_conf_t  *cscf;
    u_char                     text[RP_SOCKADDR_STRLEN];
#if (RP_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    rp_mail_in6_addr_t       *addr6;
#endif


    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (rp_connection_local_sockaddr(c, NULL, 0) != RP_OK) {
            rp_mail_close_connection(c);
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

    s = rp_pcalloc(c->pool, sizeof(rp_mail_session_t));
    if (s == NULL) {
        rp_mail_close_connection(c);
        return;
    }

    s->signature = RP_MAIL_MODULE;

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    rp_set_connection_log(c, cscf->error_log);

    len = rp_sock_ntop(c->sockaddr, c->socklen, text, RP_SOCKADDR_STRLEN, 1);

    rp_log_error(RP_LOG_INFO, c->log, 0, "*%uA client %*s connected to %V",
                  c->number, len, text, s->addr_text);

    ctx = rp_palloc(c->pool, sizeof(rp_mail_log_ctx_t));
    if (ctx == NULL) {
        rp_mail_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = rp_mail_log_error;
    c->log->data = ctx;
    c->log->action = "sending client greeting line";

    c->log_error = RP_ERROR_INFO;

#if (RP_MAIL_SSL)
    {
    rp_mail_ssl_conf_t  *sslcf;

    sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

    if (sslcf->enable || addr_conf->ssl) {
        c->log->action = "SSL handshaking";

        rp_mail_ssl_init_connection(&sslcf->ssl, c);
        return;
    }

    }
#endif

    rp_mail_init_session(c);
}


#if (RP_MAIL_SSL)

void
rp_mail_starttls_handler(rp_event_t *rev)
{
    rp_connection_t     *c;
    rp_mail_session_t   *s;
    rp_mail_ssl_conf_t  *sslcf;

    c = rev->data;
    s = c->data;
    s->starttls = 1;

    c->log->action = "in starttls state";

    sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

    rp_mail_ssl_init_connection(&sslcf->ssl, c);
}


static void
rp_mail_ssl_init_connection(rp_ssl_t *ssl, rp_connection_t *c)
{
    rp_mail_session_t        *s;
    rp_mail_core_srv_conf_t  *cscf;

    if (rp_ssl_create_connection(ssl, c, 0) != RP_OK) {
        rp_mail_close_connection(c);
        return;
    }

    if (rp_ssl_handshake(c) == RP_AGAIN) {

        s = c->data;

        cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

        rp_add_timer(c->read, cscf->timeout);

        c->ssl->handler = rp_mail_ssl_handshake_handler;

        return;
    }

    rp_mail_ssl_handshake_handler(c);
}


static void
rp_mail_ssl_handshake_handler(rp_connection_t *c)
{
    rp_mail_session_t        *s;
    rp_mail_core_srv_conf_t  *cscf;

    if (c->ssl->handshaked) {

        s = c->data;

        if (rp_mail_verify_cert(s, c) != RP_OK) {
            return;
        }

        if (s->starttls) {
            cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

            c->read->handler = cscf->protocol->init_protocol;
            c->write->handler = rp_mail_send;

            cscf->protocol->init_protocol(c->read);

            return;
        }

        c->read->ready = 0;

        rp_mail_init_session(c);
        return;
    }

    rp_mail_close_connection(c);
}


static rp_int_t
rp_mail_verify_cert(rp_mail_session_t *s, rp_connection_t *c)
{
    long                       rc;
    X509                      *cert;
    rp_mail_ssl_conf_t       *sslcf;
    rp_mail_core_srv_conf_t  *cscf;

    sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

    if (!sslcf->verify) {
        return RP_OK;
    }

    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc != X509_V_OK
        && (sslcf->verify != 3 || !rp_ssl_verify_error_optional(rc)))
    {
        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "client SSL certificate verify error: (%l:%s)",
                      rc, X509_verify_cert_error_string(rc));

        rp_ssl_remove_cached_session(c->ssl->session_ctx,
                                      (SSL_get0_session(c->ssl->connection)));

        cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

        s->out = cscf->protocol->cert_error;
        s->quit = 1;

        c->write->handler = rp_mail_send;

        rp_mail_send(s->connection->write);
        return RP_ERROR;
    }

    if (sslcf->verify == 1) {
        cert = SSL_get_peer_certificate(c->ssl->connection);

        if (cert == NULL) {
            rp_log_error(RP_LOG_INFO, c->log, 0,
                          "client sent no required SSL certificate");

            rp_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

            cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

            s->out = cscf->protocol->no_cert;
            s->quit = 1;

            c->write->handler = rp_mail_send;

            rp_mail_send(s->connection->write);
            return RP_ERROR;
        }

        X509_free(cert);
    }

    return RP_OK;
}

#endif


static void
rp_mail_init_session(rp_connection_t *c)
{
    rp_mail_session_t        *s;
    rp_mail_core_srv_conf_t  *cscf;

    s = c->data;

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    s->protocol = cscf->protocol->type;

    s->ctx = rp_pcalloc(c->pool, sizeof(void *) * rp_mail_max_module);
    if (s->ctx == NULL) {
        rp_mail_session_internal_server_error(s);
        return;
    }

    c->write->handler = rp_mail_send;

    cscf->protocol->init_session(s, c);
}


rp_int_t
rp_mail_salt(rp_mail_session_t *s, rp_connection_t *c,
    rp_mail_core_srv_conf_t *cscf)
{
    s->salt.data = rp_pnalloc(c->pool,
                               sizeof(" <18446744073709551616.@>" CRLF) - 1
                               + RP_TIME_T_LEN
                               + cscf->server_name.len);
    if (s->salt.data == NULL) {
        return RP_ERROR;
    }

    s->salt.len = rp_sprintf(s->salt.data, "<%ul.%T@%V>" CRLF,
                              rp_random(), rp_time(), &cscf->server_name)
                  - s->salt.data;

    return RP_OK;
}


#if (RP_MAIL_SSL)

rp_int_t
rp_mail_starttls_only(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_mail_ssl_conf_t  *sslcf;

    if (c->ssl) {
        return 0;
    }

    sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

    if (sslcf->starttls == RP_MAIL_STARTTLS_ONLY) {
        return 1;
    }

    return 0;
}

#endif


rp_int_t
rp_mail_auth_plain(rp_mail_session_t *s, rp_connection_t *c, rp_uint_t n)
{
    u_char     *p, *last;
    rp_str_t  *arg, plain;

    arg = s->args.elts;

#if (RP_DEBUG_MAIL_PASSWD)
    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\"", &arg[n]);
#endif

    plain.data = rp_pnalloc(c->pool, rp_base64_decoded_length(arg[n].len));
    if (plain.data == NULL) {
        return RP_ERROR;
    }

    if (rp_decode_base64(&plain, &arg[n]) != RP_OK) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH PLAIN command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    p = plain.data;
    last = p + plain.len;

    while (p < last && *p++) { /* void */ }

    if (p == last) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "client sent invalid login in AUTH PLAIN command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.data = p;

    while (p < last && *p) { p++; }

    if (p == last) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "client sent invalid password in AUTH PLAIN command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = p++ - s->login.data;

    s->passwd.len = last - p;
    s->passwd.data = p;

#if (RP_DEBUG_MAIL_PASSWD)
    rp_log_debug2(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\" \"%V\"", &s->login, &s->passwd);
#endif

    return RP_DONE;
}


rp_int_t
rp_mail_auth_login_username(rp_mail_session_t *s, rp_connection_t *c,
    rp_uint_t n)
{
    rp_str_t  *arg;

    arg = s->args.elts;

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &arg[n]);

    s->login.data = rp_pnalloc(c->pool, rp_base64_decoded_length(arg[n].len));
    if (s->login.data == NULL) {
        return RP_ERROR;
    }

    if (rp_decode_base64(&s->login, &arg[n]) != RP_OK) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &s->login);

    return RP_OK;
}


rp_int_t
rp_mail_auth_login_password(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t  *arg;

    arg = s->args.elts;

#if (RP_DEBUG_MAIL_PASSWD)
    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &arg[0]);
#endif

    s->passwd.data = rp_pnalloc(c->pool,
                                 rp_base64_decoded_length(arg[0].len));
    if (s->passwd.data == NULL) {
        return RP_ERROR;
    }

    if (rp_decode_base64(&s->passwd, &arg[0]) != RP_OK) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

#if (RP_DEBUG_MAIL_PASSWD)
    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &s->passwd);
#endif

    return RP_DONE;
}


rp_int_t
rp_mail_auth_cram_md5_salt(rp_mail_session_t *s, rp_connection_t *c,
    char *prefix, size_t len)
{
    u_char      *p;
    rp_str_t    salt;
    rp_uint_t   n;

    p = rp_pnalloc(c->pool, len + rp_base64_encoded_length(s->salt.len) + 2);
    if (p == NULL) {
        return RP_ERROR;
    }

    salt.data = rp_cpymem(p, prefix, len);
    s->salt.len -= 2;

    rp_encode_base64(&salt, &s->salt);

    s->salt.len += 2;
    n = len + salt.len;
    p[n++] = CR; p[n++] = LF;

    s->out.len = n;
    s->out.data = p;

    return RP_OK;
}


rp_int_t
rp_mail_auth_cram_md5(rp_mail_session_t *s, rp_connection_t *c)
{
    u_char     *p, *last;
    rp_str_t  *arg;

    arg = s->args.elts;

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\"", &arg[0]);

    s->login.data = rp_pnalloc(c->pool, rp_base64_decoded_length(arg[0].len));
    if (s->login.data == NULL) {
        return RP_ERROR;
    }

    if (rp_decode_base64(&s->login, &arg[0]) != RP_OK) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH CRAM-MD5 command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    p = s->login.data;
    last = p + s->login.len;

    while (p < last) {
        if (*p++ == ' ') {
            s->login.len = p - s->login.data - 1;
            s->passwd.len = last - p;
            s->passwd.data = p;
            break;
        }
    }

    if (s->passwd.len != 32) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
            "client sent invalid CRAM-MD5 hash in AUTH CRAM-MD5 command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    rp_log_debug2(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = RP_MAIL_AUTH_CRAM_MD5;

    return RP_DONE;
}


rp_int_t
rp_mail_auth_external(rp_mail_session_t *s, rp_connection_t *c,
    rp_uint_t n)
{
    rp_str_t  *arg, external;

    arg = s->args.elts;

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &arg[n]);

    external.data = rp_pnalloc(c->pool, rp_base64_decoded_length(arg[n].len));
    if (external.data == NULL) {
        return RP_ERROR;
    }

    if (rp_decode_base64(&external, &arg[n]) != RP_OK) {
        rp_log_error(RP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH EXTERNAL command");
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = external.len;
    s->login.data = external.data;

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &s->login);

    s->auth_method = RP_MAIL_AUTH_EXTERNAL;

    return RP_DONE;
}


void
rp_mail_send(rp_event_t *wev)
{
    rp_int_t                  n;
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_mail_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rp_mail_close_connection(c);
        return;
    }

    if (s->out.len == 0) {
        if (rp_handle_write_event(c->write, 0) != RP_OK) {
            rp_mail_close_connection(c);
        }

        return;
    }

    n = c->send(c, s->out.data, s->out.len);

    if (n > 0) {
        s->out.data += n;
        s->out.len -= n;

        if (s->out.len != 0) {
            goto again;
        }

        if (wev->timer_set) {
            rp_del_timer(wev);
        }

        if (s->quit) {
            rp_mail_close_connection(c);
            return;
        }

        if (s->blocked) {
            c->read->handler(c->read);
        }

        return;
    }

    if (n == RP_ERROR) {
        rp_mail_close_connection(c);
        return;
    }

    /* n == RP_AGAIN */

again:

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    rp_add_timer(c->write, cscf->timeout);

    if (rp_handle_write_event(c->write, 0) != RP_OK) {
        rp_mail_close_connection(c);
        return;
    }
}


rp_int_t
rp_mail_read_command(rp_mail_session_t *s, rp_connection_t *c)
{
    ssize_t                    n;
    rp_int_t                  rc;
    rp_str_t                  l;
    rp_mail_core_srv_conf_t  *cscf;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == RP_ERROR || n == 0) {
        rp_mail_close_connection(c);
        return RP_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == RP_AGAIN) {
        if (rp_handle_read_event(c->read, 0) != RP_OK) {
            rp_mail_session_internal_server_error(s);
            return RP_ERROR;
        }

        if (s->buffer->pos == s->buffer->last) {
            return RP_AGAIN;
        }
    }

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    rc = cscf->protocol->parse_command(s);

    if (rc == RP_AGAIN) {

        if (s->buffer->last < s->buffer->end) {
            return rc;
        }

        l.len = s->buffer->last - s->buffer->start;
        l.data = s->buffer->start;

        rp_log_error(RP_LOG_INFO, c->log, 0,
                      "client sent too long command \"%V\"", &l);

        s->quit = 1;

        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    if (rc == RP_IMAP_NEXT || rc == RP_MAIL_PARSE_INVALID_COMMAND) {
        return rc;
    }

    if (rc == RP_ERROR) {
        rp_mail_close_connection(c);
        return RP_ERROR;
    }

    return RP_OK;
}


void
rp_mail_auth(rp_mail_session_t *s, rp_connection_t *c)
{
    s->args.nelts = 0;

    if (s->buffer->pos == s->buffer->last) {
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;
    }

    s->state = 0;

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

    s->login_attempt++;

    rp_mail_auth_http_init(s);
}


void
rp_mail_session_internal_server_error(rp_mail_session_t *s)
{
    rp_mail_core_srv_conf_t  *cscf;

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    s->out = cscf->protocol->internal_server_error;
    s->quit = 1;

    rp_mail_send(s->connection->write);
}


void
rp_mail_close_connection(rp_connection_t *c)
{
    rp_pool_t  *pool;

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "close mail connection: %d", c->fd);

#if (RP_MAIL_SSL)

    if (c->ssl) {
        if (rp_ssl_shutdown(c) == RP_AGAIN) {
            c->ssl->handler = rp_mail_close_connection;
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


u_char *
rp_mail_log_error(rp_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    rp_mail_session_t  *s;
    rp_mail_log_ctx_t  *ctx;

    if (log->action) {
        p = rp_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = rp_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = rp_snprintf(buf, len, "%s, server: %V",
                     s->starttls ? " using starttls" : "",
                     s->addr_text);
    len -= p - buf;
    buf = p;

    if (s->login.len == 0) {
        return p;
    }

    p = rp_snprintf(buf, len, ", login: \"%V\"", &s->login);
    len -= p - buf;
    buf = p;

    if (s->proxy == NULL) {
        return p;
    }

    p = rp_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    return p;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>


static void rap_mail_init_session(rap_connection_t *c);

#if (RAP_MAIL_SSL)
static void rap_mail_ssl_init_connection(rap_ssl_t *ssl, rap_connection_t *c);
static void rap_mail_ssl_handshake_handler(rap_connection_t *c);
static rap_int_t rap_mail_verify_cert(rap_mail_session_t *s,
    rap_connection_t *c);
#endif


void
rap_mail_init_connection(rap_connection_t *c)
{
    size_t                     len;
    rap_uint_t                 i;
    rap_mail_port_t           *port;
    struct sockaddr           *sa;
    struct sockaddr_in        *sin;
    rap_mail_log_ctx_t        *ctx;
    rap_mail_in_addr_t        *addr;
    rap_mail_session_t        *s;
    rap_mail_addr_conf_t      *addr_conf;
    rap_mail_core_srv_conf_t  *cscf;
    u_char                     text[RAP_SOCKADDR_STRLEN];
#if (RAP_HAVE_INET6)
    struct sockaddr_in6       *sin6;
    rap_mail_in6_addr_t       *addr6;
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

        if (rap_connection_local_sockaddr(c, NULL, 0) != RAP_OK) {
            rap_mail_close_connection(c);
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

    s = rap_pcalloc(c->pool, sizeof(rap_mail_session_t));
    if (s == NULL) {
        rap_mail_close_connection(c);
        return;
    }

    s->signature = RAP_MAIL_MODULE;

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    rap_set_connection_log(c, cscf->error_log);

    len = rap_sock_ntop(c->sockaddr, c->socklen, text, RAP_SOCKADDR_STRLEN, 1);

    rap_log_error(RAP_LOG_INFO, c->log, 0, "*%uA client %*s connected to %V",
                  c->number, len, text, s->addr_text);

    ctx = rap_palloc(c->pool, sizeof(rap_mail_log_ctx_t));
    if (ctx == NULL) {
        rap_mail_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = rap_mail_log_error;
    c->log->data = ctx;
    c->log->action = "sending client greeting line";

    c->log_error = RAP_ERROR_INFO;

#if (RAP_MAIL_SSL)
    {
    rap_mail_ssl_conf_t  *sslcf;

    sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

    if (sslcf->enable || addr_conf->ssl) {
        c->log->action = "SSL handshaking";

        rap_mail_ssl_init_connection(&sslcf->ssl, c);
        return;
    }

    }
#endif

    rap_mail_init_session(c);
}


#if (RAP_MAIL_SSL)

void
rap_mail_starttls_handler(rap_event_t *rev)
{
    rap_connection_t     *c;
    rap_mail_session_t   *s;
    rap_mail_ssl_conf_t  *sslcf;

    c = rev->data;
    s = c->data;
    s->starttls = 1;

    c->log->action = "in starttls state";

    sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

    rap_mail_ssl_init_connection(&sslcf->ssl, c);
}


static void
rap_mail_ssl_init_connection(rap_ssl_t *ssl, rap_connection_t *c)
{
    rap_mail_session_t        *s;
    rap_mail_core_srv_conf_t  *cscf;

    if (rap_ssl_create_connection(ssl, c, 0) != RAP_OK) {
        rap_mail_close_connection(c);
        return;
    }

    if (rap_ssl_handshake(c) == RAP_AGAIN) {

        s = c->data;

        cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

        rap_add_timer(c->read, cscf->timeout);

        c->ssl->handler = rap_mail_ssl_handshake_handler;

        return;
    }

    rap_mail_ssl_handshake_handler(c);
}


static void
rap_mail_ssl_handshake_handler(rap_connection_t *c)
{
    rap_mail_session_t        *s;
    rap_mail_core_srv_conf_t  *cscf;

    if (c->ssl->handshaked) {

        s = c->data;

        if (rap_mail_verify_cert(s, c) != RAP_OK) {
            return;
        }

        if (s->starttls) {
            cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

            c->read->handler = cscf->protocol->init_protocol;
            c->write->handler = rap_mail_send;

            cscf->protocol->init_protocol(c->read);

            return;
        }

        c->read->ready = 0;

        rap_mail_init_session(c);
        return;
    }

    rap_mail_close_connection(c);
}


static rap_int_t
rap_mail_verify_cert(rap_mail_session_t *s, rap_connection_t *c)
{
    long                       rc;
    X509                      *cert;
    rap_mail_ssl_conf_t       *sslcf;
    rap_mail_core_srv_conf_t  *cscf;

    sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

    if (!sslcf->verify) {
        return RAP_OK;
    }

    rc = SSL_get_verify_result(c->ssl->connection);

    if (rc != X509_V_OK
        && (sslcf->verify != 3 || !rap_ssl_verify_error_optional(rc)))
    {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "client SSL certificate verify error: (%l:%s)",
                      rc, X509_verify_cert_error_string(rc));

        rap_ssl_remove_cached_session(c->ssl->session_ctx,
                                      (SSL_get0_session(c->ssl->connection)));

        cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

        s->out = cscf->protocol->cert_error;
        s->quit = 1;

        c->write->handler = rap_mail_send;

        rap_mail_send(s->connection->write);
        return RAP_ERROR;
    }

    if (sslcf->verify == 1) {
        cert = SSL_get_peer_certificate(c->ssl->connection);

        if (cert == NULL) {
            rap_log_error(RAP_LOG_INFO, c->log, 0,
                          "client sent no required SSL certificate");

            rap_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

            cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

            s->out = cscf->protocol->no_cert;
            s->quit = 1;

            c->write->handler = rap_mail_send;

            rap_mail_send(s->connection->write);
            return RAP_ERROR;
        }

        X509_free(cert);
    }

    return RAP_OK;
}

#endif


static void
rap_mail_init_session(rap_connection_t *c)
{
    rap_mail_session_t        *s;
    rap_mail_core_srv_conf_t  *cscf;

    s = c->data;

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    s->protocol = cscf->protocol->type;

    s->ctx = rap_pcalloc(c->pool, sizeof(void *) * rap_mail_max_module);
    if (s->ctx == NULL) {
        rap_mail_session_internal_server_error(s);
        return;
    }

    c->write->handler = rap_mail_send;

    cscf->protocol->init_session(s, c);
}


rap_int_t
rap_mail_salt(rap_mail_session_t *s, rap_connection_t *c,
    rap_mail_core_srv_conf_t *cscf)
{
    s->salt.data = rap_pnalloc(c->pool,
                               sizeof(" <18446744073709551616.@>" CRLF) - 1
                               + RAP_TIME_T_LEN
                               + cscf->server_name.len);
    if (s->salt.data == NULL) {
        return RAP_ERROR;
    }

    s->salt.len = rap_sprintf(s->salt.data, "<%ul.%T@%V>" CRLF,
                              rap_random(), rap_time(), &cscf->server_name)
                  - s->salt.data;

    return RAP_OK;
}


#if (RAP_MAIL_SSL)

rap_int_t
rap_mail_starttls_only(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_mail_ssl_conf_t  *sslcf;

    if (c->ssl) {
        return 0;
    }

    sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

    if (sslcf->starttls == RAP_MAIL_STARTTLS_ONLY) {
        return 1;
    }

    return 0;
}

#endif


rap_int_t
rap_mail_auth_plain(rap_mail_session_t *s, rap_connection_t *c, rap_uint_t n)
{
    u_char     *p, *last;
    rap_str_t  *arg, plain;

    arg = s->args.elts;

#if (RAP_DEBUG_MAIL_PASSWD)
    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\"", &arg[n]);
#endif

    plain.data = rap_pnalloc(c->pool, rap_base64_decoded_length(arg[n].len));
    if (plain.data == NULL) {
        return RAP_ERROR;
    }

    if (rap_decode_base64(&plain, &arg[n]) != RAP_OK) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH PLAIN command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    p = plain.data;
    last = p + plain.len;

    while (p < last && *p++) { /* void */ }

    if (p == last) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "client sent invalid login in AUTH PLAIN command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.data = p;

    while (p < last && *p) { p++; }

    if (p == last) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "client sent invalid password in AUTH PLAIN command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = p++ - s->login.data;

    s->passwd.len = last - p;
    s->passwd.data = p;

#if (RAP_DEBUG_MAIL_PASSWD)
    rap_log_debug2(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth plain: \"%V\" \"%V\"", &s->login, &s->passwd);
#endif

    return RAP_DONE;
}


rap_int_t
rap_mail_auth_login_username(rap_mail_session_t *s, rap_connection_t *c,
    rap_uint_t n)
{
    rap_str_t  *arg;

    arg = s->args.elts;

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &arg[n]);

    s->login.data = rap_pnalloc(c->pool, rap_base64_decoded_length(arg[n].len));
    if (s->login.data == NULL) {
        return RAP_ERROR;
    }

    if (rap_decode_base64(&s->login, &arg[n]) != RAP_OK) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login username: \"%V\"", &s->login);

    return RAP_OK;
}


rap_int_t
rap_mail_auth_login_password(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t  *arg;

    arg = s->args.elts;

#if (RAP_DEBUG_MAIL_PASSWD)
    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &arg[0]);
#endif

    s->passwd.data = rap_pnalloc(c->pool,
                                 rap_base64_decoded_length(arg[0].len));
    if (s->passwd.data == NULL) {
        return RAP_ERROR;
    }

    if (rap_decode_base64(&s->passwd, &arg[0]) != RAP_OK) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH LOGIN command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

#if (RAP_DEBUG_MAIL_PASSWD)
    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth login password: \"%V\"", &s->passwd);
#endif

    return RAP_DONE;
}


rap_int_t
rap_mail_auth_cram_md5_salt(rap_mail_session_t *s, rap_connection_t *c,
    char *prefix, size_t len)
{
    u_char      *p;
    rap_str_t    salt;
    rap_uint_t   n;

    p = rap_pnalloc(c->pool, len + rap_base64_encoded_length(s->salt.len) + 2);
    if (p == NULL) {
        return RAP_ERROR;
    }

    salt.data = rap_cpymem(p, prefix, len);
    s->salt.len -= 2;

    rap_encode_base64(&salt, &s->salt);

    s->salt.len += 2;
    n = len + salt.len;
    p[n++] = CR; p[n++] = LF;

    s->out.len = n;
    s->out.data = p;

    return RAP_OK;
}


rap_int_t
rap_mail_auth_cram_md5(rap_mail_session_t *s, rap_connection_t *c)
{
    u_char     *p, *last;
    rap_str_t  *arg;

    arg = s->args.elts;

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\"", &arg[0]);

    s->login.data = rap_pnalloc(c->pool, rap_base64_decoded_length(arg[0].len));
    if (s->login.data == NULL) {
        return RAP_ERROR;
    }

    if (rap_decode_base64(&s->login, &arg[0]) != RAP_OK) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH CRAM-MD5 command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
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
        rap_log_error(RAP_LOG_INFO, c->log, 0,
            "client sent invalid CRAM-MD5 hash in AUTH CRAM-MD5 command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    rap_log_debug2(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth cram-md5: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = RAP_MAIL_AUTH_CRAM_MD5;

    return RAP_DONE;
}


rap_int_t
rap_mail_auth_external(rap_mail_session_t *s, rap_connection_t *c,
    rap_uint_t n)
{
    rap_str_t  *arg, external;

    arg = s->args.elts;

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &arg[n]);

    external.data = rap_pnalloc(c->pool, rap_base64_decoded_length(arg[n].len));
    if (external.data == NULL) {
        return RAP_ERROR;
    }

    if (rap_decode_base64(&external, &arg[n]) != RAP_OK) {
        rap_log_error(RAP_LOG_INFO, c->log, 0,
            "client sent invalid base64 encoding in AUTH EXTERNAL command");
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = external.len;
    s->login.data = external.data;

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "mail auth external: \"%V\"", &s->login);

    s->auth_method = RAP_MAIL_AUTH_EXTERNAL;

    return RAP_DONE;
}


void
rap_mail_send(rap_event_t *wev)
{
    rap_int_t                  n;
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_mail_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rap_mail_close_connection(c);
        return;
    }

    if (s->out.len == 0) {
        if (rap_handle_write_event(c->write, 0) != RAP_OK) {
            rap_mail_close_connection(c);
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
            rap_del_timer(wev);
        }

        if (s->quit) {
            rap_mail_close_connection(c);
            return;
        }

        if (s->blocked) {
            c->read->handler(c->read);
        }

        return;
    }

    if (n == RAP_ERROR) {
        rap_mail_close_connection(c);
        return;
    }

    /* n == RAP_AGAIN */

again:

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    rap_add_timer(c->write, cscf->timeout);

    if (rap_handle_write_event(c->write, 0) != RAP_OK) {
        rap_mail_close_connection(c);
        return;
    }
}


rap_int_t
rap_mail_read_command(rap_mail_session_t *s, rap_connection_t *c)
{
    ssize_t                    n;
    rap_int_t                  rc;
    rap_str_t                  l;
    rap_mail_core_srv_conf_t  *cscf;

    n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

    if (n == RAP_ERROR || n == 0) {
        rap_mail_close_connection(c);
        return RAP_ERROR;
    }

    if (n > 0) {
        s->buffer->last += n;
    }

    if (n == RAP_AGAIN) {
        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            rap_mail_session_internal_server_error(s);
            return RAP_ERROR;
        }

        if (s->buffer->pos == s->buffer->last) {
            return RAP_AGAIN;
        }
    }

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    rc = cscf->protocol->parse_command(s);

    if (rc == RAP_AGAIN) {

        if (s->buffer->last < s->buffer->end) {
            return rc;
        }

        l.len = s->buffer->last - s->buffer->start;
        l.data = s->buffer->start;

        rap_log_error(RAP_LOG_INFO, c->log, 0,
                      "client sent too long command \"%V\"", &l);

        s->quit = 1;

        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    if (rc == RAP_IMAP_NEXT || rc == RAP_MAIL_PARSE_INVALID_COMMAND) {
        return rc;
    }

    if (rc == RAP_ERROR) {
        rap_mail_close_connection(c);
        return RAP_ERROR;
    }

    return RAP_OK;
}


void
rap_mail_auth(rap_mail_session_t *s, rap_connection_t *c)
{
    s->args.nelts = 0;

    if (s->buffer->pos == s->buffer->last) {
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;
    }

    s->state = 0;

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

    s->login_attempt++;

    rap_mail_auth_http_init(s);
}


void
rap_mail_session_internal_server_error(rap_mail_session_t *s)
{
    rap_mail_core_srv_conf_t  *cscf;

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    s->out = cscf->protocol->internal_server_error;
    s->quit = 1;

    rap_mail_send(s->connection->write);
}


void
rap_mail_close_connection(rap_connection_t *c)
{
    rap_pool_t  *pool;

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "close mail connection: %d", c->fd);

#if (RAP_MAIL_SSL)

    if (c->ssl) {
        if (rap_ssl_shutdown(c) == RAP_AGAIN) {
            c->ssl->handler = rap_mail_close_connection;
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


u_char *
rap_mail_log_error(rap_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    rap_mail_session_t  *s;
    rap_mail_log_ctx_t  *ctx;

    if (log->action) {
        p = rap_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = rap_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = rap_snprintf(buf, len, "%s, server: %V",
                     s->starttls ? " using starttls" : "",
                     s->addr_text);
    len -= p - buf;
    buf = p;

    if (s->login.len == 0) {
        return p;
    }

    p = rap_snprintf(buf, len, ", login: \"%V\"", &s->login);
    len -= p - buf;
    buf = p;

    if (s->proxy == NULL) {
        return p;
    }

    p = rap_snprintf(buf, len, ", upstream: %V", s->proxy->upstream.name);

    return p;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>
#include <rp_mail_smtp_module.h>


static void rp_mail_smtp_resolve_addr_handler(rp_resolver_ctx_t *ctx);
static void rp_mail_smtp_resolve_name(rp_event_t *rev);
static void rp_mail_smtp_resolve_name_handler(rp_resolver_ctx_t *ctx);
static void rp_mail_smtp_block_reading(rp_event_t *rev);
static void rp_mail_smtp_greeting(rp_mail_session_t *s, rp_connection_t *c);
static void rp_mail_smtp_invalid_pipelining(rp_event_t *rev);
static rp_int_t rp_mail_smtp_create_buffer(rp_mail_session_t *s,
    rp_connection_t *c);

static rp_int_t rp_mail_smtp_helo(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_smtp_auth(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_smtp_mail(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_smtp_starttls(rp_mail_session_t *s,
    rp_connection_t *c);
static rp_int_t rp_mail_smtp_rset(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_smtp_rcpt(rp_mail_session_t *s, rp_connection_t *c);

static rp_int_t rp_mail_smtp_discard_command(rp_mail_session_t *s,
    rp_connection_t *c, char *err);
static void rp_mail_smtp_log_rejected_command(rp_mail_session_t *s,
    rp_connection_t *c, char *err);


static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char  smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
static u_char  smtp_next[] = "334 " CRLF;
static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
static u_char  smtp_invalid_pipelining[] =
    "503 5.5.0 Improper use of SMTP command pipelining" CRLF;
static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;
static u_char  smtp_bad_sequence[] = "503 5.5.1 Bad sequence of commands" CRLF;


static rp_str_t  smtp_unavailable = rp_string("[UNAVAILABLE]");
static rp_str_t  smtp_tempunavail = rp_string("[TEMPUNAVAIL]");


void
rp_mail_smtp_init_session(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_resolver_ctx_t        *ctx;
    rp_mail_core_srv_conf_t  *cscf;

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    if (cscf->resolver == NULL) {
        s->host = smtp_unavailable;
        rp_mail_smtp_greeting(s, c);
        return;
    }

#if (RP_HAVE_UNIX_DOMAIN)
    if (c->sockaddr->sa_family == AF_UNIX) {
        s->host = smtp_tempunavail;
        rp_mail_smtp_greeting(s, c);
        return;
    }
#endif

    c->log->action = "in resolving client address";

    ctx = rp_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        rp_mail_close_connection(c);
        return;
    }

    ctx->addr.sockaddr = c->sockaddr;
    ctx->addr.socklen = c->socklen;
    ctx->handler = rp_mail_smtp_resolve_addr_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    s->resolver_ctx = ctx;
    c->read->handler = rp_mail_smtp_block_reading;

    if (rp_resolve_addr(ctx) != RP_OK) {
        rp_mail_close_connection(c);
    }
}


static void
rp_mail_smtp_resolve_addr_handler(rp_resolver_ctx_t *ctx)
{
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        rp_log_error(RP_LOG_ERR, c->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &c->addr_text, ctx->state,
                      rp_resolver_strerror(ctx->state));

        if (ctx->state == RP_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

        rp_resolve_addr_done(ctx);

        rp_mail_smtp_greeting(s, s->connection);

        return;
    }

    c->log->action = "in resolving client hostname";

    s->host.data = rp_pstrdup(c->pool, &ctx->name);
    if (s->host.data == NULL) {
        rp_resolve_addr_done(ctx);
        rp_mail_close_connection(c);
        return;
    }

    s->host.len = ctx->name.len;

    rp_resolve_addr_done(ctx);

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "address resolved: %V", &s->host);

    c->read->handler = rp_mail_smtp_resolve_name;

    rp_post_event(c->read, &rp_posted_events);
}


static void
rp_mail_smtp_resolve_name(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_resolver_ctx_t        *ctx;
    rp_mail_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    ctx = rp_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        rp_mail_close_connection(c);
        return;
    }

    ctx->name = s->host;
    ctx->handler = rp_mail_smtp_resolve_name_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    s->resolver_ctx = ctx;
    c->read->handler = rp_mail_smtp_block_reading;

    if (rp_resolve_name(ctx) != RP_OK) {
        rp_mail_close_connection(c);
    }
}


static void
rp_mail_smtp_resolve_name_handler(rp_resolver_ctx_t *ctx)
{
    rp_uint_t           i;
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        rp_log_error(RP_LOG_ERR, c->log, 0,
                      "\"%V\" could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      rp_resolver_strerror(ctx->state));

        if (ctx->state == RP_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

    } else {

#if (RP_DEBUG)
        {
        u_char     text[RP_SOCKADDR_STRLEN];
        rp_str_t  addr;

        addr.data = text;

        for (i = 0; i < ctx->naddrs; i++) {
            addr.len = rp_sock_ntop(ctx->addrs[i].sockaddr,
                                     ctx->addrs[i].socklen,
                                     text, RP_SOCKADDR_STRLEN, 0);

            rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                           "name was resolved to %V", &addr);
        }
        }
#endif

        for (i = 0; i < ctx->naddrs; i++) {
            if (rp_cmp_sockaddr(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                                 c->sockaddr, c->socklen, 0)
                == RP_OK)
            {
                goto found;
            }
        }

        s->host = smtp_unavailable;
    }

found:

    rp_resolve_name_done(ctx);

    rp_mail_smtp_greeting(s, c);
}


static void
rp_mail_smtp_block_reading(rp_event_t *rev)
{
    rp_connection_t    *c;
    rp_mail_session_t  *s;
    rp_resolver_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "smtp reading blocked");

    if (rp_handle_read_event(rev, 0) != RP_OK) {

        if (s->resolver_ctx) {
            ctx = s->resolver_ctx;

            if (ctx->handler == rp_mail_smtp_resolve_addr_handler) {
                rp_resolve_addr_done(ctx);

            } else if (ctx->handler == rp_mail_smtp_resolve_name_handler) {
                rp_resolve_name_done(ctx);
            }

            s->resolver_ctx = NULL;
        }

        rp_mail_close_connection(c);
    }
}


static void
rp_mail_smtp_greeting(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_msec_t                 timeout;
    rp_mail_core_srv_conf_t  *cscf;
    rp_mail_smtp_srv_conf_t  *sscf;

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp greeting for \"%V\"", &s->host);

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);
    sscf = rp_mail_get_module_srv_conf(s, rp_mail_smtp_module);

    timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
    rp_add_timer(c->read, timeout);

    if (rp_handle_read_event(c->read, 0) != RP_OK) {
        rp_mail_close_connection(c);
    }

    if (c->read->ready) {
        rp_post_event(c->read, &rp_posted_events);
    }

    if (sscf->greeting_delay) {
         c->read->handler = rp_mail_smtp_invalid_pipelining;
         return;
    }

    c->read->handler = rp_mail_smtp_init_protocol;

    s->out = sscf->greeting;

    rp_mail_send(c->write);
}


static void
rp_mail_smtp_invalid_pipelining(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_mail_core_srv_conf_t  *cscf;
    rp_mail_smtp_srv_conf_t  *sscf;

    c = rev->data;
    s = c->data;

    c->log->action = "in delay pipelining state";

    if (rev->timedout) {

        rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "delay greeting");

        rev->timedout = 0;

        cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

        c->read->handler = rp_mail_smtp_init_protocol;

        rp_add_timer(c->read, cscf->timeout);

        if (rp_handle_read_event(c->read, 0) != RP_OK) {
            rp_mail_close_connection(c);
            return;
        }

        sscf = rp_mail_get_module_srv_conf(s, rp_mail_smtp_module);

        s->out = sscf->greeting;

    } else {

        rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "invalid pipelining");

        if (s->buffer == NULL) {
            if (rp_mail_smtp_create_buffer(s, c) != RP_OK) {
                return;
            }
        }

        if (rp_mail_smtp_discard_command(s, c,
                                "client was rejected before greeting: \"%V\"")
            != RP_OK)
        {
            return;
        }

        rp_str_set(&s->out, smtp_invalid_pipelining);
        s->quit = 1;
    }

    rp_mail_send(c->write);
}


void
rp_mail_smtp_init_protocol(rp_event_t *rev)
{
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rp_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (rp_mail_smtp_create_buffer(s, c) != RP_OK) {
            return;
        }
    }

    s->mail_state = rp_smtp_start;
    c->read->handler = rp_mail_smtp_auth_state;

    rp_mail_smtp_auth_state(rev);
}


static rp_int_t
rp_mail_smtp_create_buffer(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_mail_smtp_srv_conf_t  *sscf;

    if (rp_array_init(&s->args, c->pool, 2, sizeof(rp_str_t)) == RP_ERROR) {
        rp_mail_session_internal_server_error(s);
        return RP_ERROR;
    }

    sscf = rp_mail_get_module_srv_conf(s, rp_mail_smtp_module);

    s->buffer = rp_create_temp_buf(c->pool, sscf->client_buffer_size);
    if (s->buffer == NULL) {
        rp_mail_session_internal_server_error(s);
        return RP_ERROR;
    }

    return RP_OK;
}


void
rp_mail_smtp_auth_state(rp_event_t *rev)
{
    rp_int_t            rc;
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rp_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = rp_mail_read_command(s, c);

    if (rc == RP_AGAIN || rc == RP_ERROR) {
        return;
    }

    rp_str_set(&s->out, smtp_ok);

    if (rc == RP_OK) {
        switch (s->mail_state) {

        case rp_smtp_start:

            switch (s->command) {

            case RP_SMTP_HELO:
            case RP_SMTP_EHLO:
                rc = rp_mail_smtp_helo(s, c);
                break;

            case RP_SMTP_AUTH:
                rc = rp_mail_smtp_auth(s, c);
                break;

            case RP_SMTP_QUIT:
                s->quit = 1;
                rp_str_set(&s->out, smtp_bye);
                break;

            case RP_SMTP_MAIL:
                rc = rp_mail_smtp_mail(s, c);
                break;

            case RP_SMTP_RCPT:
                rc = rp_mail_smtp_rcpt(s, c);
                break;

            case RP_SMTP_RSET:
                rc = rp_mail_smtp_rset(s, c);
                break;

            case RP_SMTP_NOOP:
                break;

            case RP_SMTP_STARTTLS:
                rc = rp_mail_smtp_starttls(s, c);
                rp_str_set(&s->out, smtp_starttls);
                break;

            default:
                rc = RP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case rp_smtp_auth_login_username:
            rc = rp_mail_auth_login_username(s, c, 0);

            rp_str_set(&s->out, smtp_password);
            s->mail_state = rp_smtp_auth_login_password;
            break;

        case rp_smtp_auth_login_password:
            rc = rp_mail_auth_login_password(s, c);
            break;

        case rp_smtp_auth_plain:
            rc = rp_mail_auth_plain(s, c, 0);
            break;

        case rp_smtp_auth_cram_md5:
            rc = rp_mail_auth_cram_md5(s, c);
            break;

        case rp_smtp_auth_external:
            rc = rp_mail_auth_external(s, c, 0);
            break;
        }
    }

    if (s->buffer->pos < s->buffer->last) {
        s->blocked = 1;
    }

    switch (rc) {

    case RP_DONE:
        rp_mail_auth(s, c);
        return;

    case RP_ERROR:
        rp_mail_session_internal_server_error(s);
        return;

    case RP_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = rp_smtp_start;
        s->state = 0;
        rp_str_set(&s->out, smtp_invalid_command);

        /* fall through */

    case RP_OK:
        s->args.nelts = 0;

        if (s->buffer->pos == s->buffer->last) {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
        }

        if (s->state) {
            s->arg_start = s->buffer->pos;
        }

        rp_mail_send(c->write);
    }
}


static rp_int_t
rp_mail_smtp_helo(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t                 *arg;
    rp_mail_smtp_srv_conf_t  *sscf;

    if (s->args.nelts != 1) {
        rp_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return RP_OK;
    }

    arg = s->args.elts;

    s->smtp_helo.len = arg[0].len;

    s->smtp_helo.data = rp_pnalloc(c->pool, arg[0].len);
    if (s->smtp_helo.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

    rp_str_null(&s->smtp_from);
    rp_str_null(&s->smtp_to);

    sscf = rp_mail_get_module_srv_conf(s, rp_mail_smtp_module);

    if (s->command == RP_SMTP_HELO) {
        s->out = sscf->server_name;

    } else {
        s->esmtp = 1;

#if (RP_MAIL_SSL)

        if (c->ssl == NULL) {
            rp_mail_ssl_conf_t  *sslcf;

            sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

            if (sslcf->starttls == RP_MAIL_STARTTLS_ON) {
                s->out = sscf->starttls_capability;
                return RP_OK;
            }

            if (sslcf->starttls == RP_MAIL_STARTTLS_ONLY) {
                s->out = sscf->starttls_only_capability;
                return RP_OK;
            }
        }
#endif

        s->out = sscf->capability;
    }

    return RP_OK;
}


static rp_int_t
rp_mail_smtp_auth(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_int_t                  rc;
    rp_mail_core_srv_conf_t  *cscf;
    rp_mail_smtp_srv_conf_t  *sscf;

#if (RP_MAIL_SSL)
    if (rp_mail_starttls_only(s, c)) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts == 0) {
        rp_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return RP_OK;
    }

    sscf = rp_mail_get_module_srv_conf(s, rp_mail_smtp_module);

    rc = rp_mail_auth_parse(s, c);

    switch (rc) {

    case RP_MAIL_AUTH_LOGIN:

        rp_str_set(&s->out, smtp_username);
        s->mail_state = rp_smtp_auth_login_username;

        return RP_OK;

    case RP_MAIL_AUTH_LOGIN_USERNAME:

        rp_str_set(&s->out, smtp_password);
        s->mail_state = rp_smtp_auth_login_password;

        return rp_mail_auth_login_username(s, c, 1);

    case RP_MAIL_AUTH_PLAIN:

        rp_str_set(&s->out, smtp_next);
        s->mail_state = rp_smtp_auth_plain;

        return RP_OK;

    case RP_MAIL_AUTH_CRAM_MD5:

        if (!(sscf->auth_methods & RP_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return RP_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

            if (rp_mail_salt(s, c, cscf) != RP_OK) {
                return RP_ERROR;
            }
        }

        if (rp_mail_auth_cram_md5_salt(s, c, "334 ", 4) == RP_OK) {
            s->mail_state = rp_smtp_auth_cram_md5;
            return RP_OK;
        }

        return RP_ERROR;

    case RP_MAIL_AUTH_EXTERNAL:

        if (!(sscf->auth_methods & RP_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return RP_MAIL_PARSE_INVALID_COMMAND;
        }

        rp_str_set(&s->out, smtp_username);
        s->mail_state = rp_smtp_auth_external;

        return RP_OK;
    }

    return rc;
}


static rp_int_t
rp_mail_smtp_mail(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t                 *arg, cmd;
    rp_mail_smtp_srv_conf_t  *sscf;

    sscf = rp_mail_get_module_srv_conf(s, rp_mail_smtp_module);

    if (!(sscf->auth_methods & RP_MAIL_AUTH_NONE_ENABLED)) {
        rp_mail_smtp_log_rejected_command(s, c, "client was rejected: \"%V\"");
        rp_str_set(&s->out, smtp_auth_required);
        return RP_OK;
    }

    /* auth none */

    if (s->smtp_from.len) {
        rp_str_set(&s->out, smtp_bad_sequence);
        return RP_OK;
    }

    if (s->args.nelts == 0) {
        rp_str_set(&s->out, smtp_invalid_argument);
        return RP_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_from.len = cmd.len;

    s->smtp_from.data = rp_pnalloc(c->pool, cmd.len);
    if (s->smtp_from.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s->smtp_from.data, cmd.data, cmd.len);

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp mail from:\"%V\"", &s->smtp_from);

    rp_str_set(&s->out, smtp_ok);

    return RP_OK;
}


static rp_int_t
rp_mail_smtp_rcpt(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t  *arg, cmd;

    if (s->smtp_from.len == 0) {
        rp_str_set(&s->out, smtp_bad_sequence);
        return RP_OK;
    }

    if (s->args.nelts == 0) {
        rp_str_set(&s->out, smtp_invalid_argument);
        return RP_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_to.len = cmd.len;

    s->smtp_to.data = rp_pnalloc(c->pool, cmd.len);
    if (s->smtp_to.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s->smtp_to.data, cmd.data, cmd.len);

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp rcpt to:\"%V\"", &s->smtp_to);

    s->auth_method = RP_MAIL_AUTH_NONE;

    return RP_DONE;
}


static rp_int_t
rp_mail_smtp_rset(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_null(&s->smtp_from);
    rp_str_null(&s->smtp_to);
    rp_str_set(&s->out, smtp_ok);

    return RP_OK;
}


static rp_int_t
rp_mail_smtp_starttls(rp_mail_session_t *s, rp_connection_t *c)
{
#if (RP_MAIL_SSL)
    rp_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);
        if (sslcf->starttls) {

            /*
             * RFC3207 requires us to discard any knowledge
             * obtained from client before STARTTLS.
             */

            rp_str_null(&s->smtp_helo);
            rp_str_null(&s->smtp_from);
            rp_str_null(&s->smtp_to);

            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;

            c->read->handler = rp_mail_starttls_handler;
            return RP_OK;
        }
    }

#endif

    return RP_MAIL_PARSE_INVALID_COMMAND;
}


static rp_int_t
rp_mail_smtp_discard_command(rp_mail_session_t *s, rp_connection_t *c,
    char *err)
{
    ssize_t    n;

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

        return RP_AGAIN;
    }

    rp_mail_smtp_log_rejected_command(s, c, err);

    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    return RP_OK;
}


static void
rp_mail_smtp_log_rejected_command(rp_mail_session_t *s, rp_connection_t *c,
    char *err)
{
    u_char      ch;
    rp_str_t   cmd;
    rp_uint_t  i;

    if (c->log->log_level < RP_LOG_INFO) {
        return;
    }

    cmd.len = s->buffer->last - s->buffer->start;
    cmd.data = s->buffer->start;

    for (i = 0; i < cmd.len; i++) {
        ch = cmd.data[i];

        if (ch != CR && ch != LF) {
            continue;
        }

        cmd.data[i] = '_';
    }

    cmd.len = i;

    rp_log_error(RP_LOG_INFO, c->log, 0, err, &cmd);
}

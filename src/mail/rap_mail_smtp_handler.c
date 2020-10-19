
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>
#include <rap_mail_smtp_module.h>


static void rap_mail_smtp_resolve_addr_handler(rap_resolver_ctx_t *ctx);
static void rap_mail_smtp_resolve_name(rap_event_t *rev);
static void rap_mail_smtp_resolve_name_handler(rap_resolver_ctx_t *ctx);
static void rap_mail_smtp_block_reading(rap_event_t *rev);
static void rap_mail_smtp_greeting(rap_mail_session_t *s, rap_connection_t *c);
static void rap_mail_smtp_invalid_pipelining(rap_event_t *rev);
static rap_int_t rap_mail_smtp_create_buffer(rap_mail_session_t *s,
    rap_connection_t *c);

static rap_int_t rap_mail_smtp_helo(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_smtp_auth(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_smtp_mail(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_smtp_starttls(rap_mail_session_t *s,
    rap_connection_t *c);
static rap_int_t rap_mail_smtp_rset(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_smtp_rcpt(rap_mail_session_t *s, rap_connection_t *c);

static rap_int_t rap_mail_smtp_discard_command(rap_mail_session_t *s,
    rap_connection_t *c, char *err);
static void rap_mail_smtp_log_rejected_command(rap_mail_session_t *s,
    rap_connection_t *c, char *err);


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


static rap_str_t  smtp_unavailable = rap_string("[UNAVAILABLE]");
static rap_str_t  smtp_tempunavail = rap_string("[TEMPUNAVAIL]");


void
rap_mail_smtp_init_session(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_resolver_ctx_t        *ctx;
    rap_mail_core_srv_conf_t  *cscf;

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    if (cscf->resolver == NULL) {
        s->host = smtp_unavailable;
        rap_mail_smtp_greeting(s, c);
        return;
    }

#if (RAP_HAVE_UNIX_DOMAIN)
    if (c->sockaddr->sa_family == AF_UNIX) {
        s->host = smtp_tempunavail;
        rap_mail_smtp_greeting(s, c);
        return;
    }
#endif

    c->log->action = "in resolving client address";

    ctx = rap_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        rap_mail_close_connection(c);
        return;
    }

    ctx->addr.sockaddr = c->sockaddr;
    ctx->addr.socklen = c->socklen;
    ctx->handler = rap_mail_smtp_resolve_addr_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    s->resolver_ctx = ctx;
    c->read->handler = rap_mail_smtp_block_reading;

    if (rap_resolve_addr(ctx) != RAP_OK) {
        rap_mail_close_connection(c);
    }
}


static void
rap_mail_smtp_resolve_addr_handler(rap_resolver_ctx_t *ctx)
{
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        rap_log_error(RAP_LOG_ERR, c->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &c->addr_text, ctx->state,
                      rap_resolver_strerror(ctx->state));

        if (ctx->state == RAP_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

        rap_resolve_addr_done(ctx);

        rap_mail_smtp_greeting(s, s->connection);

        return;
    }

    c->log->action = "in resolving client hostname";

    s->host.data = rap_pstrdup(c->pool, &ctx->name);
    if (s->host.data == NULL) {
        rap_resolve_addr_done(ctx);
        rap_mail_close_connection(c);
        return;
    }

    s->host.len = ctx->name.len;

    rap_resolve_addr_done(ctx);

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "address resolved: %V", &s->host);

    c->read->handler = rap_mail_smtp_resolve_name;

    rap_post_event(c->read, &rap_posted_events);
}


static void
rap_mail_smtp_resolve_name(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_resolver_ctx_t        *ctx;
    rap_mail_core_srv_conf_t  *cscf;

    c = rev->data;
    s = c->data;

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    ctx = rap_resolve_start(cscf->resolver, NULL);
    if (ctx == NULL) {
        rap_mail_close_connection(c);
        return;
    }

    ctx->name = s->host;
    ctx->handler = rap_mail_smtp_resolve_name_handler;
    ctx->data = s;
    ctx->timeout = cscf->resolver_timeout;

    s->resolver_ctx = ctx;
    c->read->handler = rap_mail_smtp_block_reading;

    if (rap_resolve_name(ctx) != RAP_OK) {
        rap_mail_close_connection(c);
    }
}


static void
rap_mail_smtp_resolve_name_handler(rap_resolver_ctx_t *ctx)
{
    rap_uint_t           i;
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    s = ctx->data;
    c = s->connection;

    if (ctx->state) {
        rap_log_error(RAP_LOG_ERR, c->log, 0,
                      "\"%V\" could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      rap_resolver_strerror(ctx->state));

        if (ctx->state == RAP_RESOLVE_NXDOMAIN) {
            s->host = smtp_unavailable;

        } else {
            s->host = smtp_tempunavail;
        }

    } else {

#if (RAP_DEBUG)
        {
        u_char     text[RAP_SOCKADDR_STRLEN];
        rap_str_t  addr;

        addr.data = text;

        for (i = 0; i < ctx->naddrs; i++) {
            addr.len = rap_sock_ntop(ctx->addrs[i].sockaddr,
                                     ctx->addrs[i].socklen,
                                     text, RAP_SOCKADDR_STRLEN, 0);

            rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                           "name was resolved to %V", &addr);
        }
        }
#endif

        for (i = 0; i < ctx->naddrs; i++) {
            if (rap_cmp_sockaddr(ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,
                                 c->sockaddr, c->socklen, 0)
                == RAP_OK)
            {
                goto found;
            }
        }

        s->host = smtp_unavailable;
    }

found:

    rap_resolve_name_done(ctx);

    rap_mail_smtp_greeting(s, c);
}


static void
rap_mail_smtp_block_reading(rap_event_t *rev)
{
    rap_connection_t    *c;
    rap_mail_session_t  *s;
    rap_resolver_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "smtp reading blocked");

    if (rap_handle_read_event(rev, 0) != RAP_OK) {

        if (s->resolver_ctx) {
            ctx = s->resolver_ctx;

            if (ctx->handler == rap_mail_smtp_resolve_addr_handler) {
                rap_resolve_addr_done(ctx);

            } else if (ctx->handler == rap_mail_smtp_resolve_name_handler) {
                rap_resolve_name_done(ctx);
            }

            s->resolver_ctx = NULL;
        }

        rap_mail_close_connection(c);
    }
}


static void
rap_mail_smtp_greeting(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_msec_t                 timeout;
    rap_mail_core_srv_conf_t  *cscf;
    rap_mail_smtp_srv_conf_t  *sscf;

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp greeting for \"%V\"", &s->host);

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);
    sscf = rap_mail_get_module_srv_conf(s, rap_mail_smtp_module);

    timeout = sscf->greeting_delay ? sscf->greeting_delay : cscf->timeout;
    rap_add_timer(c->read, timeout);

    if (rap_handle_read_event(c->read, 0) != RAP_OK) {
        rap_mail_close_connection(c);
    }

    if (c->read->ready) {
        rap_post_event(c->read, &rap_posted_events);
    }

    if (sscf->greeting_delay) {
         c->read->handler = rap_mail_smtp_invalid_pipelining;
         return;
    }

    c->read->handler = rap_mail_smtp_init_protocol;

    s->out = sscf->greeting;

    rap_mail_send(c->write);
}


static void
rap_mail_smtp_invalid_pipelining(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_mail_core_srv_conf_t  *cscf;
    rap_mail_smtp_srv_conf_t  *sscf;

    c = rev->data;
    s = c->data;

    c->log->action = "in delay pipelining state";

    if (rev->timedout) {

        rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "delay greeting");

        rev->timedout = 0;

        cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

        c->read->handler = rap_mail_smtp_init_protocol;

        rap_add_timer(c->read, cscf->timeout);

        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            rap_mail_close_connection(c);
            return;
        }

        sscf = rap_mail_get_module_srv_conf(s, rap_mail_smtp_module);

        s->out = sscf->greeting;

    } else {

        rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "invalid pipelining");

        if (s->buffer == NULL) {
            if (rap_mail_smtp_create_buffer(s, c) != RAP_OK) {
                return;
            }
        }

        if (rap_mail_smtp_discard_command(s, c,
                                "client was rejected before greeting: \"%V\"")
            != RAP_OK)
        {
            return;
        }

        rap_str_set(&s->out, smtp_invalid_pipelining);
        s->quit = 1;
    }

    rap_mail_send(c->write);
}


void
rap_mail_smtp_init_protocol(rap_event_t *rev)
{
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rap_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (rap_mail_smtp_create_buffer(s, c) != RAP_OK) {
            return;
        }
    }

    s->mail_state = rap_smtp_start;
    c->read->handler = rap_mail_smtp_auth_state;

    rap_mail_smtp_auth_state(rev);
}


static rap_int_t
rap_mail_smtp_create_buffer(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_mail_smtp_srv_conf_t  *sscf;

    if (rap_array_init(&s->args, c->pool, 2, sizeof(rap_str_t)) == RAP_ERROR) {
        rap_mail_session_internal_server_error(s);
        return RAP_ERROR;
    }

    sscf = rap_mail_get_module_srv_conf(s, rap_mail_smtp_module);

    s->buffer = rap_create_temp_buf(c->pool, sscf->client_buffer_size);
    if (s->buffer == NULL) {
        rap_mail_session_internal_server_error(s);
        return RAP_ERROR;
    }

    return RAP_OK;
}


void
rap_mail_smtp_auth_state(rap_event_t *rev)
{
    rap_int_t            rc;
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rap_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = rap_mail_read_command(s, c);

    if (rc == RAP_AGAIN || rc == RAP_ERROR) {
        return;
    }

    rap_str_set(&s->out, smtp_ok);

    if (rc == RAP_OK) {
        switch (s->mail_state) {

        case rap_smtp_start:

            switch (s->command) {

            case RAP_SMTP_HELO:
            case RAP_SMTP_EHLO:
                rc = rap_mail_smtp_helo(s, c);
                break;

            case RAP_SMTP_AUTH:
                rc = rap_mail_smtp_auth(s, c);
                break;

            case RAP_SMTP_QUIT:
                s->quit = 1;
                rap_str_set(&s->out, smtp_bye);
                break;

            case RAP_SMTP_MAIL:
                rc = rap_mail_smtp_mail(s, c);
                break;

            case RAP_SMTP_RCPT:
                rc = rap_mail_smtp_rcpt(s, c);
                break;

            case RAP_SMTP_RSET:
                rc = rap_mail_smtp_rset(s, c);
                break;

            case RAP_SMTP_NOOP:
                break;

            case RAP_SMTP_STARTTLS:
                rc = rap_mail_smtp_starttls(s, c);
                rap_str_set(&s->out, smtp_starttls);
                break;

            default:
                rc = RAP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case rap_smtp_auth_login_username:
            rc = rap_mail_auth_login_username(s, c, 0);

            rap_str_set(&s->out, smtp_password);
            s->mail_state = rap_smtp_auth_login_password;
            break;

        case rap_smtp_auth_login_password:
            rc = rap_mail_auth_login_password(s, c);
            break;

        case rap_smtp_auth_plain:
            rc = rap_mail_auth_plain(s, c, 0);
            break;

        case rap_smtp_auth_cram_md5:
            rc = rap_mail_auth_cram_md5(s, c);
            break;

        case rap_smtp_auth_external:
            rc = rap_mail_auth_external(s, c, 0);
            break;
        }
    }

    if (s->buffer->pos < s->buffer->last) {
        s->blocked = 1;
    }

    switch (rc) {

    case RAP_DONE:
        rap_mail_auth(s, c);
        return;

    case RAP_ERROR:
        rap_mail_session_internal_server_error(s);
        return;

    case RAP_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = rap_smtp_start;
        s->state = 0;
        rap_str_set(&s->out, smtp_invalid_command);

        /* fall through */

    case RAP_OK:
        s->args.nelts = 0;

        if (s->buffer->pos == s->buffer->last) {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
        }

        if (s->state) {
            s->arg_start = s->buffer->pos;
        }

        rap_mail_send(c->write);
    }
}


static rap_int_t
rap_mail_smtp_helo(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t                 *arg;
    rap_mail_smtp_srv_conf_t  *sscf;

    if (s->args.nelts != 1) {
        rap_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return RAP_OK;
    }

    arg = s->args.elts;

    s->smtp_helo.len = arg[0].len;

    s->smtp_helo.data = rap_pnalloc(c->pool, arg[0].len);
    if (s->smtp_helo.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

    rap_str_null(&s->smtp_from);
    rap_str_null(&s->smtp_to);

    sscf = rap_mail_get_module_srv_conf(s, rap_mail_smtp_module);

    if (s->command == RAP_SMTP_HELO) {
        s->out = sscf->server_name;

    } else {
        s->esmtp = 1;

#if (RAP_MAIL_SSL)

        if (c->ssl == NULL) {
            rap_mail_ssl_conf_t  *sslcf;

            sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

            if (sslcf->starttls == RAP_MAIL_STARTTLS_ON) {
                s->out = sscf->starttls_capability;
                return RAP_OK;
            }

            if (sslcf->starttls == RAP_MAIL_STARTTLS_ONLY) {
                s->out = sscf->starttls_only_capability;
                return RAP_OK;
            }
        }
#endif

        s->out = sscf->capability;
    }

    return RAP_OK;
}


static rap_int_t
rap_mail_smtp_auth(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_int_t                  rc;
    rap_mail_core_srv_conf_t  *cscf;
    rap_mail_smtp_srv_conf_t  *sscf;

#if (RAP_MAIL_SSL)
    if (rap_mail_starttls_only(s, c)) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts == 0) {
        rap_str_set(&s->out, smtp_invalid_argument);
        s->state = 0;
        return RAP_OK;
    }

    sscf = rap_mail_get_module_srv_conf(s, rap_mail_smtp_module);

    rc = rap_mail_auth_parse(s, c);

    switch (rc) {

    case RAP_MAIL_AUTH_LOGIN:

        rap_str_set(&s->out, smtp_username);
        s->mail_state = rap_smtp_auth_login_username;

        return RAP_OK;

    case RAP_MAIL_AUTH_LOGIN_USERNAME:

        rap_str_set(&s->out, smtp_password);
        s->mail_state = rap_smtp_auth_login_password;

        return rap_mail_auth_login_username(s, c, 1);

    case RAP_MAIL_AUTH_PLAIN:

        rap_str_set(&s->out, smtp_next);
        s->mail_state = rap_smtp_auth_plain;

        return RAP_OK;

    case RAP_MAIL_AUTH_CRAM_MD5:

        if (!(sscf->auth_methods & RAP_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return RAP_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

            if (rap_mail_salt(s, c, cscf) != RAP_OK) {
                return RAP_ERROR;
            }
        }

        if (rap_mail_auth_cram_md5_salt(s, c, "334 ", 4) == RAP_OK) {
            s->mail_state = rap_smtp_auth_cram_md5;
            return RAP_OK;
        }

        return RAP_ERROR;

    case RAP_MAIL_AUTH_EXTERNAL:

        if (!(sscf->auth_methods & RAP_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return RAP_MAIL_PARSE_INVALID_COMMAND;
        }

        rap_str_set(&s->out, smtp_username);
        s->mail_state = rap_smtp_auth_external;

        return RAP_OK;
    }

    return rc;
}


static rap_int_t
rap_mail_smtp_mail(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t                 *arg, cmd;
    rap_mail_smtp_srv_conf_t  *sscf;

    sscf = rap_mail_get_module_srv_conf(s, rap_mail_smtp_module);

    if (!(sscf->auth_methods & RAP_MAIL_AUTH_NONE_ENABLED)) {
        rap_mail_smtp_log_rejected_command(s, c, "client was rejected: \"%V\"");
        rap_str_set(&s->out, smtp_auth_required);
        return RAP_OK;
    }

    /* auth none */

    if (s->smtp_from.len) {
        rap_str_set(&s->out, smtp_bad_sequence);
        return RAP_OK;
    }

    if (s->args.nelts == 0) {
        rap_str_set(&s->out, smtp_invalid_argument);
        return RAP_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_from.len = cmd.len;

    s->smtp_from.data = rap_pnalloc(c->pool, cmd.len);
    if (s->smtp_from.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->smtp_from.data, cmd.data, cmd.len);

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp mail from:\"%V\"", &s->smtp_from);

    rap_str_set(&s->out, smtp_ok);

    return RAP_OK;
}


static rap_int_t
rap_mail_smtp_rcpt(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t  *arg, cmd;

    if (s->smtp_from.len == 0) {
        rap_str_set(&s->out, smtp_bad_sequence);
        return RAP_OK;
    }

    if (s->args.nelts == 0) {
        rap_str_set(&s->out, smtp_invalid_argument);
        return RAP_OK;
    }

    arg = s->args.elts;
    arg += s->args.nelts - 1;

    cmd.len = arg->data + arg->len - s->cmd.data;
    cmd.data = s->cmd.data;

    s->smtp_to.len = cmd.len;

    s->smtp_to.data = rap_pnalloc(c->pool, cmd.len);
    if (s->smtp_to.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->smtp_to.data, cmd.data, cmd.len);

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp rcpt to:\"%V\"", &s->smtp_to);

    s->auth_method = RAP_MAIL_AUTH_NONE;

    return RAP_DONE;
}


static rap_int_t
rap_mail_smtp_rset(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_null(&s->smtp_from);
    rap_str_null(&s->smtp_to);
    rap_str_set(&s->out, smtp_ok);

    return RAP_OK;
}


static rap_int_t
rap_mail_smtp_starttls(rap_mail_session_t *s, rap_connection_t *c)
{
#if (RAP_MAIL_SSL)
    rap_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);
        if (sslcf->starttls) {

            /*
             * RFC3207 requires us to discard any knowledge
             * obtained from client before STARTTLS.
             */

            rap_str_null(&s->smtp_helo);
            rap_str_null(&s->smtp_from);
            rap_str_null(&s->smtp_to);

            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;

            c->read->handler = rap_mail_starttls_handler;
            return RAP_OK;
        }
    }

#endif

    return RAP_MAIL_PARSE_INVALID_COMMAND;
}


static rap_int_t
rap_mail_smtp_discard_command(rap_mail_session_t *s, rap_connection_t *c,
    char *err)
{
    ssize_t    n;

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

        return RAP_AGAIN;
    }

    rap_mail_smtp_log_rejected_command(s, c, err);

    s->buffer->pos = s->buffer->start;
    s->buffer->last = s->buffer->start;

    return RAP_OK;
}


static void
rap_mail_smtp_log_rejected_command(rap_mail_session_t *s, rap_connection_t *c,
    char *err)
{
    u_char      ch;
    rap_str_t   cmd;
    rap_uint_t  i;

    if (c->log->log_level < RAP_LOG_INFO) {
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

    rap_log_error(RAP_LOG_INFO, c->log, 0, err, &cmd);
}

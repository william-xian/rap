
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>
#include <rap_mail_imap_module.h>


static rap_int_t rap_mail_imap_login(rap_mail_session_t *s,
    rap_connection_t *c);
static rap_int_t rap_mail_imap_authenticate(rap_mail_session_t *s,
    rap_connection_t *c);
static rap_int_t rap_mail_imap_capability(rap_mail_session_t *s,
    rap_connection_t *c);
static rap_int_t rap_mail_imap_starttls(rap_mail_session_t *s,
    rap_connection_t *c);


static u_char  imap_greeting[] = "* OK IMAP4 ready" CRLF;
static u_char  imap_star[] = "* ";
static u_char  imap_ok[] = "OK completed" CRLF;
static u_char  imap_next[] = "+ OK" CRLF;
static u_char  imap_plain_next[] = "+ " CRLF;
static u_char  imap_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  imap_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  imap_bye[] = "* BYE" CRLF;
static u_char  imap_invalid_command[] = "BAD invalid command" CRLF;


void
rap_mail_imap_init_session(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_mail_core_srv_conf_t  *cscf;

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    rap_str_set(&s->out, imap_greeting);

    c->read->handler = rap_mail_imap_init_protocol;

    rap_add_timer(c->read, cscf->timeout);

    if (rap_handle_read_event(c->read, 0) != RAP_OK) {
        rap_mail_close_connection(c);
    }

    rap_mail_send(c->write);
}


void
rap_mail_imap_init_protocol(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_mail_imap_srv_conf_t  *iscf;

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
        if (rap_array_init(&s->args, c->pool, 2, sizeof(rap_str_t))
            == RAP_ERROR)
        {
            rap_mail_session_internal_server_error(s);
            return;
        }

        iscf = rap_mail_get_module_srv_conf(s, rap_mail_imap_module);

        s->buffer = rap_create_temp_buf(c->pool, iscf->client_buffer_size);
        if (s->buffer == NULL) {
            rap_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = rap_imap_start;
    c->read->handler = rap_mail_imap_auth_state;

    rap_mail_imap_auth_state(rev);
}


void
rap_mail_imap_auth_state(rap_event_t *rev)
{
    u_char              *p, *dst, *src, *end;
    rap_str_t           *arg;
    rap_int_t            rc;
    rap_uint_t           tag, i;
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "imap auth state");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rap_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "imap send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = rap_mail_read_command(s, c);

    if (rc == RAP_AGAIN || rc == RAP_ERROR) {
        return;
    }

    tag = 1;
    s->text.len = 0;
    rap_str_set(&s->out, imap_ok);

    if (rc == RAP_OK) {

        rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0, "imap auth command: %i",
                       s->command);

        if (s->backslash) {

            arg = s->args.elts;

            for (i = 0; i < s->args.nelts; i++) {
                dst = arg[i].data;
                end = dst + arg[i].len;

                for (src = dst; src < end; dst++) {
                    *dst = *src;
                    if (*src++ == '\\') {
                        *dst = *src++;
                    }
                }

                arg[i].len = dst - arg[i].data;
            }

            s->backslash = 0;
        }

        switch (s->mail_state) {

        case rap_imap_start:

            switch (s->command) {

            case RAP_IMAP_LOGIN:
                rc = rap_mail_imap_login(s, c);
                break;

            case RAP_IMAP_AUTHENTICATE:
                rc = rap_mail_imap_authenticate(s, c);
                tag = (rc != RAP_OK);
                break;

            case RAP_IMAP_CAPABILITY:
                rc = rap_mail_imap_capability(s, c);
                break;

            case RAP_IMAP_LOGOUT:
                s->quit = 1;
                rap_str_set(&s->text, imap_bye);
                break;

            case RAP_IMAP_NOOP:
                break;

            case RAP_IMAP_STARTTLS:
                rc = rap_mail_imap_starttls(s, c);
                break;

            default:
                rc = RAP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case rap_imap_auth_login_username:
            rc = rap_mail_auth_login_username(s, c, 0);

            tag = 0;
            rap_str_set(&s->out, imap_password);
            s->mail_state = rap_imap_auth_login_password;

            break;

        case rap_imap_auth_login_password:
            rc = rap_mail_auth_login_password(s, c);
            break;

        case rap_imap_auth_plain:
            rc = rap_mail_auth_plain(s, c, 0);
            break;

        case rap_imap_auth_cram_md5:
            rc = rap_mail_auth_cram_md5(s, c);
            break;

        case rap_imap_auth_external:
            rc = rap_mail_auth_external(s, c, 0);
            break;
        }

    } else if (rc == RAP_IMAP_NEXT) {
        tag = 0;
        rap_str_set(&s->out, imap_next);
    }

    switch (rc) {

    case RAP_DONE:
        rap_mail_auth(s, c);
        return;

    case RAP_ERROR:
        rap_mail_session_internal_server_error(s);
        return;

    case RAP_MAIL_PARSE_INVALID_COMMAND:
        s->state = 0;
        rap_str_set(&s->out, imap_invalid_command);
        s->mail_state = rap_imap_start;
        break;
    }

    if (tag) {
        if (s->tag.len == 0) {
            rap_str_set(&s->tag, imap_star);
        }

        if (s->tagged_line.len < s->tag.len + s->text.len + s->out.len) {
            s->tagged_line.len = s->tag.len + s->text.len + s->out.len;
            s->tagged_line.data = rap_pnalloc(c->pool, s->tagged_line.len);
            if (s->tagged_line.data == NULL) {
                rap_mail_close_connection(c);
                return;
            }
        }

        p = s->tagged_line.data;

        if (s->text.len) {
            p = rap_cpymem(p, s->text.data, s->text.len);
        }

        p = rap_cpymem(p, s->tag.data, s->tag.len);
        rap_memcpy(p, s->out.data, s->out.len);

        s->out.len = s->text.len + s->tag.len + s->out.len;
        s->out.data = s->tagged_line.data;
    }

    if (rc != RAP_IMAP_NEXT) {
        s->args.nelts = 0;

        if (s->state) {
            /* preserve tag */
            s->arg_start = s->buffer->start + s->tag.len;
            s->buffer->pos = s->arg_start;
            s->buffer->last = s->arg_start;

        } else {
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
            s->tag.len = 0;
        }
    }

    rap_mail_send(c->write);
}


static rap_int_t
rap_mail_imap_login(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t  *arg;

#if (RAP_MAIL_SSL)
    if (rap_mail_starttls_only(s, c)) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    arg = s->args.elts;

    if (s->args.nelts != 2 || arg[0].len == 0) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = arg[0].len;
    s->login.data = rap_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->login.data, arg[0].data, s->login.len);

    s->passwd.len = arg[1].len;
    s->passwd.data = rap_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

#if (RAP_DEBUG_MAIL_PASSWD)
    rap_log_debug2(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\" passwd:\"%V\"",
                   &s->login, &s->passwd);
#else
    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\"", &s->login);
#endif

    return RAP_DONE;
}


static rap_int_t
rap_mail_imap_authenticate(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_int_t                  rc;
    rap_mail_core_srv_conf_t  *cscf;
    rap_mail_imap_srv_conf_t  *iscf;

#if (RAP_MAIL_SSL)
    if (rap_mail_starttls_only(s, c)) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    iscf = rap_mail_get_module_srv_conf(s, rap_mail_imap_module);

    rc = rap_mail_auth_parse(s, c);

    switch (rc) {

    case RAP_MAIL_AUTH_LOGIN:

        rap_str_set(&s->out, imap_username);
        s->mail_state = rap_imap_auth_login_username;

        return RAP_OK;

    case RAP_MAIL_AUTH_LOGIN_USERNAME:

        rap_str_set(&s->out, imap_password);
        s->mail_state = rap_imap_auth_login_password;

        return rap_mail_auth_login_username(s, c, 1);

    case RAP_MAIL_AUTH_PLAIN:

        rap_str_set(&s->out, imap_plain_next);
        s->mail_state = rap_imap_auth_plain;

        return RAP_OK;

    case RAP_MAIL_AUTH_CRAM_MD5:

        if (!(iscf->auth_methods & RAP_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return RAP_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

            if (rap_mail_salt(s, c, cscf) != RAP_OK) {
                return RAP_ERROR;
            }
        }

        if (rap_mail_auth_cram_md5_salt(s, c, "+ ", 2) == RAP_OK) {
            s->mail_state = rap_imap_auth_cram_md5;
            return RAP_OK;
        }

        return RAP_ERROR;

    case RAP_MAIL_AUTH_EXTERNAL:

        if (!(iscf->auth_methods & RAP_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return RAP_MAIL_PARSE_INVALID_COMMAND;
        }

        rap_str_set(&s->out, imap_username);
        s->mail_state = rap_imap_auth_external;

        return RAP_OK;
    }

    return rc;
}


static rap_int_t
rap_mail_imap_capability(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_mail_imap_srv_conf_t  *iscf;

    iscf = rap_mail_get_module_srv_conf(s, rap_mail_imap_module);

#if (RAP_MAIL_SSL)

    if (c->ssl == NULL) {
        rap_mail_ssl_conf_t  *sslcf;

        sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

        if (sslcf->starttls == RAP_MAIL_STARTTLS_ON) {
            s->text = iscf->starttls_capability;
            return RAP_OK;
        }

        if (sslcf->starttls == RAP_MAIL_STARTTLS_ONLY) {
            s->text = iscf->starttls_only_capability;
            return RAP_OK;
        }
    }
#endif

    s->text = iscf->capability;

    return RAP_OK;
}


static rap_int_t
rap_mail_imap_starttls(rap_mail_session_t *s, rap_connection_t *c)
{
#if (RAP_MAIL_SSL)
    rap_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);
        if (sslcf->starttls) {
            c->read->handler = rap_mail_starttls_handler;
            return RAP_OK;
        }
    }

#endif

    return RAP_MAIL_PARSE_INVALID_COMMAND;
}

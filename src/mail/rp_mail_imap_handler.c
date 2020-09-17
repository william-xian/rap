
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>
#include <rp_mail_imap_module.h>


static rp_int_t rp_mail_imap_login(rp_mail_session_t *s,
    rp_connection_t *c);
static rp_int_t rp_mail_imap_authenticate(rp_mail_session_t *s,
    rp_connection_t *c);
static rp_int_t rp_mail_imap_capability(rp_mail_session_t *s,
    rp_connection_t *c);
static rp_int_t rp_mail_imap_starttls(rp_mail_session_t *s,
    rp_connection_t *c);


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
rp_mail_imap_init_session(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_mail_core_srv_conf_t  *cscf;

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    rp_str_set(&s->out, imap_greeting);

    c->read->handler = rp_mail_imap_init_protocol;

    rp_add_timer(c->read, cscf->timeout);

    if (rp_handle_read_event(c->read, 0) != RP_OK) {
        rp_mail_close_connection(c);
    }

    rp_mail_send(c->write);
}


void
rp_mail_imap_init_protocol(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_mail_imap_srv_conf_t  *iscf;

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
        if (rp_array_init(&s->args, c->pool, 2, sizeof(rp_str_t))
            == RP_ERROR)
        {
            rp_mail_session_internal_server_error(s);
            return;
        }

        iscf = rp_mail_get_module_srv_conf(s, rp_mail_imap_module);

        s->buffer = rp_create_temp_buf(c->pool, iscf->client_buffer_size);
        if (s->buffer == NULL) {
            rp_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = rp_imap_start;
    c->read->handler = rp_mail_imap_auth_state;

    rp_mail_imap_auth_state(rev);
}


void
rp_mail_imap_auth_state(rp_event_t *rev)
{
    u_char              *p, *dst, *src, *end;
    rp_str_t           *arg;
    rp_int_t            rc;
    rp_uint_t           tag, i;
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "imap auth state");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rp_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "imap send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = rp_mail_read_command(s, c);

    if (rc == RP_AGAIN || rc == RP_ERROR) {
        return;
    }

    tag = 1;
    s->text.len = 0;
    rp_str_set(&s->out, imap_ok);

    if (rc == RP_OK) {

        rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0, "imap auth command: %i",
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

        case rp_imap_start:

            switch (s->command) {

            case RP_IMAP_LOGIN:
                rc = rp_mail_imap_login(s, c);
                break;

            case RP_IMAP_AUTHENTICATE:
                rc = rp_mail_imap_authenticate(s, c);
                tag = (rc != RP_OK);
                break;

            case RP_IMAP_CAPABILITY:
                rc = rp_mail_imap_capability(s, c);
                break;

            case RP_IMAP_LOGOUT:
                s->quit = 1;
                rp_str_set(&s->text, imap_bye);
                break;

            case RP_IMAP_NOOP:
                break;

            case RP_IMAP_STARTTLS:
                rc = rp_mail_imap_starttls(s, c);
                break;

            default:
                rc = RP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case rp_imap_auth_login_username:
            rc = rp_mail_auth_login_username(s, c, 0);

            tag = 0;
            rp_str_set(&s->out, imap_password);
            s->mail_state = rp_imap_auth_login_password;

            break;

        case rp_imap_auth_login_password:
            rc = rp_mail_auth_login_password(s, c);
            break;

        case rp_imap_auth_plain:
            rc = rp_mail_auth_plain(s, c, 0);
            break;

        case rp_imap_auth_cram_md5:
            rc = rp_mail_auth_cram_md5(s, c);
            break;

        case rp_imap_auth_external:
            rc = rp_mail_auth_external(s, c, 0);
            break;
        }

    } else if (rc == RP_IMAP_NEXT) {
        tag = 0;
        rp_str_set(&s->out, imap_next);
    }

    switch (rc) {

    case RP_DONE:
        rp_mail_auth(s, c);
        return;

    case RP_ERROR:
        rp_mail_session_internal_server_error(s);
        return;

    case RP_MAIL_PARSE_INVALID_COMMAND:
        s->state = 0;
        rp_str_set(&s->out, imap_invalid_command);
        s->mail_state = rp_imap_start;
        break;
    }

    if (tag) {
        if (s->tag.len == 0) {
            rp_str_set(&s->tag, imap_star);
        }

        if (s->tagged_line.len < s->tag.len + s->text.len + s->out.len) {
            s->tagged_line.len = s->tag.len + s->text.len + s->out.len;
            s->tagged_line.data = rp_pnalloc(c->pool, s->tagged_line.len);
            if (s->tagged_line.data == NULL) {
                rp_mail_close_connection(c);
                return;
            }
        }

        p = s->tagged_line.data;

        if (s->text.len) {
            p = rp_cpymem(p, s->text.data, s->text.len);
        }

        p = rp_cpymem(p, s->tag.data, s->tag.len);
        rp_memcpy(p, s->out.data, s->out.len);

        s->out.len = s->text.len + s->tag.len + s->out.len;
        s->out.data = s->tagged_line.data;
    }

    if (rc != RP_IMAP_NEXT) {
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

    rp_mail_send(c->write);
}


static rp_int_t
rp_mail_imap_login(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t  *arg;

#if (RP_MAIL_SSL)
    if (rp_mail_starttls_only(s, c)) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    arg = s->args.elts;

    if (s->args.nelts != 2 || arg[0].len == 0) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    s->login.len = arg[0].len;
    s->login.data = rp_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s->login.data, arg[0].data, s->login.len);

    s->passwd.len = arg[1].len;
    s->passwd.data = rp_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s->passwd.data, arg[1].data, s->passwd.len);

#if (RP_DEBUG_MAIL_PASSWD)
    rp_log_debug2(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\" passwd:\"%V\"",
                   &s->login, &s->passwd);
#else
    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "imap login:\"%V\"", &s->login);
#endif

    return RP_DONE;
}


static rp_int_t
rp_mail_imap_authenticate(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_int_t                  rc;
    rp_mail_core_srv_conf_t  *cscf;
    rp_mail_imap_srv_conf_t  *iscf;

#if (RP_MAIL_SSL)
    if (rp_mail_starttls_only(s, c)) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    iscf = rp_mail_get_module_srv_conf(s, rp_mail_imap_module);

    rc = rp_mail_auth_parse(s, c);

    switch (rc) {

    case RP_MAIL_AUTH_LOGIN:

        rp_str_set(&s->out, imap_username);
        s->mail_state = rp_imap_auth_login_username;

        return RP_OK;

    case RP_MAIL_AUTH_LOGIN_USERNAME:

        rp_str_set(&s->out, imap_password);
        s->mail_state = rp_imap_auth_login_password;

        return rp_mail_auth_login_username(s, c, 1);

    case RP_MAIL_AUTH_PLAIN:

        rp_str_set(&s->out, imap_plain_next);
        s->mail_state = rp_imap_auth_plain;

        return RP_OK;

    case RP_MAIL_AUTH_CRAM_MD5:

        if (!(iscf->auth_methods & RP_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return RP_MAIL_PARSE_INVALID_COMMAND;
        }

        if (s->salt.data == NULL) {
            cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

            if (rp_mail_salt(s, c, cscf) != RP_OK) {
                return RP_ERROR;
            }
        }

        if (rp_mail_auth_cram_md5_salt(s, c, "+ ", 2) == RP_OK) {
            s->mail_state = rp_imap_auth_cram_md5;
            return RP_OK;
        }

        return RP_ERROR;

    case RP_MAIL_AUTH_EXTERNAL:

        if (!(iscf->auth_methods & RP_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return RP_MAIL_PARSE_INVALID_COMMAND;
        }

        rp_str_set(&s->out, imap_username);
        s->mail_state = rp_imap_auth_external;

        return RP_OK;
    }

    return rc;
}


static rp_int_t
rp_mail_imap_capability(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_mail_imap_srv_conf_t  *iscf;

    iscf = rp_mail_get_module_srv_conf(s, rp_mail_imap_module);

#if (RP_MAIL_SSL)

    if (c->ssl == NULL) {
        rp_mail_ssl_conf_t  *sslcf;

        sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

        if (sslcf->starttls == RP_MAIL_STARTTLS_ON) {
            s->text = iscf->starttls_capability;
            return RP_OK;
        }

        if (sslcf->starttls == RP_MAIL_STARTTLS_ONLY) {
            s->text = iscf->starttls_only_capability;
            return RP_OK;
        }
    }
#endif

    s->text = iscf->capability;

    return RP_OK;
}


static rp_int_t
rp_mail_imap_starttls(rp_mail_session_t *s, rp_connection_t *c)
{
#if (RP_MAIL_SSL)
    rp_mail_ssl_conf_t  *sslcf;

    if (c->ssl == NULL) {
        sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);
        if (sslcf->starttls) {
            c->read->handler = rp_mail_starttls_handler;
            return RP_OK;
        }
    }

#endif

    return RP_MAIL_PARSE_INVALID_COMMAND;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>
#include <rap_mail_pop3_module.h>


static rap_int_t rap_mail_pop3_user(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_pop3_pass(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_pop3_capa(rap_mail_session_t *s, rap_connection_t *c,
    rap_int_t stls);
static rap_int_t rap_mail_pop3_stls(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_pop3_apop(rap_mail_session_t *s, rap_connection_t *c);
static rap_int_t rap_mail_pop3_auth(rap_mail_session_t *s, rap_connection_t *c);


static u_char  pop3_greeting[] = "+OK POP3 ready" CRLF;
static u_char  pop3_ok[] = "+OK" CRLF;
static u_char  pop3_next[] = "+ " CRLF;
static u_char  pop3_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  pop3_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;


void
rap_mail_pop3_init_session(rap_mail_session_t *s, rap_connection_t *c)
{
    u_char                    *p;
    rap_mail_core_srv_conf_t  *cscf;
    rap_mail_pop3_srv_conf_t  *pscf;

    pscf = rap_mail_get_module_srv_conf(s, rap_mail_pop3_module);
    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    if (pscf->auth_methods
        & (RAP_MAIL_AUTH_APOP_ENABLED|RAP_MAIL_AUTH_CRAM_MD5_ENABLED))
    {
        if (rap_mail_salt(s, c, cscf) != RAP_OK) {
            rap_mail_session_internal_server_error(s);
            return;
        }

        s->out.data = rap_pnalloc(c->pool, sizeof(pop3_greeting) + s->salt.len);
        if (s->out.data == NULL) {
            rap_mail_session_internal_server_error(s);
            return;
        }

        p = rap_cpymem(s->out.data, pop3_greeting, sizeof(pop3_greeting) - 3);
        *p++ = ' ';
        p = rap_cpymem(p, s->salt.data, s->salt.len);

        s->out.len = p - s->out.data;

    } else {
        rap_str_set(&s->out, pop3_greeting);
    }

    c->read->handler = rap_mail_pop3_init_protocol;

    rap_add_timer(c->read, cscf->timeout);

    if (rap_handle_read_event(c->read, 0) != RAP_OK) {
        rap_mail_close_connection(c);
    }

    rap_mail_send(c->write);
}


void
rap_mail_pop3_init_protocol(rap_event_t *rev)
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
        if (rap_array_init(&s->args, c->pool, 2, sizeof(rap_str_t))
            == RAP_ERROR)
        {
            rap_mail_session_internal_server_error(s);
            return;
        }

        s->buffer = rap_create_temp_buf(c->pool, 128);
        if (s->buffer == NULL) {
            rap_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = rap_pop3_start;
    c->read->handler = rap_mail_pop3_auth_state;

    rap_mail_pop3_auth_state(rev);
}


void
rap_mail_pop3_auth_state(rap_event_t *rev)
{
    rap_int_t            rc;
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "pop3 auth state");

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rap_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, c->log, 0, "pop3 send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = rap_mail_read_command(s, c);

    if (rc == RAP_AGAIN || rc == RAP_ERROR) {
        return;
    }

    rap_str_set(&s->out, pop3_ok);

    if (rc == RAP_OK) {
        switch (s->mail_state) {

        case rap_pop3_start:

            switch (s->command) {

            case RAP_POP3_USER:
                rc = rap_mail_pop3_user(s, c);
                break;

            case RAP_POP3_CAPA:
                rc = rap_mail_pop3_capa(s, c, 1);
                break;

            case RAP_POP3_APOP:
                rc = rap_mail_pop3_apop(s, c);
                break;

            case RAP_POP3_AUTH:
                rc = rap_mail_pop3_auth(s, c);
                break;

            case RAP_POP3_QUIT:
                s->quit = 1;
                break;

            case RAP_POP3_NOOP:
                break;

            case RAP_POP3_STLS:
                rc = rap_mail_pop3_stls(s, c);
                break;

            default:
                rc = RAP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case rap_pop3_user:

            switch (s->command) {

            case RAP_POP3_PASS:
                rc = rap_mail_pop3_pass(s, c);
                break;

            case RAP_POP3_CAPA:
                rc = rap_mail_pop3_capa(s, c, 0);
                break;

            case RAP_POP3_QUIT:
                s->quit = 1;
                break;

            case RAP_POP3_NOOP:
                break;

            default:
                rc = RAP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        /* suppress warnings */
        case rap_pop3_passwd:
            break;

        case rap_pop3_auth_login_username:
            rc = rap_mail_auth_login_username(s, c, 0);

            rap_str_set(&s->out, pop3_password);
            s->mail_state = rap_pop3_auth_login_password;
            break;

        case rap_pop3_auth_login_password:
            rc = rap_mail_auth_login_password(s, c);
            break;

        case rap_pop3_auth_plain:
            rc = rap_mail_auth_plain(s, c, 0);
            break;

        case rap_pop3_auth_cram_md5:
            rc = rap_mail_auth_cram_md5(s, c);
            break;

        case rap_pop3_auth_external:
            rc = rap_mail_auth_external(s, c, 0);
            break;
        }
    }

    switch (rc) {

    case RAP_DONE:
        rap_mail_auth(s, c);
        return;

    case RAP_ERROR:
        rap_mail_session_internal_server_error(s);
        return;

    case RAP_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = rap_pop3_start;
        s->state = 0;

        rap_str_set(&s->out, pop3_invalid_command);

        /* fall through */

    case RAP_OK:

        s->args.nelts = 0;
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;

        if (s->state) {
            s->arg_start = s->buffer->start;
        }

        rap_mail_send(c->write);
    }
}

static rap_int_t
rap_mail_pop3_user(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t  *arg;

#if (RAP_MAIL_SSL)
    if (rap_mail_starttls_only(s, c)) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 1) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    s->login.len = arg[0].len;
    s->login.data = rap_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->login.data, arg[0].data, s->login.len);

    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 login: \"%V\"", &s->login);

    s->mail_state = rap_pop3_user;

    return RAP_OK;
}


static rap_int_t
rap_mail_pop3_pass(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t  *arg;

    if (s->args.nelts != 1) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    s->passwd.len = arg[0].len;
    s->passwd.data = rap_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s->passwd.data, arg[0].data, s->passwd.len);

#if (RAP_DEBUG_MAIL_PASSWD)
    rap_log_debug1(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 passwd: \"%V\"", &s->passwd);
#endif

    return RAP_DONE;
}


static rap_int_t
rap_mail_pop3_capa(rap_mail_session_t *s, rap_connection_t *c, rap_int_t stls)
{
    rap_mail_pop3_srv_conf_t  *pscf;

    pscf = rap_mail_get_module_srv_conf(s, rap_mail_pop3_module);

#if (RAP_MAIL_SSL)

    if (stls && c->ssl == NULL) {
        rap_mail_ssl_conf_t  *sslcf;

        sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

        if (sslcf->starttls == RAP_MAIL_STARTTLS_ON) {
            s->out = pscf->starttls_capability;
            return RAP_OK;
        }

        if (sslcf->starttls == RAP_MAIL_STARTTLS_ONLY) {
            s->out = pscf->starttls_only_capability;
            return RAP_OK;
        }
    }

#endif

    s->out = pscf->capability;
    return RAP_OK;
}


static rap_int_t
rap_mail_pop3_stls(rap_mail_session_t *s, rap_connection_t *c)
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


static rap_int_t
rap_mail_pop3_apop(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_str_t                 *arg;
    rap_mail_pop3_srv_conf_t  *pscf;

#if (RAP_MAIL_SSL)
    if (rap_mail_starttls_only(s, c)) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 2) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    pscf = rap_mail_get_module_srv_conf(s, rap_mail_pop3_module);

    if (!(pscf->auth_methods & RAP_MAIL_AUTH_APOP_ENABLED)) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

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

    rap_log_debug2(RAP_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 apop: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = RAP_MAIL_AUTH_APOP;

    return RAP_DONE;
}


static rap_int_t
rap_mail_pop3_auth(rap_mail_session_t *s, rap_connection_t *c)
{
    rap_int_t                  rc;
    rap_mail_pop3_srv_conf_t  *pscf;

#if (RAP_MAIL_SSL)
    if (rap_mail_starttls_only(s, c)) {
        return RAP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    pscf = rap_mail_get_module_srv_conf(s, rap_mail_pop3_module);

    if (s->args.nelts == 0) {
        s->out = pscf->auth_capability;
        s->state = 0;

        return RAP_OK;
    }

    rc = rap_mail_auth_parse(s, c);

    switch (rc) {

    case RAP_MAIL_AUTH_LOGIN:

        rap_str_set(&s->out, pop3_username);
        s->mail_state = rap_pop3_auth_login_username;

        return RAP_OK;

    case RAP_MAIL_AUTH_LOGIN_USERNAME:

        rap_str_set(&s->out, pop3_password);
        s->mail_state = rap_pop3_auth_login_password;

        return rap_mail_auth_login_username(s, c, 1);

    case RAP_MAIL_AUTH_PLAIN:

        rap_str_set(&s->out, pop3_next);
        s->mail_state = rap_pop3_auth_plain;

        return RAP_OK;

    case RAP_MAIL_AUTH_CRAM_MD5:

        if (!(pscf->auth_methods & RAP_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return RAP_MAIL_PARSE_INVALID_COMMAND;
        }

        if (rap_mail_auth_cram_md5_salt(s, c, "+ ", 2) == RAP_OK) {
            s->mail_state = rap_pop3_auth_cram_md5;
            return RAP_OK;
        }

        return RAP_ERROR;

    case RAP_MAIL_AUTH_EXTERNAL:

        if (!(pscf->auth_methods & RAP_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return RAP_MAIL_PARSE_INVALID_COMMAND;
        }

        rap_str_set(&s->out, pop3_username);
        s->mail_state = rap_pop3_auth_external;

        return RAP_OK;
    }

    return rc;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>
#include <rp_mail_pop3_module.h>


static rp_int_t rp_mail_pop3_user(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_pop3_pass(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_pop3_capa(rp_mail_session_t *s, rp_connection_t *c,
    rp_int_t stls);
static rp_int_t rp_mail_pop3_stls(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_pop3_apop(rp_mail_session_t *s, rp_connection_t *c);
static rp_int_t rp_mail_pop3_auth(rp_mail_session_t *s, rp_connection_t *c);


static u_char  pop3_greeting[] = "+OK POP3 ready" CRLF;
static u_char  pop3_ok[] = "+OK" CRLF;
static u_char  pop3_next[] = "+ " CRLF;
static u_char  pop3_username[] = "+ VXNlcm5hbWU6" CRLF;
static u_char  pop3_password[] = "+ UGFzc3dvcmQ6" CRLF;
static u_char  pop3_invalid_command[] = "-ERR invalid command" CRLF;


void
rp_mail_pop3_init_session(rp_mail_session_t *s, rp_connection_t *c)
{
    u_char                    *p;
    rp_mail_core_srv_conf_t  *cscf;
    rp_mail_pop3_srv_conf_t  *pscf;

    pscf = rp_mail_get_module_srv_conf(s, rp_mail_pop3_module);
    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    if (pscf->auth_methods
        & (RP_MAIL_AUTH_APOP_ENABLED|RP_MAIL_AUTH_CRAM_MD5_ENABLED))
    {
        if (rp_mail_salt(s, c, cscf) != RP_OK) {
            rp_mail_session_internal_server_error(s);
            return;
        }

        s->out.data = rp_pnalloc(c->pool, sizeof(pop3_greeting) + s->salt.len);
        if (s->out.data == NULL) {
            rp_mail_session_internal_server_error(s);
            return;
        }

        p = rp_cpymem(s->out.data, pop3_greeting, sizeof(pop3_greeting) - 3);
        *p++ = ' ';
        p = rp_cpymem(p, s->salt.data, s->salt.len);

        s->out.len = p - s->out.data;

    } else {
        rp_str_set(&s->out, pop3_greeting);
    }

    c->read->handler = rp_mail_pop3_init_protocol;

    rp_add_timer(c->read, cscf->timeout);

    if (rp_handle_read_event(c->read, 0) != RP_OK) {
        rp_mail_close_connection(c);
    }

    rp_mail_send(c->write);
}


void
rp_mail_pop3_init_protocol(rp_event_t *rev)
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
        if (rp_array_init(&s->args, c->pool, 2, sizeof(rp_str_t))
            == RP_ERROR)
        {
            rp_mail_session_internal_server_error(s);
            return;
        }

        s->buffer = rp_create_temp_buf(c->pool, 128);
        if (s->buffer == NULL) {
            rp_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = rp_pop3_start;
    c->read->handler = rp_mail_pop3_auth_state;

    rp_mail_pop3_auth_state(rev);
}


void
rp_mail_pop3_auth_state(rp_event_t *rev)
{
    rp_int_t            rc;
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    c = rev->data;
    s = c->data;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "pop3 auth state");

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        rp_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        rp_log_debug0(RP_LOG_DEBUG_MAIL, c->log, 0, "pop3 send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = rp_mail_read_command(s, c);

    if (rc == RP_AGAIN || rc == RP_ERROR) {
        return;
    }

    rp_str_set(&s->out, pop3_ok);

    if (rc == RP_OK) {
        switch (s->mail_state) {

        case rp_pop3_start:

            switch (s->command) {

            case RP_POP3_USER:
                rc = rp_mail_pop3_user(s, c);
                break;

            case RP_POP3_CAPA:
                rc = rp_mail_pop3_capa(s, c, 1);
                break;

            case RP_POP3_APOP:
                rc = rp_mail_pop3_apop(s, c);
                break;

            case RP_POP3_AUTH:
                rc = rp_mail_pop3_auth(s, c);
                break;

            case RP_POP3_QUIT:
                s->quit = 1;
                break;

            case RP_POP3_NOOP:
                break;

            case RP_POP3_STLS:
                rc = rp_mail_pop3_stls(s, c);
                break;

            default:
                rc = RP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case rp_pop3_user:

            switch (s->command) {

            case RP_POP3_PASS:
                rc = rp_mail_pop3_pass(s, c);
                break;

            case RP_POP3_CAPA:
                rc = rp_mail_pop3_capa(s, c, 0);
                break;

            case RP_POP3_QUIT:
                s->quit = 1;
                break;

            case RP_POP3_NOOP:
                break;

            default:
                rc = RP_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        /* suppress warnings */
        case rp_pop3_passwd:
            break;

        case rp_pop3_auth_login_username:
            rc = rp_mail_auth_login_username(s, c, 0);

            rp_str_set(&s->out, pop3_password);
            s->mail_state = rp_pop3_auth_login_password;
            break;

        case rp_pop3_auth_login_password:
            rc = rp_mail_auth_login_password(s, c);
            break;

        case rp_pop3_auth_plain:
            rc = rp_mail_auth_plain(s, c, 0);
            break;

        case rp_pop3_auth_cram_md5:
            rc = rp_mail_auth_cram_md5(s, c);
            break;

        case rp_pop3_auth_external:
            rc = rp_mail_auth_external(s, c, 0);
            break;
        }
    }

    switch (rc) {

    case RP_DONE:
        rp_mail_auth(s, c);
        return;

    case RP_ERROR:
        rp_mail_session_internal_server_error(s);
        return;

    case RP_MAIL_PARSE_INVALID_COMMAND:
        s->mail_state = rp_pop3_start;
        s->state = 0;

        rp_str_set(&s->out, pop3_invalid_command);

        /* fall through */

    case RP_OK:

        s->args.nelts = 0;
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;

        if (s->state) {
            s->arg_start = s->buffer->start;
        }

        rp_mail_send(c->write);
    }
}

static rp_int_t
rp_mail_pop3_user(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t  *arg;

#if (RP_MAIL_SSL)
    if (rp_mail_starttls_only(s, c)) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 1) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    s->login.len = arg[0].len;
    s->login.data = rp_pnalloc(c->pool, s->login.len);
    if (s->login.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s->login.data, arg[0].data, s->login.len);

    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 login: \"%V\"", &s->login);

    s->mail_state = rp_pop3_user;

    return RP_OK;
}


static rp_int_t
rp_mail_pop3_pass(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t  *arg;

    if (s->args.nelts != 1) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    s->passwd.len = arg[0].len;
    s->passwd.data = rp_pnalloc(c->pool, s->passwd.len);
    if (s->passwd.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s->passwd.data, arg[0].data, s->passwd.len);

#if (RP_DEBUG_MAIL_PASSWD)
    rp_log_debug1(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 passwd: \"%V\"", &s->passwd);
#endif

    return RP_DONE;
}


static rp_int_t
rp_mail_pop3_capa(rp_mail_session_t *s, rp_connection_t *c, rp_int_t stls)
{
    rp_mail_pop3_srv_conf_t  *pscf;

    pscf = rp_mail_get_module_srv_conf(s, rp_mail_pop3_module);

#if (RP_MAIL_SSL)

    if (stls && c->ssl == NULL) {
        rp_mail_ssl_conf_t  *sslcf;

        sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

        if (sslcf->starttls == RP_MAIL_STARTTLS_ON) {
            s->out = pscf->starttls_capability;
            return RP_OK;
        }

        if (sslcf->starttls == RP_MAIL_STARTTLS_ONLY) {
            s->out = pscf->starttls_only_capability;
            return RP_OK;
        }
    }

#endif

    s->out = pscf->capability;
    return RP_OK;
}


static rp_int_t
rp_mail_pop3_stls(rp_mail_session_t *s, rp_connection_t *c)
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


static rp_int_t
rp_mail_pop3_apop(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_str_t                 *arg;
    rp_mail_pop3_srv_conf_t  *pscf;

#if (RP_MAIL_SSL)
    if (rp_mail_starttls_only(s, c)) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    if (s->args.nelts != 2) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    pscf = rp_mail_get_module_srv_conf(s, rp_mail_pop3_module);

    if (!(pscf->auth_methods & RP_MAIL_AUTH_APOP_ENABLED)) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;

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

    rp_log_debug2(RP_LOG_DEBUG_MAIL, c->log, 0,
                   "pop3 apop: \"%V\" \"%V\"", &s->login, &s->passwd);

    s->auth_method = RP_MAIL_AUTH_APOP;

    return RP_DONE;
}


static rp_int_t
rp_mail_pop3_auth(rp_mail_session_t *s, rp_connection_t *c)
{
    rp_int_t                  rc;
    rp_mail_pop3_srv_conf_t  *pscf;

#if (RP_MAIL_SSL)
    if (rp_mail_starttls_only(s, c)) {
        return RP_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    pscf = rp_mail_get_module_srv_conf(s, rp_mail_pop3_module);

    if (s->args.nelts == 0) {
        s->out = pscf->auth_capability;
        s->state = 0;

        return RP_OK;
    }

    rc = rp_mail_auth_parse(s, c);

    switch (rc) {

    case RP_MAIL_AUTH_LOGIN:

        rp_str_set(&s->out, pop3_username);
        s->mail_state = rp_pop3_auth_login_username;

        return RP_OK;

    case RP_MAIL_AUTH_LOGIN_USERNAME:

        rp_str_set(&s->out, pop3_password);
        s->mail_state = rp_pop3_auth_login_password;

        return rp_mail_auth_login_username(s, c, 1);

    case RP_MAIL_AUTH_PLAIN:

        rp_str_set(&s->out, pop3_next);
        s->mail_state = rp_pop3_auth_plain;

        return RP_OK;

    case RP_MAIL_AUTH_CRAM_MD5:

        if (!(pscf->auth_methods & RP_MAIL_AUTH_CRAM_MD5_ENABLED)) {
            return RP_MAIL_PARSE_INVALID_COMMAND;
        }

        if (rp_mail_auth_cram_md5_salt(s, c, "+ ", 2) == RP_OK) {
            s->mail_state = rp_pop3_auth_cram_md5;
            return RP_OK;
        }

        return RP_ERROR;

    case RP_MAIL_AUTH_EXTERNAL:

        if (!(pscf->auth_methods & RP_MAIL_AUTH_EXTERNAL_ENABLED)) {
            return RP_MAIL_PARSE_INVALID_COMMAND;
        }

        rp_str_set(&s->out, pop3_username);
        s->mail_state = rp_pop3_auth_external;

        return RP_OK;
    }

    return rc;
}

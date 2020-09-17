
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_event_connect.h>
#include <rp_mail.h>


typedef struct {
    rp_flag_t  enable;
    rp_flag_t  pass_error_message;
    rp_flag_t  xclient;
    size_t      buffer_size;
    rp_msec_t  timeout;
} rp_mail_proxy_conf_t;


static void rp_mail_proxy_block_read(rp_event_t *rev);
static void rp_mail_proxy_pop3_handler(rp_event_t *rev);
static void rp_mail_proxy_imap_handler(rp_event_t *rev);
static void rp_mail_proxy_smtp_handler(rp_event_t *rev);
static void rp_mail_proxy_dummy_handler(rp_event_t *ev);
static rp_int_t rp_mail_proxy_read_response(rp_mail_session_t *s,
    rp_uint_t state);
static void rp_mail_proxy_handler(rp_event_t *ev);
static void rp_mail_proxy_upstream_error(rp_mail_session_t *s);
static void rp_mail_proxy_internal_server_error(rp_mail_session_t *s);
static void rp_mail_proxy_close_session(rp_mail_session_t *s);
static void *rp_mail_proxy_create_conf(rp_conf_t *cf);
static char *rp_mail_proxy_merge_conf(rp_conf_t *cf, void *parent,
    void *child);


static rp_command_t  rp_mail_proxy_commands[] = {

    { rp_string("proxy"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_proxy_conf_t, enable),
      NULL },

    { rp_string("proxy_buffer"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_proxy_conf_t, buffer_size),
      NULL },

    { rp_string("proxy_timeout"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_proxy_conf_t, timeout),
      NULL },

    { rp_string("proxy_pass_error_message"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_proxy_conf_t, pass_error_message),
      NULL },

    { rp_string("xclient"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_proxy_conf_t, xclient),
      NULL },

      rp_null_command
};


static rp_mail_module_t  rp_mail_proxy_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_mail_proxy_create_conf,            /* create server configuration */
    rp_mail_proxy_merge_conf              /* merge server configuration */
};


rp_module_t  rp_mail_proxy_module = {
    RP_MODULE_V1,
    &rp_mail_proxy_module_ctx,            /* module context */
    rp_mail_proxy_commands,               /* module directives */
    RP_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static u_char  smtp_auth_ok[] = "235 2.0.0 OK" CRLF;


void
rp_mail_proxy_init(rp_mail_session_t *s, rp_addr_t *peer)
{
    rp_int_t                  rc;
    rp_mail_proxy_ctx_t      *p;
    rp_mail_proxy_conf_t     *pcf;
    rp_mail_core_srv_conf_t  *cscf;

    s->connection->log->action = "connecting to upstream";

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    p = rp_pcalloc(s->connection->pool, sizeof(rp_mail_proxy_ctx_t));
    if (p == NULL) {
        rp_mail_session_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->upstream.sockaddr = peer->sockaddr;
    p->upstream.socklen = peer->socklen;
    p->upstream.name = &peer->name;
    p->upstream.get = rp_event_get_peer;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = RP_ERROR_ERR;

    rc = rp_event_connect_peer(&p->upstream);

    if (rc == RP_ERROR || rc == RP_BUSY || rc == RP_DECLINED) {
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    rp_add_timer(p->upstream.connection->read, cscf->timeout);

    p->upstream.connection->data = s;
    p->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = rp_mail_proxy_block_read;
    p->upstream.connection->write->handler = rp_mail_proxy_dummy_handler;

    pcf = rp_mail_get_module_srv_conf(s, rp_mail_proxy_module);

    s->proxy->buffer = rp_create_temp_buf(s->connection->pool,
                                           pcf->buffer_size);
    if (s->proxy->buffer == NULL) {
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    s->out.len = 0;

    switch (s->protocol) {

    case RP_MAIL_POP3_PROTOCOL:
        p->upstream.connection->read->handler = rp_mail_proxy_pop3_handler;
        s->mail_state = rp_pop3_start;
        break;

    case RP_MAIL_IMAP_PROTOCOL:
        p->upstream.connection->read->handler = rp_mail_proxy_imap_handler;
        s->mail_state = rp_imap_start;
        break;

    default: /* RP_MAIL_SMTP_PROTOCOL */
        p->upstream.connection->read->handler = rp_mail_proxy_smtp_handler;
        s->mail_state = rp_smtp_start;
        break;
    }
}


static void
rp_mail_proxy_block_read(rp_event_t *rev)
{
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy block read");

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        c = rev->data;
        s = c->data;

        rp_mail_proxy_close_session(s);
    }
}


static void
rp_mail_proxy_pop3_handler(rp_event_t *rev)
{
    u_char                 *p;
    rp_int_t               rc;
    rp_str_t               line;
    rp_connection_t       *c;
    rp_mail_session_t     *s;
    rp_mail_proxy_conf_t  *pcf;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy pop3 auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    rc = rp_mail_proxy_read_response(s, 0);

    if (rc == RP_AGAIN) {
        return;
    }

    if (rc == RP_ERROR) {
        rp_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case rp_pop3_start:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = sizeof("USER ")  - 1 + s->login.len + 2;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        p = rp_cpymem(line.data, "USER ", sizeof("USER ") - 1);
        p = rp_cpymem(p, s->login.data, s->login.len);
        *p++ = CR; *p = LF;

        s->mail_state = rp_pop3_user;
        break;

    case rp_pop3_user:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send pass");

        s->connection->log->action = "sending password to upstream";

        line.len = sizeof("PASS ")  - 1 + s->passwd.len + 2;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        p = rp_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
        p = rp_cpymem(p, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = rp_pop3_passwd;
        break;

    case rp_pop3_passwd:
        s->connection->read->handler = rp_mail_proxy_handler;
        s->connection->write->handler = rp_mail_proxy_handler;
        rev->handler = rp_mail_proxy_handler;
        c->write->handler = rp_mail_proxy_handler;

        pcf = rp_mail_get_module_srv_conf(s, rp_mail_proxy_module);
        rp_add_timer(s->connection->read, pcf->timeout);
        rp_del_timer(c->read);

        c->log->action = NULL;
        rp_log_error(RP_LOG_INFO, c->log, 0, "client logged in");

        rp_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (RP_SUPPRESS_WARN)
        rp_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as RP_ERROR
         * because it is very strange here
         */
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
rp_mail_proxy_imap_handler(rp_event_t *rev)
{
    u_char                 *p;
    rp_int_t               rc;
    rp_str_t               line;
    rp_connection_t       *c;
    rp_mail_session_t     *s;
    rp_mail_proxy_conf_t  *pcf;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy imap auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    rc = rp_mail_proxy_read_response(s, s->mail_state);

    if (rc == RP_AGAIN) {
        return;
    }

    if (rc == RP_ERROR) {
        rp_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case rp_imap_start:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send login");

        s->connection->log->action = "sending LOGIN command to upstream";

        line.len = s->tag.len + sizeof("LOGIN ") - 1
                   + 1 + RP_SIZE_T_LEN + 1 + 2;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = rp_sprintf(line.data, "%VLOGIN {%uz}" CRLF,
                               &s->tag, s->login.len)
                   - line.data;

        s->mail_state = rp_imap_login;
        break;

    case rp_imap_login:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = s->login.len + 1 + 1 + RP_SIZE_T_LEN + 1 + 2;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = rp_sprintf(line.data, "%V {%uz}" CRLF,
                               &s->login, s->passwd.len)
                   - line.data;

        s->mail_state = rp_imap_user;
        break;

    case rp_imap_user:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send passwd");

        s->connection->log->action = "sending password to upstream";

        line.len = s->passwd.len + 2;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        p = rp_cpymem(line.data, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = rp_imap_passwd;
        break;

    case rp_imap_passwd:
        s->connection->read->handler = rp_mail_proxy_handler;
        s->connection->write->handler = rp_mail_proxy_handler;
        rev->handler = rp_mail_proxy_handler;
        c->write->handler = rp_mail_proxy_handler;

        pcf = rp_mail_get_module_srv_conf(s, rp_mail_proxy_module);
        rp_add_timer(s->connection->read, pcf->timeout);
        rp_del_timer(c->read);

        c->log->action = NULL;
        rp_log_error(RP_LOG_INFO, c->log, 0, "client logged in");

        rp_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (RP_SUPPRESS_WARN)
        rp_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as RP_ERROR
         * because it is very strange here
         */
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
rp_mail_proxy_smtp_handler(rp_event_t *rev)
{
    u_char                    *p;
    rp_int_t                  rc;
    rp_str_t                  line;
    rp_buf_t                 *b;
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_mail_proxy_conf_t     *pcf;
    rp_mail_core_srv_conf_t  *cscf;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy smtp auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    rc = rp_mail_proxy_read_response(s, s->mail_state);

    if (rc == RP_AGAIN) {
        return;
    }

    if (rc == RP_ERROR) {
        rp_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case rp_smtp_start:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send ehlo");

        s->connection->log->action = "sending HELO/EHLO to upstream";

        cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

        line.len = sizeof("HELO ")  - 1 + cscf->server_name.len + 2;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        pcf = rp_mail_get_module_srv_conf(s, rp_mail_proxy_module);

        p = rp_cpymem(line.data,
                       ((s->esmtp || pcf->xclient) ? "EHLO " : "HELO "),
                       sizeof("HELO ") - 1);

        p = rp_cpymem(p, cscf->server_name.data, cscf->server_name.len);
        *p++ = CR; *p = LF;

        if (pcf->xclient) {
            s->mail_state = rp_smtp_helo_xclient;

        } else if (s->auth_method == RP_MAIL_AUTH_NONE) {
            s->mail_state = rp_smtp_helo_from;

        } else {
            s->mail_state = rp_smtp_helo;
        }

        break;

    case rp_smtp_helo_xclient:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send xclient");

        s->connection->log->action = "sending XCLIENT to upstream";

        line.len = sizeof("XCLIENT ADDR= LOGIN= NAME="
                          CRLF) - 1
                   + s->connection->addr_text.len + s->login.len + s->host.len;

#if (RP_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            line.len += sizeof("IPV6:") - 1;
        }
#endif

        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        p = rp_cpymem(line.data, "XCLIENT ADDR=", sizeof("XCLIENT ADDR=") - 1);

#if (RP_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            p = rp_cpymem(p, "IPV6:", sizeof("IPV6:") - 1);
        }
#endif

        p = rp_copy(p, s->connection->addr_text.data,
                     s->connection->addr_text.len);

        if (s->login.len) {
            p = rp_cpymem(p, " LOGIN=", sizeof(" LOGIN=") - 1);
            p = rp_copy(p, s->login.data, s->login.len);
        }

        p = rp_cpymem(p, " NAME=", sizeof(" NAME=") - 1);
        p = rp_copy(p, s->host.data, s->host.len);

        *p++ = CR; *p++ = LF;

        line.len = p - line.data;

        if (s->smtp_helo.len) {
            s->mail_state = rp_smtp_xclient_helo;

        } else if (s->auth_method == RP_MAIL_AUTH_NONE) {
            s->mail_state = rp_smtp_xclient_from;

        } else {
            s->mail_state = rp_smtp_xclient;
        }

        break;

    case rp_smtp_xclient_helo:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send client ehlo");

        s->connection->log->action = "sending client HELO/EHLO to upstream";

        line.len = sizeof("HELO " CRLF) - 1 + s->smtp_helo.len;

        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = rp_sprintf(line.data,
                       ((s->esmtp) ? "EHLO %V" CRLF : "HELO %V" CRLF),
                       &s->smtp_helo)
                   - line.data;

        s->mail_state = (s->auth_method == RP_MAIL_AUTH_NONE) ?
                            rp_smtp_helo_from : rp_smtp_helo;

        break;

    case rp_smtp_helo_from:
    case rp_smtp_xclient_from:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send mail from");

        s->connection->log->action = "sending MAIL FROM to upstream";

        line.len = s->smtp_from.len + sizeof(CRLF) - 1;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        p = rp_cpymem(line.data, s->smtp_from.data, s->smtp_from.len);
        *p++ = CR; *p = LF;

        s->mail_state = rp_smtp_from;

        break;

    case rp_smtp_from:
        rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send rcpt to");

        s->connection->log->action = "sending RCPT TO to upstream";

        line.len = s->smtp_to.len + sizeof(CRLF) - 1;
        line.data = rp_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rp_mail_proxy_internal_server_error(s);
            return;
        }

        p = rp_cpymem(line.data, s->smtp_to.data, s->smtp_to.len);
        *p++ = CR; *p = LF;

        s->mail_state = rp_smtp_to;

        break;

    case rp_smtp_helo:
    case rp_smtp_xclient:
    case rp_smtp_to:

        b = s->proxy->buffer;

        if (s->auth_method == RP_MAIL_AUTH_NONE) {
            b->pos = b->start;

        } else {
            rp_memcpy(b->start, smtp_auth_ok, sizeof(smtp_auth_ok) - 1);
            b->last = b->start + sizeof(smtp_auth_ok) - 1;
        }

        s->connection->read->handler = rp_mail_proxy_handler;
        s->connection->write->handler = rp_mail_proxy_handler;
        rev->handler = rp_mail_proxy_handler;
        c->write->handler = rp_mail_proxy_handler;

        pcf = rp_mail_get_module_srv_conf(s, rp_mail_proxy_module);
        rp_add_timer(s->connection->read, pcf->timeout);
        rp_del_timer(c->read);

        c->log->action = NULL;
        rp_log_error(RP_LOG_INFO, c->log, 0, "client logged in");

        if (s->buffer->pos == s->buffer->last) {
            rp_mail_proxy_handler(s->connection->write);

        } else {
            rp_mail_proxy_handler(c->write);
        }

        return;

    default:
#if (RP_SUPPRESS_WARN)
        rp_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as RP_ERROR
         * because it is very strange here
         */
        rp_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
rp_mail_proxy_dummy_handler(rp_event_t *wev)
{
    rp_connection_t    *c;
    rp_mail_session_t  *s;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy dummy handler");

    if (rp_handle_write_event(wev, 0) != RP_OK) {
        c = wev->data;
        s = c->data;

        rp_mail_proxy_close_session(s);
    }
}


static rp_int_t
rp_mail_proxy_read_response(rp_mail_session_t *s, rp_uint_t state)
{
    u_char                 *p, *m;
    ssize_t                 n;
    rp_buf_t              *b;
    rp_mail_proxy_conf_t  *pcf;

    s->connection->log->action = "reading response from upstream";

    b = s->proxy->buffer;

    n = s->proxy->upstream.connection->recv(s->proxy->upstream.connection,
                                            b->last, b->end - b->last);

    if (n == RP_ERROR || n == 0) {
        return RP_ERROR;
    }

    if (n == RP_AGAIN) {
        return RP_AGAIN;
    }

    b->last += n;

    if (b->last - b->pos < 4) {
        return RP_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                          "upstream sent too long response line: \"%s\"",
                          b->pos);
            return RP_ERROR;
        }

        return RP_AGAIN;
    }

    p = b->pos;

    switch (s->protocol) {

    case RP_MAIL_POP3_PROTOCOL:
        if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
            return RP_OK;
        }
        break;

    case RP_MAIL_IMAP_PROTOCOL:
        switch (state) {

        case rp_imap_start:
            if (p[0] == '*' && p[1] == ' ' && p[2] == 'O' && p[3] == 'K') {
                return RP_OK;
            }
            break;

        case rp_imap_login:
        case rp_imap_user:
            if (p[0] == '+') {
                return RP_OK;
            }
            break;

        case rp_imap_passwd:
            if (rp_strncmp(p, s->tag.data, s->tag.len) == 0) {
                p += s->tag.len;
                if (p[0] == 'O' && p[1] == 'K') {
                    return RP_OK;
                }
            }
            break;
        }

        break;

    default: /* RP_MAIL_SMTP_PROTOCOL */

        if (p[3] == '-') {
            /* multiline reply, check if we got last line */

            m = b->last - (sizeof(CRLF "200" CRLF) - 1);

            while (m > p) {
                if (m[0] == CR && m[1] == LF) {
                    break;
                }

                m--;
            }

            if (m <= p || m[5] == '-') {
                return RP_AGAIN;
            }
        }

        switch (state) {

        case rp_smtp_start:
            if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
                return RP_OK;
            }
            break;

        case rp_smtp_helo:
        case rp_smtp_helo_xclient:
        case rp_smtp_helo_from:
        case rp_smtp_from:
            if (p[0] == '2' && p[1] == '5' && p[2] == '0') {
                return RP_OK;
            }
            break;

        case rp_smtp_xclient:
        case rp_smtp_xclient_from:
        case rp_smtp_xclient_helo:
            if (p[0] == '2' && (p[1] == '2' || p[1] == '5') && p[2] == '0') {
                return RP_OK;
            }
            break;

        case rp_smtp_to:
            return RP_OK;
        }

        break;
    }

    pcf = rp_mail_get_module_srv_conf(s, rp_mail_proxy_module);

    if (pcf->pass_error_message == 0) {
        *(b->last - 2) = '\0';
        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid response: \"%s\"", p);
        return RP_ERROR;
    }

    s->out.len = b->last - p - 2;
    s->out.data = p;

    rp_log_error(RP_LOG_INFO, s->connection->log, 0,
                  "upstream sent invalid response: \"%V\"", &s->out);

    s->out.len = b->last - b->pos;
    s->out.data = b->pos;

    return RP_ERROR;
}


static void
rp_mail_proxy_handler(rp_event_t *ev)
{
    char                   *action, *recv_action, *send_action;
    size_t                  size;
    ssize_t                 n;
    rp_buf_t              *b;
    rp_uint_t              do_write;
    rp_connection_t       *c, *src, *dst;
    rp_mail_session_t     *s;
    rp_mail_proxy_conf_t  *pcf;

    c = ev->data;
    s = c->data;

    if (ev->timedout || c->close) {
        c->log->action = "proxying";

        if (c->close) {
            rp_log_error(RP_LOG_INFO, c->log, 0, "shutdown timeout");

        } else if (c == s->connection) {
            rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

        } else {
            rp_log_error(RP_LOG_INFO, c->log, RP_ETIMEDOUT,
                          "upstream timed out");
        }

        rp_mail_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        if (ev->write) {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = s->proxy->upstream.connection;
            dst = c;
            b = s->proxy->buffer;

        } else {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = c;
            dst = s->proxy->upstream.connection;
            b = s->buffer;
        }

    } else {
        if (ev->write) {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = s->connection;
            dst = c;
            b = s->buffer;

        } else {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = c;
            dst = s->connection;
            b = s->proxy->buffer;
        }
    }

    do_write = ev->write ? 1 : 0;

    rp_log_debug3(RP_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail proxy handler: %ui, #%d > #%d",
                   do_write, src->fd, dst->fd);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);

                if (n == RP_ERROR) {
                    rp_mail_proxy_close_session(s);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {
            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == RP_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                continue;
            }

            if (n == RP_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    c->log->action = "proxying";

    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
        || (s->proxy->upstream.connection->read->eof
            && s->proxy->buffer->pos == s->proxy->buffer->last)
        || (s->connection->read->eof
            && s->proxy->upstream.connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        rp_log_error(RP_LOG_INFO, c->log, 0, "proxied session done");
        c->log->action = action;

        rp_mail_proxy_close_session(s);
        return;
    }

    if (rp_handle_write_event(dst->write, 0) != RP_OK) {
        rp_mail_proxy_close_session(s);
        return;
    }

    if (rp_handle_read_event(dst->read, 0) != RP_OK) {
        rp_mail_proxy_close_session(s);
        return;
    }

    if (rp_handle_write_event(src->write, 0) != RP_OK) {
        rp_mail_proxy_close_session(s);
        return;
    }

    if (rp_handle_read_event(src->read, 0) != RP_OK) {
        rp_mail_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        pcf = rp_mail_get_module_srv_conf(s, rp_mail_proxy_module);
        rp_add_timer(c->read, pcf->timeout);
    }
}


static void
rp_mail_proxy_upstream_error(rp_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        rp_log_debug1(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        rp_close_connection(s->proxy->upstream.connection);
    }

    if (s->out.len == 0) {
        rp_mail_session_internal_server_error(s);
        return;
    }

    s->quit = 1;
    rp_mail_send(s->connection->write);
}


static void
rp_mail_proxy_internal_server_error(rp_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        rp_log_debug1(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        rp_close_connection(s->proxy->upstream.connection);
    }

    rp_mail_session_internal_server_error(s);
}


static void
rp_mail_proxy_close_session(rp_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        rp_log_debug1(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        rp_close_connection(s->proxy->upstream.connection);
    }

    rp_mail_close_connection(s->connection);
}


static void *
rp_mail_proxy_create_conf(rp_conf_t *cf)
{
    rp_mail_proxy_conf_t  *pcf;

    pcf = rp_pcalloc(cf->pool, sizeof(rp_mail_proxy_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->enable = RP_CONF_UNSET;
    pcf->pass_error_message = RP_CONF_UNSET;
    pcf->xclient = RP_CONF_UNSET;
    pcf->buffer_size = RP_CONF_UNSET_SIZE;
    pcf->timeout = RP_CONF_UNSET_MSEC;

    return pcf;
}


static char *
rp_mail_proxy_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_mail_proxy_conf_t *prev = parent;
    rp_mail_proxy_conf_t *conf = child;

    rp_conf_merge_value(conf->enable, prev->enable, 0);
    rp_conf_merge_value(conf->pass_error_message, prev->pass_error_message, 0);
    rp_conf_merge_value(conf->xclient, prev->xclient, 1);
    rp_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) rp_pagesize);
    rp_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);

    return RP_CONF_OK;
}

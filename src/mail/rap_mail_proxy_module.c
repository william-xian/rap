
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_event_connect.h>
#include <rap_mail.h>


typedef struct {
    rap_flag_t  enable;
    rap_flag_t  pass_error_message;
    rap_flag_t  xclient;
    size_t      buffer_size;
    rap_msec_t  timeout;
} rap_mail_proxy_conf_t;


static void rap_mail_proxy_block_read(rap_event_t *rev);
static void rap_mail_proxy_pop3_handler(rap_event_t *rev);
static void rap_mail_proxy_imap_handler(rap_event_t *rev);
static void rap_mail_proxy_smtp_handler(rap_event_t *rev);
static void rap_mail_proxy_dummy_handler(rap_event_t *ev);
static rap_int_t rap_mail_proxy_read_response(rap_mail_session_t *s,
    rap_uint_t state);
static void rap_mail_proxy_handler(rap_event_t *ev);
static void rap_mail_proxy_upstream_error(rap_mail_session_t *s);
static void rap_mail_proxy_internal_server_error(rap_mail_session_t *s);
static void rap_mail_proxy_close_session(rap_mail_session_t *s);
static void *rap_mail_proxy_create_conf(rap_conf_t *cf);
static char *rap_mail_proxy_merge_conf(rap_conf_t *cf, void *parent,
    void *child);


static rap_command_t  rap_mail_proxy_commands[] = {

    { rap_string("proxy"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_proxy_conf_t, enable),
      NULL },

    { rap_string("proxy_buffer"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_proxy_conf_t, buffer_size),
      NULL },

    { rap_string("proxy_timeout"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_proxy_conf_t, timeout),
      NULL },

    { rap_string("proxy_pass_error_message"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_proxy_conf_t, pass_error_message),
      NULL },

    { rap_string("xclient"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_proxy_conf_t, xclient),
      NULL },

      rap_null_command
};


static rap_mail_module_t  rap_mail_proxy_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_mail_proxy_create_conf,            /* create server configuration */
    rap_mail_proxy_merge_conf              /* merge server configuration */
};


rap_module_t  rap_mail_proxy_module = {
    RAP_MODULE_V1,
    &rap_mail_proxy_module_ctx,            /* module context */
    rap_mail_proxy_commands,               /* module directives */
    RAP_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static u_char  smtp_auth_ok[] = "235 2.0.0 OK" CRLF;


void
rap_mail_proxy_init(rap_mail_session_t *s, rap_addr_t *peer)
{
    rap_int_t                  rc;
    rap_mail_proxy_ctx_t      *p;
    rap_mail_proxy_conf_t     *pcf;
    rap_mail_core_srv_conf_t  *cscf;

    s->connection->log->action = "connecting to upstream";

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    p = rap_pcalloc(s->connection->pool, sizeof(rap_mail_proxy_ctx_t));
    if (p == NULL) {
        rap_mail_session_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->upstream.sockaddr = peer->sockaddr;
    p->upstream.socklen = peer->socklen;
    p->upstream.name = &peer->name;
    p->upstream.get = rap_event_get_peer;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = RAP_ERROR_ERR;

    rc = rap_event_connect_peer(&p->upstream);

    if (rc == RAP_ERROR || rc == RAP_BUSY || rc == RAP_DECLINED) {
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    rap_add_timer(p->upstream.connection->read, cscf->timeout);

    p->upstream.connection->data = s;
    p->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = rap_mail_proxy_block_read;
    p->upstream.connection->write->handler = rap_mail_proxy_dummy_handler;

    pcf = rap_mail_get_module_srv_conf(s, rap_mail_proxy_module);

    s->proxy->buffer = rap_create_temp_buf(s->connection->pool,
                                           pcf->buffer_size);
    if (s->proxy->buffer == NULL) {
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    s->out.len = 0;

    switch (s->protocol) {

    case RAP_MAIL_POP3_PROTOCOL:
        p->upstream.connection->read->handler = rap_mail_proxy_pop3_handler;
        s->mail_state = rap_pop3_start;
        break;

    case RAP_MAIL_IMAP_PROTOCOL:
        p->upstream.connection->read->handler = rap_mail_proxy_imap_handler;
        s->mail_state = rap_imap_start;
        break;

    default: /* RAP_MAIL_SMTP_PROTOCOL */
        p->upstream.connection->read->handler = rap_mail_proxy_smtp_handler;
        s->mail_state = rap_smtp_start;
        break;
    }
}


static void
rap_mail_proxy_block_read(rap_event_t *rev)
{
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy block read");

    if (rap_handle_read_event(rev, 0) != RAP_OK) {
        c = rev->data;
        s = c->data;

        rap_mail_proxy_close_session(s);
    }
}


static void
rap_mail_proxy_pop3_handler(rap_event_t *rev)
{
    u_char                 *p;
    rap_int_t               rc;
    rap_str_t               line;
    rap_connection_t       *c;
    rap_mail_session_t     *s;
    rap_mail_proxy_conf_t  *pcf;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy pop3 auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    rc = rap_mail_proxy_read_response(s, 0);

    if (rc == RAP_AGAIN) {
        return;
    }

    if (rc == RAP_ERROR) {
        rap_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case rap_pop3_start:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = sizeof("USER ")  - 1 + s->login.len + 2;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        p = rap_cpymem(line.data, "USER ", sizeof("USER ") - 1);
        p = rap_cpymem(p, s->login.data, s->login.len);
        *p++ = CR; *p = LF;

        s->mail_state = rap_pop3_user;
        break;

    case rap_pop3_user:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send pass");

        s->connection->log->action = "sending password to upstream";

        line.len = sizeof("PASS ")  - 1 + s->passwd.len + 2;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        p = rap_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
        p = rap_cpymem(p, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = rap_pop3_passwd;
        break;

    case rap_pop3_passwd:
        s->connection->read->handler = rap_mail_proxy_handler;
        s->connection->write->handler = rap_mail_proxy_handler;
        rev->handler = rap_mail_proxy_handler;
        c->write->handler = rap_mail_proxy_handler;

        pcf = rap_mail_get_module_srv_conf(s, rap_mail_proxy_module);
        rap_add_timer(s->connection->read, pcf->timeout);
        rap_del_timer(c->read);

        c->log->action = NULL;
        rap_log_error(RAP_LOG_INFO, c->log, 0, "client logged in");

        rap_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (RAP_SUPPRESS_WARN)
        rap_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as RAP_ERROR
         * because it is very strange here
         */
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
rap_mail_proxy_imap_handler(rap_event_t *rev)
{
    u_char                 *p;
    rap_int_t               rc;
    rap_str_t               line;
    rap_connection_t       *c;
    rap_mail_session_t     *s;
    rap_mail_proxy_conf_t  *pcf;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy imap auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    rc = rap_mail_proxy_read_response(s, s->mail_state);

    if (rc == RAP_AGAIN) {
        return;
    }

    if (rc == RAP_ERROR) {
        rap_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case rap_imap_start:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send login");

        s->connection->log->action = "sending LOGIN command to upstream";

        line.len = s->tag.len + sizeof("LOGIN ") - 1
                   + 1 + RAP_SIZE_T_LEN + 1 + 2;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = rap_sprintf(line.data, "%VLOGIN {%uz}" CRLF,
                               &s->tag, s->login.len)
                   - line.data;

        s->mail_state = rap_imap_login;
        break;

    case rap_imap_login:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = s->login.len + 1 + 1 + RAP_SIZE_T_LEN + 1 + 2;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = rap_sprintf(line.data, "%V {%uz}" CRLF,
                               &s->login, s->passwd.len)
                   - line.data;

        s->mail_state = rap_imap_user;
        break;

    case rap_imap_user:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send passwd");

        s->connection->log->action = "sending password to upstream";

        line.len = s->passwd.len + 2;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        p = rap_cpymem(line.data, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = rap_imap_passwd;
        break;

    case rap_imap_passwd:
        s->connection->read->handler = rap_mail_proxy_handler;
        s->connection->write->handler = rap_mail_proxy_handler;
        rev->handler = rap_mail_proxy_handler;
        c->write->handler = rap_mail_proxy_handler;

        pcf = rap_mail_get_module_srv_conf(s, rap_mail_proxy_module);
        rap_add_timer(s->connection->read, pcf->timeout);
        rap_del_timer(c->read);

        c->log->action = NULL;
        rap_log_error(RAP_LOG_INFO, c->log, 0, "client logged in");

        rap_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (RAP_SUPPRESS_WARN)
        rap_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as RAP_ERROR
         * because it is very strange here
         */
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
rap_mail_proxy_smtp_handler(rap_event_t *rev)
{
    u_char                    *p;
    rap_int_t                  rc;
    rap_str_t                  line;
    rap_buf_t                 *b;
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_mail_proxy_conf_t     *pcf;
    rap_mail_core_srv_conf_t  *cscf;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy smtp auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    rc = rap_mail_proxy_read_response(s, s->mail_state);

    if (rc == RAP_AGAIN) {
        return;
    }

    if (rc == RAP_ERROR) {
        rap_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case rap_smtp_start:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send ehlo");

        s->connection->log->action = "sending HELO/EHLO to upstream";

        cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

        line.len = sizeof("HELO ")  - 1 + cscf->server_name.len + 2;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        pcf = rap_mail_get_module_srv_conf(s, rap_mail_proxy_module);

        p = rap_cpymem(line.data,
                       ((s->esmtp || pcf->xclient) ? "EHLO " : "HELO "),
                       sizeof("HELO ") - 1);

        p = rap_cpymem(p, cscf->server_name.data, cscf->server_name.len);
        *p++ = CR; *p = LF;

        if (pcf->xclient) {
            s->mail_state = rap_smtp_helo_xclient;

        } else if (s->auth_method == RAP_MAIL_AUTH_NONE) {
            s->mail_state = rap_smtp_helo_from;

        } else {
            s->mail_state = rap_smtp_helo;
        }

        break;

    case rap_smtp_helo_xclient:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send xclient");

        s->connection->log->action = "sending XCLIENT to upstream";

        line.len = sizeof("XCLIENT ADDR= LOGIN= NAME="
                          CRLF) - 1
                   + s->connection->addr_text.len + s->login.len + s->host.len;

#if (RAP_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            line.len += sizeof("IPV6:") - 1;
        }
#endif

        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        p = rap_cpymem(line.data, "XCLIENT ADDR=", sizeof("XCLIENT ADDR=") - 1);

#if (RAP_HAVE_INET6)
        if (s->connection->sockaddr->sa_family == AF_INET6) {
            p = rap_cpymem(p, "IPV6:", sizeof("IPV6:") - 1);
        }
#endif

        p = rap_copy(p, s->connection->addr_text.data,
                     s->connection->addr_text.len);

        if (s->login.len) {
            p = rap_cpymem(p, " LOGIN=", sizeof(" LOGIN=") - 1);
            p = rap_copy(p, s->login.data, s->login.len);
        }

        p = rap_cpymem(p, " NAME=", sizeof(" NAME=") - 1);
        p = rap_copy(p, s->host.data, s->host.len);

        *p++ = CR; *p++ = LF;

        line.len = p - line.data;

        if (s->smtp_helo.len) {
            s->mail_state = rap_smtp_xclient_helo;

        } else if (s->auth_method == RAP_MAIL_AUTH_NONE) {
            s->mail_state = rap_smtp_xclient_from;

        } else {
            s->mail_state = rap_smtp_xclient;
        }

        break;

    case rap_smtp_xclient_helo:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send client ehlo");

        s->connection->log->action = "sending client HELO/EHLO to upstream";

        line.len = sizeof("HELO " CRLF) - 1 + s->smtp_helo.len;

        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = rap_sprintf(line.data,
                       ((s->esmtp) ? "EHLO %V" CRLF : "HELO %V" CRLF),
                       &s->smtp_helo)
                   - line.data;

        s->mail_state = (s->auth_method == RAP_MAIL_AUTH_NONE) ?
                            rap_smtp_helo_from : rap_smtp_helo;

        break;

    case rap_smtp_helo_from:
    case rap_smtp_xclient_from:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send mail from");

        s->connection->log->action = "sending MAIL FROM to upstream";

        line.len = s->smtp_from.len + sizeof(CRLF) - 1;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        p = rap_cpymem(line.data, s->smtp_from.data, s->smtp_from.len);
        *p++ = CR; *p = LF;

        s->mail_state = rap_smtp_from;

        break;

    case rap_smtp_from:
        rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send rcpt to");

        s->connection->log->action = "sending RCPT TO to upstream";

        line.len = s->smtp_to.len + sizeof(CRLF) - 1;
        line.data = rap_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            rap_mail_proxy_internal_server_error(s);
            return;
        }

        p = rap_cpymem(line.data, s->smtp_to.data, s->smtp_to.len);
        *p++ = CR; *p = LF;

        s->mail_state = rap_smtp_to;

        break;

    case rap_smtp_helo:
    case rap_smtp_xclient:
    case rap_smtp_to:

        b = s->proxy->buffer;

        if (s->auth_method == RAP_MAIL_AUTH_NONE) {
            b->pos = b->start;

        } else {
            rap_memcpy(b->start, smtp_auth_ok, sizeof(smtp_auth_ok) - 1);
            b->last = b->start + sizeof(smtp_auth_ok) - 1;
        }

        s->connection->read->handler = rap_mail_proxy_handler;
        s->connection->write->handler = rap_mail_proxy_handler;
        rev->handler = rap_mail_proxy_handler;
        c->write->handler = rap_mail_proxy_handler;

        pcf = rap_mail_get_module_srv_conf(s, rap_mail_proxy_module);
        rap_add_timer(s->connection->read, pcf->timeout);
        rap_del_timer(c->read);

        c->log->action = NULL;
        rap_log_error(RAP_LOG_INFO, c->log, 0, "client logged in");

        if (s->buffer->pos == s->buffer->last) {
            rap_mail_proxy_handler(s->connection->write);

        } else {
            rap_mail_proxy_handler(c->write);
        }

        return;

    default:
#if (RAP_SUPPRESS_WARN)
        rap_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as RAP_ERROR
         * because it is very strange here
         */
        rap_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
rap_mail_proxy_dummy_handler(rap_event_t *wev)
{
    rap_connection_t    *c;
    rap_mail_session_t  *s;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy dummy handler");

    if (rap_handle_write_event(wev, 0) != RAP_OK) {
        c = wev->data;
        s = c->data;

        rap_mail_proxy_close_session(s);
    }
}


static rap_int_t
rap_mail_proxy_read_response(rap_mail_session_t *s, rap_uint_t state)
{
    u_char                 *p, *m;
    ssize_t                 n;
    rap_buf_t              *b;
    rap_mail_proxy_conf_t  *pcf;

    s->connection->log->action = "reading response from upstream";

    b = s->proxy->buffer;

    n = s->proxy->upstream.connection->recv(s->proxy->upstream.connection,
                                            b->last, b->end - b->last);

    if (n == RAP_ERROR || n == 0) {
        return RAP_ERROR;
    }

    if (n == RAP_AGAIN) {
        return RAP_AGAIN;
    }

    b->last += n;

    if (b->last - b->pos < 4) {
        return RAP_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                          "upstream sent too long response line: \"%s\"",
                          b->pos);
            return RAP_ERROR;
        }

        return RAP_AGAIN;
    }

    p = b->pos;

    switch (s->protocol) {

    case RAP_MAIL_POP3_PROTOCOL:
        if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
            return RAP_OK;
        }
        break;

    case RAP_MAIL_IMAP_PROTOCOL:
        switch (state) {

        case rap_imap_start:
            if (p[0] == '*' && p[1] == ' ' && p[2] == 'O' && p[3] == 'K') {
                return RAP_OK;
            }
            break;

        case rap_imap_login:
        case rap_imap_user:
            if (p[0] == '+') {
                return RAP_OK;
            }
            break;

        case rap_imap_passwd:
            if (rap_strncmp(p, s->tag.data, s->tag.len) == 0) {
                p += s->tag.len;
                if (p[0] == 'O' && p[1] == 'K') {
                    return RAP_OK;
                }
            }
            break;
        }

        break;

    default: /* RAP_MAIL_SMTP_PROTOCOL */

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
                return RAP_AGAIN;
            }
        }

        switch (state) {

        case rap_smtp_start:
            if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
                return RAP_OK;
            }
            break;

        case rap_smtp_helo:
        case rap_smtp_helo_xclient:
        case rap_smtp_helo_from:
        case rap_smtp_from:
            if (p[0] == '2' && p[1] == '5' && p[2] == '0') {
                return RAP_OK;
            }
            break;

        case rap_smtp_xclient:
        case rap_smtp_xclient_from:
        case rap_smtp_xclient_helo:
            if (p[0] == '2' && (p[1] == '2' || p[1] == '5') && p[2] == '0') {
                return RAP_OK;
            }
            break;

        case rap_smtp_to:
            return RAP_OK;
        }

        break;
    }

    pcf = rap_mail_get_module_srv_conf(s, rap_mail_proxy_module);

    if (pcf->pass_error_message == 0) {
        *(b->last - 2) = '\0';
        rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid response: \"%s\"", p);
        return RAP_ERROR;
    }

    s->out.len = b->last - p - 2;
    s->out.data = p;

    rap_log_error(RAP_LOG_INFO, s->connection->log, 0,
                  "upstream sent invalid response: \"%V\"", &s->out);

    s->out.len = b->last - b->pos;
    s->out.data = b->pos;

    return RAP_ERROR;
}


static void
rap_mail_proxy_handler(rap_event_t *ev)
{
    char                   *action, *recv_action, *send_action;
    size_t                  size;
    ssize_t                 n;
    rap_buf_t              *b;
    rap_uint_t              do_write;
    rap_connection_t       *c, *src, *dst;
    rap_mail_session_t     *s;
    rap_mail_proxy_conf_t  *pcf;

    c = ev->data;
    s = c->data;

    if (ev->timedout || c->close) {
        c->log->action = "proxying";

        if (c->close) {
            rap_log_error(RAP_LOG_INFO, c->log, 0, "shutdown timeout");

        } else if (c == s->connection) {
            rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

        } else {
            rap_log_error(RAP_LOG_INFO, c->log, RAP_ETIMEDOUT,
                          "upstream timed out");
        }

        rap_mail_proxy_close_session(s);
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

    rap_log_debug3(RAP_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail proxy handler: %ui, #%d > #%d",
                   do_write, src->fd, dst->fd);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);

                if (n == RAP_ERROR) {
                    rap_mail_proxy_close_session(s);
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

            if (n == RAP_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                continue;
            }

            if (n == RAP_ERROR) {
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
        rap_log_error(RAP_LOG_INFO, c->log, 0, "proxied session done");
        c->log->action = action;

        rap_mail_proxy_close_session(s);
        return;
    }

    if (rap_handle_write_event(dst->write, 0) != RAP_OK) {
        rap_mail_proxy_close_session(s);
        return;
    }

    if (rap_handle_read_event(dst->read, 0) != RAP_OK) {
        rap_mail_proxy_close_session(s);
        return;
    }

    if (rap_handle_write_event(src->write, 0) != RAP_OK) {
        rap_mail_proxy_close_session(s);
        return;
    }

    if (rap_handle_read_event(src->read, 0) != RAP_OK) {
        rap_mail_proxy_close_session(s);
        return;
    }

    if (c == s->connection) {
        pcf = rap_mail_get_module_srv_conf(s, rap_mail_proxy_module);
        rap_add_timer(c->read, pcf->timeout);
    }
}


static void
rap_mail_proxy_upstream_error(rap_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        rap_log_debug1(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        rap_close_connection(s->proxy->upstream.connection);
    }

    if (s->out.len == 0) {
        rap_mail_session_internal_server_error(s);
        return;
    }

    s->quit = 1;
    rap_mail_send(s->connection->write);
}


static void
rap_mail_proxy_internal_server_error(rap_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        rap_log_debug1(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        rap_close_connection(s->proxy->upstream.connection);
    }

    rap_mail_session_internal_server_error(s);
}


static void
rap_mail_proxy_close_session(rap_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        rap_log_debug1(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        rap_close_connection(s->proxy->upstream.connection);
    }

    rap_mail_close_connection(s->connection);
}


static void *
rap_mail_proxy_create_conf(rap_conf_t *cf)
{
    rap_mail_proxy_conf_t  *pcf;

    pcf = rap_pcalloc(cf->pool, sizeof(rap_mail_proxy_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->enable = RAP_CONF_UNSET;
    pcf->pass_error_message = RAP_CONF_UNSET;
    pcf->xclient = RAP_CONF_UNSET;
    pcf->buffer_size = RAP_CONF_UNSET_SIZE;
    pcf->timeout = RAP_CONF_UNSET_MSEC;

    return pcf;
}


static char *
rap_mail_proxy_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_mail_proxy_conf_t *prev = parent;
    rap_mail_proxy_conf_t *conf = child;

    rap_conf_merge_value(conf->enable, prev->enable, 0);
    rap_conf_merge_value(conf->pass_error_message, prev->pass_error_message, 0);
    rap_conf_merge_value(conf->xclient, prev->xclient, 1);
    rap_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) rap_pagesize);
    rap_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);

    return RAP_CONF_OK;
}

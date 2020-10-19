
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
    rap_addr_t                     *peer;

    rap_msec_t                      timeout;
    rap_flag_t                      pass_client_cert;

    rap_str_t                       host_header;
    rap_str_t                       uri;
    rap_str_t                       header;

    rap_array_t                    *headers;

    u_char                         *file;
    rap_uint_t                      line;
} rap_mail_auth_http_conf_t;


typedef struct rap_mail_auth_http_ctx_s  rap_mail_auth_http_ctx_t;

typedef void (*rap_mail_auth_http_handler_pt)(rap_mail_session_t *s,
    rap_mail_auth_http_ctx_t *ctx);

struct rap_mail_auth_http_ctx_s {
    rap_buf_t                      *request;
    rap_buf_t                      *response;
    rap_peer_connection_t           peer;

    rap_mail_auth_http_handler_pt   handler;

    rap_uint_t                      state;

    u_char                         *header_name_start;
    u_char                         *header_name_end;
    u_char                         *header_start;
    u_char                         *header_end;

    rap_str_t                       addr;
    rap_str_t                       port;
    rap_str_t                       err;
    rap_str_t                       errmsg;
    rap_str_t                       errcode;

    time_t                          sleep;

    rap_pool_t                     *pool;
};


static void rap_mail_auth_http_write_handler(rap_event_t *wev);
static void rap_mail_auth_http_read_handler(rap_event_t *rev);
static void rap_mail_auth_http_ignore_status_line(rap_mail_session_t *s,
    rap_mail_auth_http_ctx_t *ctx);
static void rap_mail_auth_http_process_headers(rap_mail_session_t *s,
    rap_mail_auth_http_ctx_t *ctx);
static void rap_mail_auth_sleep_handler(rap_event_t *rev);
static rap_int_t rap_mail_auth_http_parse_header_line(rap_mail_session_t *s,
    rap_mail_auth_http_ctx_t *ctx);
static void rap_mail_auth_http_block_read(rap_event_t *rev);
static void rap_mail_auth_http_dummy_handler(rap_event_t *ev);
static rap_buf_t *rap_mail_auth_http_create_request(rap_mail_session_t *s,
    rap_pool_t *pool, rap_mail_auth_http_conf_t *ahcf);
static rap_int_t rap_mail_auth_http_escape(rap_pool_t *pool, rap_str_t *text,
    rap_str_t *escaped);

static void *rap_mail_auth_http_create_conf(rap_conf_t *cf);
static char *rap_mail_auth_http_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_mail_auth_http(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_mail_auth_http_header(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_mail_auth_http_commands[] = {

    { rap_string("auth_http"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_mail_auth_http,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("auth_http_timeout"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_auth_http_conf_t, timeout),
      NULL },

    { rap_string("auth_http_header"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE2,
      rap_mail_auth_http_header,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("auth_http_pass_client_cert"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_auth_http_conf_t, pass_client_cert),
      NULL },

      rap_null_command
};


static rap_mail_module_t  rap_mail_auth_http_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_mail_auth_http_create_conf,        /* create server configuration */
    rap_mail_auth_http_merge_conf          /* merge server configuration */
};


rap_module_t  rap_mail_auth_http_module = {
    RAP_MODULE_V1,
    &rap_mail_auth_http_module_ctx,        /* module context */
    rap_mail_auth_http_commands,           /* module directives */
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


static rap_str_t   rap_mail_auth_http_method[] = {
    rap_string("plain"),
    rap_string("plain"),
    rap_string("plain"),
    rap_string("apop"),
    rap_string("cram-md5"),
    rap_string("external"),
    rap_string("none")
};

static rap_str_t   rap_mail_smtp_errcode = rap_string("535 5.7.0");


void
rap_mail_auth_http_init(rap_mail_session_t *s)
{
    rap_int_t                   rc;
    rap_pool_t                 *pool;
    rap_mail_auth_http_ctx_t   *ctx;
    rap_mail_auth_http_conf_t  *ahcf;

    s->connection->log->action = "in http auth state";

    pool = rap_create_pool(2048, s->connection->log);
    if (pool == NULL) {
        rap_mail_session_internal_server_error(s);
        return;
    }

    ctx = rap_pcalloc(pool, sizeof(rap_mail_auth_http_ctx_t));
    if (ctx == NULL) {
        rap_destroy_pool(pool);
        rap_mail_session_internal_server_error(s);
        return;
    }

    ctx->pool = pool;

    ahcf = rap_mail_get_module_srv_conf(s, rap_mail_auth_http_module);

    ctx->request = rap_mail_auth_http_create_request(s, pool, ahcf);
    if (ctx->request == NULL) {
        rap_destroy_pool(ctx->pool);
        rap_mail_session_internal_server_error(s);
        return;
    }

    rap_mail_set_ctx(s, ctx, rap_mail_auth_http_module);

    ctx->peer.sockaddr = ahcf->peer->sockaddr;
    ctx->peer.socklen = ahcf->peer->socklen;
    ctx->peer.name = &ahcf->peer->name;
    ctx->peer.get = rap_event_get_peer;
    ctx->peer.log = s->connection->log;
    ctx->peer.log_error = RAP_ERROR_ERR;

    rc = rap_event_connect_peer(&ctx->peer);

    if (rc == RAP_ERROR || rc == RAP_BUSY || rc == RAP_DECLINED) {
        if (ctx->peer.connection) {
            rap_close_connection(ctx->peer.connection);
        }

        rap_destroy_pool(ctx->pool);
        rap_mail_session_internal_server_error(s);
        return;
    }

    ctx->peer.connection->data = s;
    ctx->peer.connection->pool = s->connection->pool;

    s->connection->read->handler = rap_mail_auth_http_block_read;
    ctx->peer.connection->read->handler = rap_mail_auth_http_read_handler;
    ctx->peer.connection->write->handler = rap_mail_auth_http_write_handler;

    ctx->handler = rap_mail_auth_http_ignore_status_line;

    rap_add_timer(ctx->peer.connection->read, ahcf->timeout);
    rap_add_timer(ctx->peer.connection->write, ahcf->timeout);

    if (rc == RAP_OK) {
        rap_mail_auth_http_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
rap_mail_auth_http_write_handler(rap_event_t *wev)
{
    ssize_t                     n, size;
    rap_connection_t           *c;
    rap_mail_session_t         *s;
    rap_mail_auth_http_ctx_t   *ctx;
    rap_mail_auth_http_conf_t  *ahcf;

    c = wev->data;
    s = c->data;

    ctx = rap_mail_get_module_ctx(s, rap_mail_auth_http_module);

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, wev->log, 0,
                   "mail auth http write handler");

    if (wev->timedout) {
        rap_log_error(RAP_LOG_ERR, wev->log, RAP_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        rap_close_connection(c);
        rap_destroy_pool(ctx->pool);
        rap_mail_session_internal_server_error(s);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = rap_send(c, ctx->request->pos, size);

    if (n == RAP_ERROR) {
        rap_close_connection(c);
        rap_destroy_pool(ctx->pool);
        rap_mail_session_internal_server_error(s);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = rap_mail_auth_http_dummy_handler;

            if (wev->timer_set) {
                rap_del_timer(wev);
            }

            if (rap_handle_write_event(wev, 0) != RAP_OK) {
                rap_close_connection(c);
                rap_destroy_pool(ctx->pool);
                rap_mail_session_internal_server_error(s);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        ahcf = rap_mail_get_module_srv_conf(s, rap_mail_auth_http_module);
        rap_add_timer(wev, ahcf->timeout);
    }
}


static void
rap_mail_auth_http_read_handler(rap_event_t *rev)
{
    ssize_t                     n, size;
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_mail_auth_http_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http read handler");

    ctx = rap_mail_get_module_ctx(s, rap_mail_auth_http_module);

    if (rev->timedout) {
        rap_log_error(RAP_LOG_ERR, rev->log, RAP_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        rap_close_connection(c);
        rap_destroy_pool(ctx->pool);
        rap_mail_session_internal_server_error(s);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = rap_create_temp_buf(ctx->pool, 1024);
        if (ctx->response == NULL) {
            rap_close_connection(c);
            rap_destroy_pool(ctx->pool);
            rap_mail_session_internal_server_error(s);
            return;
        }
    }

    size = ctx->response->end - ctx->response->last;

    n = rap_recv(c, ctx->response->pos, size);

    if (n > 0) {
        ctx->response->last += n;

        ctx->handler(s, ctx);
        return;
    }

    if (n == RAP_AGAIN) {
        return;
    }

    rap_close_connection(c);
    rap_destroy_pool(ctx->pool);
    rap_mail_session_internal_server_error(s);
}


static void
rap_mail_auth_http_ignore_status_line(rap_mail_session_t *s,
    rap_mail_auth_http_ctx_t *ctx)
{
    u_char  *p, ch;
    enum  {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_skip,
        sw_almost_done
    } state;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process status line");

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (ch == 'H') {
                state = sw_H;
                break;
            }
            goto next;

        case sw_H:
            if (ch == 'T') {
                state = sw_HT;
                break;
            }
            goto next;

        case sw_HT:
            if (ch == 'T') {
                state = sw_HTT;
                break;
            }
            goto next;

        case sw_HTT:
            if (ch == 'P') {
                state = sw_HTTP;
                break;
            }
            goto next;

        case sw_HTTP:
            if (ch == '/') {
                state = sw_skip;
                break;
            }
            goto next;

        /* any text until end of line */
        case sw_skip:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            if (ch == LF) {
                goto done;
            }

            rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                          "auth http server %V sent invalid response",
                          ctx->peer.name);
            rap_close_connection(ctx->peer.connection);
            rap_destroy_pool(ctx->pool);
            rap_mail_session_internal_server_error(s);
            return;
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return;

next:

    p = ctx->response->start - 1;

done:

    ctx->response->pos = p + 1;
    ctx->state = 0;
    ctx->handler = rap_mail_auth_http_process_headers;
    ctx->handler(s, ctx);
}


static void
rap_mail_auth_http_process_headers(rap_mail_session_t *s,
    rap_mail_auth_http_ctx_t *ctx)
{
    u_char      *p;
    time_t       timer;
    size_t       len, size;
    rap_int_t    rc, port, n;
    rap_addr_t  *peer;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process headers");

    for ( ;; ) {
        rc = rap_mail_auth_http_parse_header_line(s, ctx);

        if (rc == RAP_OK) {

#if (RAP_DEBUG)
            {
            rap_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            rap_log_debug2(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header: \"%V: %V\"",
                           &key, &value);
            }
#endif

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Auth-Status") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Status",
                                   sizeof("Auth-Status") - 1)
                   == 0)
            {
                len = ctx->header_end - ctx->header_start;

                if (len == 2
                    && ctx->header_start[0] == 'O'
                    && ctx->header_start[1] == 'K')
                {
                    continue;
                }

                if (len == 4
                    && ctx->header_start[0] == 'W'
                    && ctx->header_start[1] == 'A'
                    && ctx->header_start[2] == 'I'
                    && ctx->header_start[3] == 'T')
                {
                    s->auth_wait = 1;
                    continue;
                }

                ctx->errmsg.len = len;
                ctx->errmsg.data = ctx->header_start;

                switch (s->protocol) {

                case RAP_MAIL_POP3_PROTOCOL:
                    size = sizeof("-ERR ") - 1 + len + sizeof(CRLF) - 1;
                    break;

                case RAP_MAIL_IMAP_PROTOCOL:
                    size = s->tag.len + sizeof("NO ") - 1 + len
                           + sizeof(CRLF) - 1;
                    break;

                default: /* RAP_MAIL_SMTP_PROTOCOL */
                    ctx->err = ctx->errmsg;
                    continue;
                }

                p = rap_pnalloc(s->connection->pool, size);
                if (p == NULL) {
                    rap_close_connection(ctx->peer.connection);
                    rap_destroy_pool(ctx->pool);
                    rap_mail_session_internal_server_error(s);
                    return;
                }

                ctx->err.data = p;

                switch (s->protocol) {

                case RAP_MAIL_POP3_PROTOCOL:
                    *p++ = '-'; *p++ = 'E'; *p++ = 'R'; *p++ = 'R'; *p++ = ' ';
                    break;

                case RAP_MAIL_IMAP_PROTOCOL:
                    p = rap_cpymem(p, s->tag.data, s->tag.len);
                    *p++ = 'N'; *p++ = 'O'; *p++ = ' ';
                    break;

                default: /* RAP_MAIL_SMTP_PROTOCOL */
                    break;
                }

                p = rap_cpymem(p, ctx->header_start, len);
                *p++ = CR; *p++ = LF;

                ctx->err.len = p - ctx->err.data;

                continue;
            }

            if (len == sizeof("Auth-Server") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Server",
                                   sizeof("Auth-Server") - 1)
                    == 0)
            {
                ctx->addr.len = ctx->header_end - ctx->header_start;
                ctx->addr.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Port") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Port",
                                   sizeof("Auth-Port") - 1)
                   == 0)
            {
                ctx->port.len = ctx->header_end - ctx->header_start;
                ctx->port.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-User") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-User",
                                   sizeof("Auth-User") - 1)
                   == 0)
            {
                s->login.len = ctx->header_end - ctx->header_start;

                s->login.data = rap_pnalloc(s->connection->pool, s->login.len);
                if (s->login.data == NULL) {
                    rap_close_connection(ctx->peer.connection);
                    rap_destroy_pool(ctx->pool);
                    rap_mail_session_internal_server_error(s);
                    return;
                }

                rap_memcpy(s->login.data, ctx->header_start, s->login.len);

                continue;
            }

            if (len == sizeof("Auth-Pass") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Pass",
                                   sizeof("Auth-Pass") - 1)
                   == 0)
            {
                s->passwd.len = ctx->header_end - ctx->header_start;

                s->passwd.data = rap_pnalloc(s->connection->pool,
                                             s->passwd.len);
                if (s->passwd.data == NULL) {
                    rap_close_connection(ctx->peer.connection);
                    rap_destroy_pool(ctx->pool);
                    rap_mail_session_internal_server_error(s);
                    return;
                }

                rap_memcpy(s->passwd.data, ctx->header_start, s->passwd.len);

                continue;
            }

            if (len == sizeof("Auth-Wait") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Wait",
                                   sizeof("Auth-Wait") - 1)
                   == 0)
            {
                n = rap_atoi(ctx->header_start,
                             ctx->header_end - ctx->header_start);

                if (n != RAP_ERROR) {
                    ctx->sleep = n;
                }

                continue;
            }

            if (len == sizeof("Auth-Error-Code") - 1
                && rap_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Error-Code",
                                   sizeof("Auth-Error-Code") - 1)
                   == 0)
            {
                ctx->errcode.len = ctx->header_end - ctx->header_start;

                ctx->errcode.data = rap_pnalloc(s->connection->pool,
                                                ctx->errcode.len);
                if (ctx->errcode.data == NULL) {
                    rap_close_connection(ctx->peer.connection);
                    rap_destroy_pool(ctx->pool);
                    rap_mail_session_internal_server_error(s);
                    return;
                }

                rap_memcpy(ctx->errcode.data, ctx->header_start,
                           ctx->errcode.len);

                continue;
            }

            /* ignore other headers */

            continue;
        }

        if (rc == RAP_DONE) {
            rap_log_debug0(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header done");

            rap_close_connection(ctx->peer.connection);

            if (ctx->err.len) {

                rap_log_error(RAP_LOG_INFO, s->connection->log, 0,
                              "client login failed: \"%V\"", &ctx->errmsg);

                if (s->protocol == RAP_MAIL_SMTP_PROTOCOL) {

                    if (ctx->errcode.len == 0) {
                        ctx->errcode = rap_mail_smtp_errcode;
                    }

                    ctx->err.len = ctx->errcode.len + ctx->errmsg.len
                                   + sizeof(" " CRLF) - 1;

                    p = rap_pnalloc(s->connection->pool, ctx->err.len);
                    if (p == NULL) {
                        rap_destroy_pool(ctx->pool);
                        rap_mail_session_internal_server_error(s);
                        return;
                    }

                    ctx->err.data = p;

                    p = rap_cpymem(p, ctx->errcode.data, ctx->errcode.len);
                    *p++ = ' ';
                    p = rap_cpymem(p, ctx->errmsg.data, ctx->errmsg.len);
                    *p++ = CR; *p = LF;
                }

                s->out = ctx->err;
                timer = ctx->sleep;

                rap_destroy_pool(ctx->pool);

                if (timer == 0) {
                    s->quit = 1;
                    rap_mail_send(s->connection->write);
                    return;
                }

                rap_add_timer(s->connection->read, (rap_msec_t) (timer * 1000));

                s->connection->read->handler = rap_mail_auth_sleep_handler;

                return;
            }

            if (s->auth_wait) {
                timer = ctx->sleep;

                rap_destroy_pool(ctx->pool);

                if (timer == 0) {
                    rap_mail_auth_http_init(s);
                    return;
                }

                rap_add_timer(s->connection->read, (rap_msec_t) (timer * 1000));

                s->connection->read->handler = rap_mail_auth_sleep_handler;

                return;
            }

            if (ctx->addr.len == 0 || ctx->port.len == 0) {
                rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send server or port",
                              ctx->peer.name);
                rap_destroy_pool(ctx->pool);
                rap_mail_session_internal_server_error(s);
                return;
            }

            if (s->passwd.data == NULL
                && s->protocol != RAP_MAIL_SMTP_PROTOCOL)
            {
                rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send password",
                              ctx->peer.name);
                rap_destroy_pool(ctx->pool);
                rap_mail_session_internal_server_error(s);
                return;
            }

            peer = rap_pcalloc(s->connection->pool, sizeof(rap_addr_t));
            if (peer == NULL) {
                rap_destroy_pool(ctx->pool);
                rap_mail_session_internal_server_error(s);
                return;
            }

            rc = rap_parse_addr(s->connection->pool, peer,
                                ctx->addr.data, ctx->addr.len);

            switch (rc) {
            case RAP_OK:
                break;

            case RAP_DECLINED:
                rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "address:\"%V\"",
                              ctx->peer.name, &ctx->addr);
                /* fall through */

            default:
                rap_destroy_pool(ctx->pool);
                rap_mail_session_internal_server_error(s);
                return;
            }

            port = rap_atoi(ctx->port.data, ctx->port.len);
            if (port == RAP_ERROR || port < 1 || port > 65535) {
                rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "port:\"%V\"",
                              ctx->peer.name, &ctx->port);
                rap_destroy_pool(ctx->pool);
                rap_mail_session_internal_server_error(s);
                return;
            }

            rap_inet_set_port(peer->sockaddr, (in_port_t) port);

            len = ctx->addr.len + 1 + ctx->port.len;

            peer->name.len = len;

            peer->name.data = rap_pnalloc(s->connection->pool, len);
            if (peer->name.data == NULL) {
                rap_destroy_pool(ctx->pool);
                rap_mail_session_internal_server_error(s);
                return;
            }

            len = ctx->addr.len;

            rap_memcpy(peer->name.data, ctx->addr.data, len);

            peer->name.data[len++] = ':';

            rap_memcpy(peer->name.data + len, ctx->port.data, ctx->port.len);

            rap_destroy_pool(ctx->pool);
            rap_mail_proxy_init(s, peer);

            return;
        }

        if (rc == RAP_AGAIN ) {
            return;
        }

        /* rc == RAP_ERROR */

        rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                      "auth http server %V sent invalid header in response",
                      ctx->peer.name);
        rap_close_connection(ctx->peer.connection);
        rap_destroy_pool(ctx->pool);
        rap_mail_session_internal_server_error(s);

        return;
    }
}


static void
rap_mail_auth_sleep_handler(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_mail_core_srv_conf_t  *cscf;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0, "mail auth sleep handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {

        rev->timedout = 0;

        if (s->auth_wait) {
            s->auth_wait = 0;
            rap_mail_auth_http_init(s);
            return;
        }

        cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

        rev->handler = cscf->protocol->auth_state;

        s->mail_state = 0;
        s->auth_method = RAP_MAIL_AUTH_PLAIN;

        c->log->action = "in auth state";

        rap_mail_send(c->write);

        if (c->destroyed) {
            return;
        }

        rap_add_timer(rev, cscf->timeout);

        if (rev->ready) {
            rev->handler(rev);
            return;
        }

        if (rap_handle_read_event(rev, 0) != RAP_OK) {
            rap_mail_close_connection(c);
        }

        return;
    }

    if (rev->active) {
        if (rap_handle_read_event(rev, 0) != RAP_OK) {
            rap_mail_close_connection(c);
        }
    }
}


static rap_int_t
rap_mail_auth_http_parse_header_line(rap_mail_session_t *s,
    rap_mail_auth_http_ctx_t *ctx)
{
    u_char      c, ch, *p;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_almost_done,
        sw_header_almost_done
    } state;

    state = ctx->state;

    for (p = ctx->response->pos; p < ctx->response->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                ctx->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto header_done;
            default:
                state = sw_name;
                ctx->header_name_start = p;

                c = (u_char) (ch | 0x20);
                if (c >= 'a' && c <= 'z') {
                    break;
                }

                if (ch >= '0' && ch <= '9') {
                    break;
                }

                return RAP_ERROR;
            }
            break;

        /* header name */
        case sw_name:
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'z') {
                break;
            }

            if (ch == ':') {
                ctx->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == '-') {
                break;
            }

            if (ch >= '0' && ch <= '9') {
                break;
            }

            if (ch == CR) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                ctx->header_name_end = p;
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            }

            return RAP_ERROR;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                ctx->header_start = p;
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_start = p;
                ctx->header_end = p;
                goto done;
            default:
                ctx->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                ctx->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                ctx->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                ctx->header_end = p;
                goto done;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_value;
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            default:
                return RAP_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return RAP_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return RAP_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RAP_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RAP_DONE;
}


static void
rap_mail_auth_http_block_read(rap_event_t *rev)
{
    rap_connection_t          *c;
    rap_mail_session_t        *s;
    rap_mail_auth_http_ctx_t  *ctx;

    rap_log_debug0(RAP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http block read");

    if (rap_handle_read_event(rev, 0) != RAP_OK) {
        c = rev->data;
        s = c->data;

        ctx = rap_mail_get_module_ctx(s, rap_mail_auth_http_module);

        rap_close_connection(ctx->peer.connection);
        rap_destroy_pool(ctx->pool);
        rap_mail_session_internal_server_error(s);
    }
}


static void
rap_mail_auth_http_dummy_handler(rap_event_t *ev)
{
    rap_log_debug0(RAP_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail auth http dummy handler");
}


static rap_buf_t *
rap_mail_auth_http_create_request(rap_mail_session_t *s, rap_pool_t *pool,
    rap_mail_auth_http_conf_t *ahcf)
{
    size_t                     len;
    rap_buf_t                 *b;
    rap_str_t                  login, passwd;
#if (RAP_MAIL_SSL)
    rap_str_t                  verify, subject, issuer, serial, fingerprint,
                               raw_cert, cert;
    rap_connection_t          *c;
    rap_mail_ssl_conf_t       *sslcf;
#endif
    rap_mail_core_srv_conf_t  *cscf;

    if (rap_mail_auth_http_escape(pool, &s->login, &login) != RAP_OK) {
        return NULL;
    }

    if (rap_mail_auth_http_escape(pool, &s->passwd, &passwd) != RAP_OK) {
        return NULL;
    }

#if (RAP_MAIL_SSL)

    c = s->connection;
    sslcf = rap_mail_get_module_srv_conf(s, rap_mail_ssl_module);

    if (c->ssl && sslcf->verify) {

        /* certificate details */

        if (rap_ssl_get_client_verify(c, pool, &verify) != RAP_OK) {
            return NULL;
        }

        if (rap_ssl_get_subject_dn(c, pool, &subject) != RAP_OK) {
            return NULL;
        }

        if (rap_ssl_get_issuer_dn(c, pool, &issuer) != RAP_OK) {
            return NULL;
        }

        if (rap_ssl_get_serial_number(c, pool, &serial) != RAP_OK) {
            return NULL;
        }

        if (rap_ssl_get_fingerprint(c, pool, &fingerprint) != RAP_OK) {
            return NULL;
        }

        if (ahcf->pass_client_cert) {

            /* certificate itself, if configured */

            if (rap_ssl_get_raw_certificate(c, pool, &raw_cert) != RAP_OK) {
                return NULL;
            }

            if (rap_mail_auth_http_escape(pool, &raw_cert, &cert) != RAP_OK) {
                return NULL;
            }

        } else {
            rap_str_null(&cert);
        }

    } else {
        rap_str_null(&verify);
        rap_str_null(&subject);
        rap_str_null(&issuer);
        rap_str_null(&serial);
        rap_str_null(&fingerprint);
        rap_str_null(&cert);
    }

#endif

    cscf = rap_mail_get_module_srv_conf(s, rap_mail_core_module);

    len = sizeof("GET ") - 1 + ahcf->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ahcf->host_header.len + sizeof(CRLF) - 1
          + sizeof("Auth-Method: ") - 1
                + rap_mail_auth_http_method[s->auth_method].len
                + sizeof(CRLF) - 1
          + sizeof("Auth-User: ") - 1 + login.len + sizeof(CRLF) - 1
          + sizeof("Auth-Pass: ") - 1 + passwd.len + sizeof(CRLF) - 1
          + sizeof("Auth-Salt: ") - 1 + s->salt.len
          + sizeof("Auth-Protocol: ") - 1 + cscf->protocol->name.len
                + sizeof(CRLF) - 1
          + sizeof("Auth-Login-Attempt: ") - 1 + RAP_INT_T_LEN
                + sizeof(CRLF) - 1
          + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
                + sizeof(CRLF) - 1
          + sizeof("Client-Host: ") - 1 + s->host.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-Helo: ") - 1 + s->smtp_helo.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-From: ") - 1 + s->smtp_from.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-To: ") - 1 + s->smtp_to.len + sizeof(CRLF) - 1
#if (RAP_MAIL_SSL)
          + sizeof("Auth-SSL: on" CRLF) - 1
          + sizeof("Auth-SSL-Verify: ") - 1 + verify.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Subject: ") - 1 + subject.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Issuer: ") - 1 + issuer.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Serial: ") - 1 + serial.len + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Fingerprint: ") - 1 + fingerprint.len
              + sizeof(CRLF) - 1
          + sizeof("Auth-SSL-Cert: ") - 1 + cert.len + sizeof(CRLF) - 1
#endif
          + ahcf->header.len
          + sizeof(CRLF) - 1;

    b = rap_create_temp_buf(pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = rap_cpymem(b->last, "GET ", sizeof("GET ") - 1);
    b->last = rap_copy(b->last, ahcf->uri.data, ahcf->uri.len);
    b->last = rap_cpymem(b->last, " HTTP/1.0" CRLF,
                         sizeof(" HTTP/1.0" CRLF) - 1);

    b->last = rap_cpymem(b->last, "Host: ", sizeof("Host: ") - 1);
    b->last = rap_copy(b->last, ahcf->host_header.data,
                         ahcf->host_header.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rap_cpymem(b->last, "Auth-Method: ",
                         sizeof("Auth-Method: ") - 1);
    b->last = rap_cpymem(b->last,
                         rap_mail_auth_http_method[s->auth_method].data,
                         rap_mail_auth_http_method[s->auth_method].len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rap_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
    b->last = rap_copy(b->last, login.data, login.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rap_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
    b->last = rap_copy(b->last, passwd.data, passwd.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->auth_method != RAP_MAIL_AUTH_PLAIN && s->salt.len) {
        b->last = rap_cpymem(b->last, "Auth-Salt: ", sizeof("Auth-Salt: ") - 1);
        b->last = rap_copy(b->last, s->salt.data, s->salt.len);

        s->passwd.data = NULL;
    }

    b->last = rap_cpymem(b->last, "Auth-Protocol: ",
                         sizeof("Auth-Protocol: ") - 1);
    b->last = rap_cpymem(b->last, cscf->protocol->name.data,
                         cscf->protocol->name.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rap_sprintf(b->last, "Auth-Login-Attempt: %ui" CRLF,
                          s->login_attempt);

    b->last = rap_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
    b->last = rap_copy(b->last, s->connection->addr_text.data,
                       s->connection->addr_text.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->host.len) {
        b->last = rap_cpymem(b->last, "Client-Host: ",
                             sizeof("Client-Host: ") - 1);
        b->last = rap_copy(b->last, s->host.data, s->host.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    if (s->auth_method == RAP_MAIL_AUTH_NONE) {

        /* HELO, MAIL FROM, and RCPT TO can't contain CRLF, no need to escape */

        b->last = rap_cpymem(b->last, "Auth-SMTP-Helo: ",
                             sizeof("Auth-SMTP-Helo: ") - 1);
        b->last = rap_copy(b->last, s->smtp_helo.data, s->smtp_helo.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = rap_cpymem(b->last, "Auth-SMTP-From: ",
                             sizeof("Auth-SMTP-From: ") - 1);
        b->last = rap_copy(b->last, s->smtp_from.data, s->smtp_from.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = rap_cpymem(b->last, "Auth-SMTP-To: ",
                             sizeof("Auth-SMTP-To: ") - 1);
        b->last = rap_copy(b->last, s->smtp_to.data, s->smtp_to.len);
        *b->last++ = CR; *b->last++ = LF;

    }

#if (RAP_MAIL_SSL)

    if (c->ssl) {
        b->last = rap_cpymem(b->last, "Auth-SSL: on" CRLF,
                             sizeof("Auth-SSL: on" CRLF) - 1);

        if (verify.len) {
            b->last = rap_cpymem(b->last, "Auth-SSL-Verify: ",
                                 sizeof("Auth-SSL-Verify: ") - 1);
            b->last = rap_copy(b->last, verify.data, verify.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (subject.len) {
            b->last = rap_cpymem(b->last, "Auth-SSL-Subject: ",
                                 sizeof("Auth-SSL-Subject: ") - 1);
            b->last = rap_copy(b->last, subject.data, subject.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (issuer.len) {
            b->last = rap_cpymem(b->last, "Auth-SSL-Issuer: ",
                                 sizeof("Auth-SSL-Issuer: ") - 1);
            b->last = rap_copy(b->last, issuer.data, issuer.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (serial.len) {
            b->last = rap_cpymem(b->last, "Auth-SSL-Serial: ",
                                 sizeof("Auth-SSL-Serial: ") - 1);
            b->last = rap_copy(b->last, serial.data, serial.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (fingerprint.len) {
            b->last = rap_cpymem(b->last, "Auth-SSL-Fingerprint: ",
                                 sizeof("Auth-SSL-Fingerprint: ") - 1);
            b->last = rap_copy(b->last, fingerprint.data, fingerprint.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (cert.len) {
            b->last = rap_cpymem(b->last, "Auth-SSL-Cert: ",
                                 sizeof("Auth-SSL-Cert: ") - 1);
            b->last = rap_copy(b->last, cert.data, cert.len);
            *b->last++ = CR; *b->last++ = LF;
        }
    }

#endif

    if (ahcf->header.len) {
        b->last = rap_copy(b->last, ahcf->header.data, ahcf->header.len);
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (RAP_DEBUG_MAIL_PASSWD)
    rap_log_debug2(RAP_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);
#endif

    return b;
}


static rap_int_t
rap_mail_auth_http_escape(rap_pool_t *pool, rap_str_t *text, rap_str_t *escaped)
{
    u_char     *p;
    uintptr_t   n;

    n = rap_escape_uri(NULL, text->data, text->len, RAP_ESCAPE_MAIL_AUTH);

    if (n == 0) {
        *escaped = *text;
        return RAP_OK;
    }

    escaped->len = text->len + n * 2;

    p = rap_pnalloc(pool, escaped->len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    (void) rap_escape_uri(p, text->data, text->len, RAP_ESCAPE_MAIL_AUTH);

    escaped->data = p;

    return RAP_OK;
}


static void *
rap_mail_auth_http_create_conf(rap_conf_t *cf)
{
    rap_mail_auth_http_conf_t  *ahcf;

    ahcf = rap_pcalloc(cf->pool, sizeof(rap_mail_auth_http_conf_t));
    if (ahcf == NULL) {
        return NULL;
    }

    ahcf->timeout = RAP_CONF_UNSET_MSEC;
    ahcf->pass_client_cert = RAP_CONF_UNSET;

    ahcf->file = cf->conf_file->file.name.data;
    ahcf->line = cf->conf_file->line;

    return ahcf;
}


static char *
rap_mail_auth_http_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_mail_auth_http_conf_t *prev = parent;
    rap_mail_auth_http_conf_t *conf = child;

    u_char           *p;
    size_t            len;
    rap_uint_t        i;
    rap_table_elt_t  *header;

    if (conf->peer == NULL) {
        conf->peer = prev->peer;
        conf->host_header = prev->host_header;
        conf->uri = prev->uri;

        if (conf->peer == NULL) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"auth_http\" is defined for server in %s:%ui",
                          conf->file, conf->line);

            return RAP_CONF_ERROR;
        }
    }

    rap_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    rap_conf_merge_value(conf->pass_client_cert, prev->pass_client_cert, 0);

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
        conf->header = prev->header;
    }

    if (conf->headers && conf->header.len == 0) {
        len = 0;
        header = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {
            len += header[i].key.len + 2 + header[i].value.len + 2;
        }

        p = rap_pnalloc(cf->pool, len);
        if (p == NULL) {
            return RAP_CONF_ERROR;
        }

        conf->header.len = len;
        conf->header.data = p;

        for (i = 0; i < conf->headers->nelts; i++) {
            p = rap_cpymem(p, header[i].key.data, header[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = rap_cpymem(p, header[i].value.data, header[i].value.len);
            *p++ = CR; *p++ = LF;
        }
    }

    return RAP_CONF_OK;
}


static char *
rap_mail_auth_http(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_auth_http_conf_t *ahcf = conf;

    rap_str_t  *value;
    rap_url_t   u;

    value = cf->args->elts;

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = value[1];
    u.default_port = 80;
    u.uri_part = 1;

    if (rap_strncmp(u.url.data, "http://", 7) == 0) {
        u.url.len -= 7;
        u.url.data += 7;
    }

    if (rap_parse_url(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "%s in auth_http \"%V\"", u.err, &u.url);
        }

        return RAP_CONF_ERROR;
    }

    ahcf->peer = u.addrs;

    if (u.family != AF_UNIX) {
        ahcf->host_header = u.host;

    } else {
        rap_str_set(&ahcf->host_header, "localhost");
    }

    ahcf->uri = u.uri;

    if (ahcf->uri.len == 0) {
        rap_str_set(&ahcf->uri, "/");
    }

    return RAP_CONF_OK;
}


static char *
rap_mail_auth_http_header(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_auth_http_conf_t *ahcf = conf;

    rap_str_t        *value;
    rap_table_elt_t  *header;

    if (ahcf->headers == NULL) {
        ahcf->headers = rap_array_create(cf->pool, 1, sizeof(rap_table_elt_t));
        if (ahcf->headers == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    header = rap_array_push(ahcf->headers);
    if (header == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    header->key = value[1];
    header->value = value[2];

    return RAP_CONF_OK;
}

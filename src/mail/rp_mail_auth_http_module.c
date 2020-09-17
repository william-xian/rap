
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
    rp_addr_t                     *peer;

    rp_msec_t                      timeout;
    rp_flag_t                      pass_client_cert;

    rp_str_t                       host_header;
    rp_str_t                       uri;
    rp_str_t                       header;

    rp_array_t                    *headers;

    u_char                         *file;
    rp_uint_t                      line;
} rp_mail_auth_http_conf_t;


typedef struct rp_mail_auth_http_ctx_s  rp_mail_auth_http_ctx_t;

typedef void (*rp_mail_auth_http_handler_pt)(rp_mail_session_t *s,
    rp_mail_auth_http_ctx_t *ctx);

struct rp_mail_auth_http_ctx_s {
    rp_buf_t                      *request;
    rp_buf_t                      *response;
    rp_peer_connection_t           peer;

    rp_mail_auth_http_handler_pt   handler;

    rp_uint_t                      state;

    u_char                         *header_name_start;
    u_char                         *header_name_end;
    u_char                         *header_start;
    u_char                         *header_end;

    rp_str_t                       addr;
    rp_str_t                       port;
    rp_str_t                       err;
    rp_str_t                       errmsg;
    rp_str_t                       errcode;

    time_t                          sleep;

    rp_pool_t                     *pool;
};


static void rp_mail_auth_http_write_handler(rp_event_t *wev);
static void rp_mail_auth_http_read_handler(rp_event_t *rev);
static void rp_mail_auth_http_ignore_status_line(rp_mail_session_t *s,
    rp_mail_auth_http_ctx_t *ctx);
static void rp_mail_auth_http_process_headers(rp_mail_session_t *s,
    rp_mail_auth_http_ctx_t *ctx);
static void rp_mail_auth_sleep_handler(rp_event_t *rev);
static rp_int_t rp_mail_auth_http_parse_header_line(rp_mail_session_t *s,
    rp_mail_auth_http_ctx_t *ctx);
static void rp_mail_auth_http_block_read(rp_event_t *rev);
static void rp_mail_auth_http_dummy_handler(rp_event_t *ev);
static rp_buf_t *rp_mail_auth_http_create_request(rp_mail_session_t *s,
    rp_pool_t *pool, rp_mail_auth_http_conf_t *ahcf);
static rp_int_t rp_mail_auth_http_escape(rp_pool_t *pool, rp_str_t *text,
    rp_str_t *escaped);

static void *rp_mail_auth_http_create_conf(rp_conf_t *cf);
static char *rp_mail_auth_http_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_mail_auth_http(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_mail_auth_http_header(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_mail_auth_http_commands[] = {

    { rp_string("auth_http"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_mail_auth_http,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("auth_http_timeout"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_auth_http_conf_t, timeout),
      NULL },

    { rp_string("auth_http_header"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE2,
      rp_mail_auth_http_header,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("auth_http_pass_client_cert"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_auth_http_conf_t, pass_client_cert),
      NULL },

      rp_null_command
};


static rp_mail_module_t  rp_mail_auth_http_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_mail_auth_http_create_conf,        /* create server configuration */
    rp_mail_auth_http_merge_conf          /* merge server configuration */
};


rp_module_t  rp_mail_auth_http_module = {
    RP_MODULE_V1,
    &rp_mail_auth_http_module_ctx,        /* module context */
    rp_mail_auth_http_commands,           /* module directives */
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


static rp_str_t   rp_mail_auth_http_method[] = {
    rp_string("plain"),
    rp_string("plain"),
    rp_string("plain"),
    rp_string("apop"),
    rp_string("cram-md5"),
    rp_string("external"),
    rp_string("none")
};

static rp_str_t   rp_mail_smtp_errcode = rp_string("535 5.7.0");


void
rp_mail_auth_http_init(rp_mail_session_t *s)
{
    rp_int_t                   rc;
    rp_pool_t                 *pool;
    rp_mail_auth_http_ctx_t   *ctx;
    rp_mail_auth_http_conf_t  *ahcf;

    s->connection->log->action = "in http auth state";

    pool = rp_create_pool(2048, s->connection->log);
    if (pool == NULL) {
        rp_mail_session_internal_server_error(s);
        return;
    }

    ctx = rp_pcalloc(pool, sizeof(rp_mail_auth_http_ctx_t));
    if (ctx == NULL) {
        rp_destroy_pool(pool);
        rp_mail_session_internal_server_error(s);
        return;
    }

    ctx->pool = pool;

    ahcf = rp_mail_get_module_srv_conf(s, rp_mail_auth_http_module);

    ctx->request = rp_mail_auth_http_create_request(s, pool, ahcf);
    if (ctx->request == NULL) {
        rp_destroy_pool(ctx->pool);
        rp_mail_session_internal_server_error(s);
        return;
    }

    rp_mail_set_ctx(s, ctx, rp_mail_auth_http_module);

    ctx->peer.sockaddr = ahcf->peer->sockaddr;
    ctx->peer.socklen = ahcf->peer->socklen;
    ctx->peer.name = &ahcf->peer->name;
    ctx->peer.get = rp_event_get_peer;
    ctx->peer.log = s->connection->log;
    ctx->peer.log_error = RP_ERROR_ERR;

    rc = rp_event_connect_peer(&ctx->peer);

    if (rc == RP_ERROR || rc == RP_BUSY || rc == RP_DECLINED) {
        if (ctx->peer.connection) {
            rp_close_connection(ctx->peer.connection);
        }

        rp_destroy_pool(ctx->pool);
        rp_mail_session_internal_server_error(s);
        return;
    }

    ctx->peer.connection->data = s;
    ctx->peer.connection->pool = s->connection->pool;

    s->connection->read->handler = rp_mail_auth_http_block_read;
    ctx->peer.connection->read->handler = rp_mail_auth_http_read_handler;
    ctx->peer.connection->write->handler = rp_mail_auth_http_write_handler;

    ctx->handler = rp_mail_auth_http_ignore_status_line;

    rp_add_timer(ctx->peer.connection->read, ahcf->timeout);
    rp_add_timer(ctx->peer.connection->write, ahcf->timeout);

    if (rc == RP_OK) {
        rp_mail_auth_http_write_handler(ctx->peer.connection->write);
        return;
    }
}


static void
rp_mail_auth_http_write_handler(rp_event_t *wev)
{
    ssize_t                     n, size;
    rp_connection_t           *c;
    rp_mail_session_t         *s;
    rp_mail_auth_http_ctx_t   *ctx;
    rp_mail_auth_http_conf_t  *ahcf;

    c = wev->data;
    s = c->data;

    ctx = rp_mail_get_module_ctx(s, rp_mail_auth_http_module);

    rp_log_debug0(RP_LOG_DEBUG_MAIL, wev->log, 0,
                   "mail auth http write handler");

    if (wev->timedout) {
        rp_log_error(RP_LOG_ERR, wev->log, RP_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        rp_close_connection(c);
        rp_destroy_pool(ctx->pool);
        rp_mail_session_internal_server_error(s);
        return;
    }

    size = ctx->request->last - ctx->request->pos;

    n = rp_send(c, ctx->request->pos, size);

    if (n == RP_ERROR) {
        rp_close_connection(c);
        rp_destroy_pool(ctx->pool);
        rp_mail_session_internal_server_error(s);
        return;
    }

    if (n > 0) {
        ctx->request->pos += n;

        if (n == size) {
            wev->handler = rp_mail_auth_http_dummy_handler;

            if (wev->timer_set) {
                rp_del_timer(wev);
            }

            if (rp_handle_write_event(wev, 0) != RP_OK) {
                rp_close_connection(c);
                rp_destroy_pool(ctx->pool);
                rp_mail_session_internal_server_error(s);
            }

            return;
        }
    }

    if (!wev->timer_set) {
        ahcf = rp_mail_get_module_srv_conf(s, rp_mail_auth_http_module);
        rp_add_timer(wev, ahcf->timeout);
    }
}


static void
rp_mail_auth_http_read_handler(rp_event_t *rev)
{
    ssize_t                     n, size;
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_mail_auth_http_ctx_t  *ctx;

    c = rev->data;
    s = c->data;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http read handler");

    ctx = rp_mail_get_module_ctx(s, rp_mail_auth_http_module);

    if (rev->timedout) {
        rp_log_error(RP_LOG_ERR, rev->log, RP_ETIMEDOUT,
                      "auth http server %V timed out", ctx->peer.name);
        rp_close_connection(c);
        rp_destroy_pool(ctx->pool);
        rp_mail_session_internal_server_error(s);
        return;
    }

    if (ctx->response == NULL) {
        ctx->response = rp_create_temp_buf(ctx->pool, 1024);
        if (ctx->response == NULL) {
            rp_close_connection(c);
            rp_destroy_pool(ctx->pool);
            rp_mail_session_internal_server_error(s);
            return;
        }
    }

    size = ctx->response->end - ctx->response->last;

    n = rp_recv(c, ctx->response->pos, size);

    if (n > 0) {
        ctx->response->last += n;

        ctx->handler(s, ctx);
        return;
    }

    if (n == RP_AGAIN) {
        return;
    }

    rp_close_connection(c);
    rp_destroy_pool(ctx->pool);
    rp_mail_session_internal_server_error(s);
}


static void
rp_mail_auth_http_ignore_status_line(rp_mail_session_t *s,
    rp_mail_auth_http_ctx_t *ctx)
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

    rp_log_debug0(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
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

            rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                          "auth http server %V sent invalid response",
                          ctx->peer.name);
            rp_close_connection(ctx->peer.connection);
            rp_destroy_pool(ctx->pool);
            rp_mail_session_internal_server_error(s);
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
    ctx->handler = rp_mail_auth_http_process_headers;
    ctx->handler(s, ctx);
}


static void
rp_mail_auth_http_process_headers(rp_mail_session_t *s,
    rp_mail_auth_http_ctx_t *ctx)
{
    u_char      *p;
    time_t       timer;
    size_t       len, size;
    rp_int_t    rc, port, n;
    rp_addr_t  *peer;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http process headers");

    for ( ;; ) {
        rc = rp_mail_auth_http_parse_header_line(s, ctx);

        if (rc == RP_OK) {

#if (RP_DEBUG)
            {
            rp_str_t  key, value;

            key.len = ctx->header_name_end - ctx->header_name_start;
            key.data = ctx->header_name_start;
            value.len = ctx->header_end - ctx->header_start;
            value.data = ctx->header_start;

            rp_log_debug2(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header: \"%V: %V\"",
                           &key, &value);
            }
#endif

            len = ctx->header_name_end - ctx->header_name_start;

            if (len == sizeof("Auth-Status") - 1
                && rp_strncasecmp(ctx->header_name_start,
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

                case RP_MAIL_POP3_PROTOCOL:
                    size = sizeof("-ERR ") - 1 + len + sizeof(CRLF) - 1;
                    break;

                case RP_MAIL_IMAP_PROTOCOL:
                    size = s->tag.len + sizeof("NO ") - 1 + len
                           + sizeof(CRLF) - 1;
                    break;

                default: /* RP_MAIL_SMTP_PROTOCOL */
                    ctx->err = ctx->errmsg;
                    continue;
                }

                p = rp_pnalloc(s->connection->pool, size);
                if (p == NULL) {
                    rp_close_connection(ctx->peer.connection);
                    rp_destroy_pool(ctx->pool);
                    rp_mail_session_internal_server_error(s);
                    return;
                }

                ctx->err.data = p;

                switch (s->protocol) {

                case RP_MAIL_POP3_PROTOCOL:
                    *p++ = '-'; *p++ = 'E'; *p++ = 'R'; *p++ = 'R'; *p++ = ' ';
                    break;

                case RP_MAIL_IMAP_PROTOCOL:
                    p = rp_cpymem(p, s->tag.data, s->tag.len);
                    *p++ = 'N'; *p++ = 'O'; *p++ = ' ';
                    break;

                default: /* RP_MAIL_SMTP_PROTOCOL */
                    break;
                }

                p = rp_cpymem(p, ctx->header_start, len);
                *p++ = CR; *p++ = LF;

                ctx->err.len = p - ctx->err.data;

                continue;
            }

            if (len == sizeof("Auth-Server") - 1
                && rp_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Server",
                                   sizeof("Auth-Server") - 1)
                    == 0)
            {
                ctx->addr.len = ctx->header_end - ctx->header_start;
                ctx->addr.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-Port") - 1
                && rp_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Port",
                                   sizeof("Auth-Port") - 1)
                   == 0)
            {
                ctx->port.len = ctx->header_end - ctx->header_start;
                ctx->port.data = ctx->header_start;

                continue;
            }

            if (len == sizeof("Auth-User") - 1
                && rp_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-User",
                                   sizeof("Auth-User") - 1)
                   == 0)
            {
                s->login.len = ctx->header_end - ctx->header_start;

                s->login.data = rp_pnalloc(s->connection->pool, s->login.len);
                if (s->login.data == NULL) {
                    rp_close_connection(ctx->peer.connection);
                    rp_destroy_pool(ctx->pool);
                    rp_mail_session_internal_server_error(s);
                    return;
                }

                rp_memcpy(s->login.data, ctx->header_start, s->login.len);

                continue;
            }

            if (len == sizeof("Auth-Pass") - 1
                && rp_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Pass",
                                   sizeof("Auth-Pass") - 1)
                   == 0)
            {
                s->passwd.len = ctx->header_end - ctx->header_start;

                s->passwd.data = rp_pnalloc(s->connection->pool,
                                             s->passwd.len);
                if (s->passwd.data == NULL) {
                    rp_close_connection(ctx->peer.connection);
                    rp_destroy_pool(ctx->pool);
                    rp_mail_session_internal_server_error(s);
                    return;
                }

                rp_memcpy(s->passwd.data, ctx->header_start, s->passwd.len);

                continue;
            }

            if (len == sizeof("Auth-Wait") - 1
                && rp_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Wait",
                                   sizeof("Auth-Wait") - 1)
                   == 0)
            {
                n = rp_atoi(ctx->header_start,
                             ctx->header_end - ctx->header_start);

                if (n != RP_ERROR) {
                    ctx->sleep = n;
                }

                continue;
            }

            if (len == sizeof("Auth-Error-Code") - 1
                && rp_strncasecmp(ctx->header_name_start,
                                   (u_char *) "Auth-Error-Code",
                                   sizeof("Auth-Error-Code") - 1)
                   == 0)
            {
                ctx->errcode.len = ctx->header_end - ctx->header_start;

                ctx->errcode.data = rp_pnalloc(s->connection->pool,
                                                ctx->errcode.len);
                if (ctx->errcode.data == NULL) {
                    rp_close_connection(ctx->peer.connection);
                    rp_destroy_pool(ctx->pool);
                    rp_mail_session_internal_server_error(s);
                    return;
                }

                rp_memcpy(ctx->errcode.data, ctx->header_start,
                           ctx->errcode.len);

                continue;
            }

            /* ignore other headers */

            continue;
        }

        if (rc == RP_DONE) {
            rp_log_debug0(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
                           "mail auth http header done");

            rp_close_connection(ctx->peer.connection);

            if (ctx->err.len) {

                rp_log_error(RP_LOG_INFO, s->connection->log, 0,
                              "client login failed: \"%V\"", &ctx->errmsg);

                if (s->protocol == RP_MAIL_SMTP_PROTOCOL) {

                    if (ctx->errcode.len == 0) {
                        ctx->errcode = rp_mail_smtp_errcode;
                    }

                    ctx->err.len = ctx->errcode.len + ctx->errmsg.len
                                   + sizeof(" " CRLF) - 1;

                    p = rp_pnalloc(s->connection->pool, ctx->err.len);
                    if (p == NULL) {
                        rp_destroy_pool(ctx->pool);
                        rp_mail_session_internal_server_error(s);
                        return;
                    }

                    ctx->err.data = p;

                    p = rp_cpymem(p, ctx->errcode.data, ctx->errcode.len);
                    *p++ = ' ';
                    p = rp_cpymem(p, ctx->errmsg.data, ctx->errmsg.len);
                    *p++ = CR; *p = LF;
                }

                s->out = ctx->err;
                timer = ctx->sleep;

                rp_destroy_pool(ctx->pool);

                if (timer == 0) {
                    s->quit = 1;
                    rp_mail_send(s->connection->write);
                    return;
                }

                rp_add_timer(s->connection->read, (rp_msec_t) (timer * 1000));

                s->connection->read->handler = rp_mail_auth_sleep_handler;

                return;
            }

            if (s->auth_wait) {
                timer = ctx->sleep;

                rp_destroy_pool(ctx->pool);

                if (timer == 0) {
                    rp_mail_auth_http_init(s);
                    return;
                }

                rp_add_timer(s->connection->read, (rp_msec_t) (timer * 1000));

                s->connection->read->handler = rp_mail_auth_sleep_handler;

                return;
            }

            if (ctx->addr.len == 0 || ctx->port.len == 0) {
                rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send server or port",
                              ctx->peer.name);
                rp_destroy_pool(ctx->pool);
                rp_mail_session_internal_server_error(s);
                return;
            }

            if (s->passwd.data == NULL
                && s->protocol != RP_MAIL_SMTP_PROTOCOL)
            {
                rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V did not send password",
                              ctx->peer.name);
                rp_destroy_pool(ctx->pool);
                rp_mail_session_internal_server_error(s);
                return;
            }

            peer = rp_pcalloc(s->connection->pool, sizeof(rp_addr_t));
            if (peer == NULL) {
                rp_destroy_pool(ctx->pool);
                rp_mail_session_internal_server_error(s);
                return;
            }

            rc = rp_parse_addr(s->connection->pool, peer,
                                ctx->addr.data, ctx->addr.len);

            switch (rc) {
            case RP_OK:
                break;

            case RP_DECLINED:
                rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "address:\"%V\"",
                              ctx->peer.name, &ctx->addr);
                /* fall through */

            default:
                rp_destroy_pool(ctx->pool);
                rp_mail_session_internal_server_error(s);
                return;
            }

            port = rp_atoi(ctx->port.data, ctx->port.len);
            if (port == RP_ERROR || port < 1 || port > 65535) {
                rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                              "auth http server %V sent invalid server "
                              "port:\"%V\"",
                              ctx->peer.name, &ctx->port);
                rp_destroy_pool(ctx->pool);
                rp_mail_session_internal_server_error(s);
                return;
            }

            rp_inet_set_port(peer->sockaddr, (in_port_t) port);

            len = ctx->addr.len + 1 + ctx->port.len;

            peer->name.len = len;

            peer->name.data = rp_pnalloc(s->connection->pool, len);
            if (peer->name.data == NULL) {
                rp_destroy_pool(ctx->pool);
                rp_mail_session_internal_server_error(s);
                return;
            }

            len = ctx->addr.len;

            rp_memcpy(peer->name.data, ctx->addr.data, len);

            peer->name.data[len++] = ':';

            rp_memcpy(peer->name.data + len, ctx->port.data, ctx->port.len);

            rp_destroy_pool(ctx->pool);
            rp_mail_proxy_init(s, peer);

            return;
        }

        if (rc == RP_AGAIN ) {
            return;
        }

        /* rc == RP_ERROR */

        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "auth http server %V sent invalid header in response",
                      ctx->peer.name);
        rp_close_connection(ctx->peer.connection);
        rp_destroy_pool(ctx->pool);
        rp_mail_session_internal_server_error(s);

        return;
    }
}


static void
rp_mail_auth_sleep_handler(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_mail_core_srv_conf_t  *cscf;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0, "mail auth sleep handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {

        rev->timedout = 0;

        if (s->auth_wait) {
            s->auth_wait = 0;
            rp_mail_auth_http_init(s);
            return;
        }

        cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

        rev->handler = cscf->protocol->auth_state;

        s->mail_state = 0;
        s->auth_method = RP_MAIL_AUTH_PLAIN;

        c->log->action = "in auth state";

        rp_mail_send(c->write);

        if (c->destroyed) {
            return;
        }

        rp_add_timer(rev, cscf->timeout);

        if (rev->ready) {
            rev->handler(rev);
            return;
        }

        if (rp_handle_read_event(rev, 0) != RP_OK) {
            rp_mail_close_connection(c);
        }

        return;
    }

    if (rev->active) {
        if (rp_handle_read_event(rev, 0) != RP_OK) {
            rp_mail_close_connection(c);
        }
    }
}


static rp_int_t
rp_mail_auth_http_parse_header_line(rp_mail_session_t *s,
    rp_mail_auth_http_ctx_t *ctx)
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

                return RP_ERROR;
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

            return RP_ERROR;

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
                return RP_ERROR;
            }

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return RP_ERROR;
            }
        }
    }

    ctx->response->pos = p;
    ctx->state = state;

    return RP_AGAIN;

done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RP_OK;

header_done:

    ctx->response->pos = p + 1;
    ctx->state = sw_start;

    return RP_DONE;
}


static void
rp_mail_auth_http_block_read(rp_event_t *rev)
{
    rp_connection_t          *c;
    rp_mail_session_t        *s;
    rp_mail_auth_http_ctx_t  *ctx;

    rp_log_debug0(RP_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail auth http block read");

    if (rp_handle_read_event(rev, 0) != RP_OK) {
        c = rev->data;
        s = c->data;

        ctx = rp_mail_get_module_ctx(s, rp_mail_auth_http_module);

        rp_close_connection(ctx->peer.connection);
        rp_destroy_pool(ctx->pool);
        rp_mail_session_internal_server_error(s);
    }
}


static void
rp_mail_auth_http_dummy_handler(rp_event_t *ev)
{
    rp_log_debug0(RP_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail auth http dummy handler");
}


static rp_buf_t *
rp_mail_auth_http_create_request(rp_mail_session_t *s, rp_pool_t *pool,
    rp_mail_auth_http_conf_t *ahcf)
{
    size_t                     len;
    rp_buf_t                 *b;
    rp_str_t                  login, passwd;
#if (RP_MAIL_SSL)
    rp_str_t                  verify, subject, issuer, serial, fingerprint,
                               raw_cert, cert;
    rp_connection_t          *c;
    rp_mail_ssl_conf_t       *sslcf;
#endif
    rp_mail_core_srv_conf_t  *cscf;

    if (rp_mail_auth_http_escape(pool, &s->login, &login) != RP_OK) {
        return NULL;
    }

    if (rp_mail_auth_http_escape(pool, &s->passwd, &passwd) != RP_OK) {
        return NULL;
    }

#if (RP_MAIL_SSL)

    c = s->connection;
    sslcf = rp_mail_get_module_srv_conf(s, rp_mail_ssl_module);

    if (c->ssl && sslcf->verify) {

        /* certificate details */

        if (rp_ssl_get_client_verify(c, pool, &verify) != RP_OK) {
            return NULL;
        }

        if (rp_ssl_get_subject_dn(c, pool, &subject) != RP_OK) {
            return NULL;
        }

        if (rp_ssl_get_issuer_dn(c, pool, &issuer) != RP_OK) {
            return NULL;
        }

        if (rp_ssl_get_serial_number(c, pool, &serial) != RP_OK) {
            return NULL;
        }

        if (rp_ssl_get_fingerprint(c, pool, &fingerprint) != RP_OK) {
            return NULL;
        }

        if (ahcf->pass_client_cert) {

            /* certificate itself, if configured */

            if (rp_ssl_get_raw_certificate(c, pool, &raw_cert) != RP_OK) {
                return NULL;
            }

            if (rp_mail_auth_http_escape(pool, &raw_cert, &cert) != RP_OK) {
                return NULL;
            }

        } else {
            rp_str_null(&cert);
        }

    } else {
        rp_str_null(&verify);
        rp_str_null(&subject);
        rp_str_null(&issuer);
        rp_str_null(&serial);
        rp_str_null(&fingerprint);
        rp_str_null(&cert);
    }

#endif

    cscf = rp_mail_get_module_srv_conf(s, rp_mail_core_module);

    len = sizeof("GET ") - 1 + ahcf->uri.len + sizeof(" HTTP/1.0" CRLF) - 1
          + sizeof("Host: ") - 1 + ahcf->host_header.len + sizeof(CRLF) - 1
          + sizeof("Auth-Method: ") - 1
                + rp_mail_auth_http_method[s->auth_method].len
                + sizeof(CRLF) - 1
          + sizeof("Auth-User: ") - 1 + login.len + sizeof(CRLF) - 1
          + sizeof("Auth-Pass: ") - 1 + passwd.len + sizeof(CRLF) - 1
          + sizeof("Auth-Salt: ") - 1 + s->salt.len
          + sizeof("Auth-Protocol: ") - 1 + cscf->protocol->name.len
                + sizeof(CRLF) - 1
          + sizeof("Auth-Login-Attempt: ") - 1 + RP_INT_T_LEN
                + sizeof(CRLF) - 1
          + sizeof("Client-IP: ") - 1 + s->connection->addr_text.len
                + sizeof(CRLF) - 1
          + sizeof("Client-Host: ") - 1 + s->host.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-Helo: ") - 1 + s->smtp_helo.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-From: ") - 1 + s->smtp_from.len + sizeof(CRLF) - 1
          + sizeof("Auth-SMTP-To: ") - 1 + s->smtp_to.len + sizeof(CRLF) - 1
#if (RP_MAIL_SSL)
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

    b = rp_create_temp_buf(pool, len);
    if (b == NULL) {
        return NULL;
    }

    b->last = rp_cpymem(b->last, "GET ", sizeof("GET ") - 1);
    b->last = rp_copy(b->last, ahcf->uri.data, ahcf->uri.len);
    b->last = rp_cpymem(b->last, " HTTP/1.0" CRLF,
                         sizeof(" HTTP/1.0" CRLF) - 1);

    b->last = rp_cpymem(b->last, "Host: ", sizeof("Host: ") - 1);
    b->last = rp_copy(b->last, ahcf->host_header.data,
                         ahcf->host_header.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rp_cpymem(b->last, "Auth-Method: ",
                         sizeof("Auth-Method: ") - 1);
    b->last = rp_cpymem(b->last,
                         rp_mail_auth_http_method[s->auth_method].data,
                         rp_mail_auth_http_method[s->auth_method].len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rp_cpymem(b->last, "Auth-User: ", sizeof("Auth-User: ") - 1);
    b->last = rp_copy(b->last, login.data, login.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rp_cpymem(b->last, "Auth-Pass: ", sizeof("Auth-Pass: ") - 1);
    b->last = rp_copy(b->last, passwd.data, passwd.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->auth_method != RP_MAIL_AUTH_PLAIN && s->salt.len) {
        b->last = rp_cpymem(b->last, "Auth-Salt: ", sizeof("Auth-Salt: ") - 1);
        b->last = rp_copy(b->last, s->salt.data, s->salt.len);

        s->passwd.data = NULL;
    }

    b->last = rp_cpymem(b->last, "Auth-Protocol: ",
                         sizeof("Auth-Protocol: ") - 1);
    b->last = rp_cpymem(b->last, cscf->protocol->name.data,
                         cscf->protocol->name.len);
    *b->last++ = CR; *b->last++ = LF;

    b->last = rp_sprintf(b->last, "Auth-Login-Attempt: %ui" CRLF,
                          s->login_attempt);

    b->last = rp_cpymem(b->last, "Client-IP: ", sizeof("Client-IP: ") - 1);
    b->last = rp_copy(b->last, s->connection->addr_text.data,
                       s->connection->addr_text.len);
    *b->last++ = CR; *b->last++ = LF;

    if (s->host.len) {
        b->last = rp_cpymem(b->last, "Client-Host: ",
                             sizeof("Client-Host: ") - 1);
        b->last = rp_copy(b->last, s->host.data, s->host.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    if (s->auth_method == RP_MAIL_AUTH_NONE) {

        /* HELO, MAIL FROM, and RCPT TO can't contain CRLF, no need to escape */

        b->last = rp_cpymem(b->last, "Auth-SMTP-Helo: ",
                             sizeof("Auth-SMTP-Helo: ") - 1);
        b->last = rp_copy(b->last, s->smtp_helo.data, s->smtp_helo.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = rp_cpymem(b->last, "Auth-SMTP-From: ",
                             sizeof("Auth-SMTP-From: ") - 1);
        b->last = rp_copy(b->last, s->smtp_from.data, s->smtp_from.len);
        *b->last++ = CR; *b->last++ = LF;

        b->last = rp_cpymem(b->last, "Auth-SMTP-To: ",
                             sizeof("Auth-SMTP-To: ") - 1);
        b->last = rp_copy(b->last, s->smtp_to.data, s->smtp_to.len);
        *b->last++ = CR; *b->last++ = LF;

    }

#if (RP_MAIL_SSL)

    if (c->ssl) {
        b->last = rp_cpymem(b->last, "Auth-SSL: on" CRLF,
                             sizeof("Auth-SSL: on" CRLF) - 1);

        if (verify.len) {
            b->last = rp_cpymem(b->last, "Auth-SSL-Verify: ",
                                 sizeof("Auth-SSL-Verify: ") - 1);
            b->last = rp_copy(b->last, verify.data, verify.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (subject.len) {
            b->last = rp_cpymem(b->last, "Auth-SSL-Subject: ",
                                 sizeof("Auth-SSL-Subject: ") - 1);
            b->last = rp_copy(b->last, subject.data, subject.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (issuer.len) {
            b->last = rp_cpymem(b->last, "Auth-SSL-Issuer: ",
                                 sizeof("Auth-SSL-Issuer: ") - 1);
            b->last = rp_copy(b->last, issuer.data, issuer.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (serial.len) {
            b->last = rp_cpymem(b->last, "Auth-SSL-Serial: ",
                                 sizeof("Auth-SSL-Serial: ") - 1);
            b->last = rp_copy(b->last, serial.data, serial.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (fingerprint.len) {
            b->last = rp_cpymem(b->last, "Auth-SSL-Fingerprint: ",
                                 sizeof("Auth-SSL-Fingerprint: ") - 1);
            b->last = rp_copy(b->last, fingerprint.data, fingerprint.len);
            *b->last++ = CR; *b->last++ = LF;
        }

        if (cert.len) {
            b->last = rp_cpymem(b->last, "Auth-SSL-Cert: ",
                                 sizeof("Auth-SSL-Cert: ") - 1);
            b->last = rp_copy(b->last, cert.data, cert.len);
            *b->last++ = CR; *b->last++ = LF;
        }
    }

#endif

    if (ahcf->header.len) {
        b->last = rp_copy(b->last, ahcf->header.data, ahcf->header.len);
    }

    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

#if (RP_DEBUG_MAIL_PASSWD)
    rp_log_debug2(RP_LOG_DEBUG_MAIL, s->connection->log, 0,
                   "mail auth http header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);
#endif

    return b;
}


static rp_int_t
rp_mail_auth_http_escape(rp_pool_t *pool, rp_str_t *text, rp_str_t *escaped)
{
    u_char     *p;
    uintptr_t   n;

    n = rp_escape_uri(NULL, text->data, text->len, RP_ESCAPE_MAIL_AUTH);

    if (n == 0) {
        *escaped = *text;
        return RP_OK;
    }

    escaped->len = text->len + n * 2;

    p = rp_pnalloc(pool, escaped->len);
    if (p == NULL) {
        return RP_ERROR;
    }

    (void) rp_escape_uri(p, text->data, text->len, RP_ESCAPE_MAIL_AUTH);

    escaped->data = p;

    return RP_OK;
}


static void *
rp_mail_auth_http_create_conf(rp_conf_t *cf)
{
    rp_mail_auth_http_conf_t  *ahcf;

    ahcf = rp_pcalloc(cf->pool, sizeof(rp_mail_auth_http_conf_t));
    if (ahcf == NULL) {
        return NULL;
    }

    ahcf->timeout = RP_CONF_UNSET_MSEC;
    ahcf->pass_client_cert = RP_CONF_UNSET;

    ahcf->file = cf->conf_file->file.name.data;
    ahcf->line = cf->conf_file->line;

    return ahcf;
}


static char *
rp_mail_auth_http_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_mail_auth_http_conf_t *prev = parent;
    rp_mail_auth_http_conf_t *conf = child;

    u_char           *p;
    size_t            len;
    rp_uint_t        i;
    rp_table_elt_t  *header;

    if (conf->peer == NULL) {
        conf->peer = prev->peer;
        conf->host_header = prev->host_header;
        conf->uri = prev->uri;

        if (conf->peer == NULL) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"auth_http\" is defined for server in %s:%ui",
                          conf->file, conf->line);

            return RP_CONF_ERROR;
        }
    }

    rp_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);

    rp_conf_merge_value(conf->pass_client_cert, prev->pass_client_cert, 0);

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

        p = rp_pnalloc(cf->pool, len);
        if (p == NULL) {
            return RP_CONF_ERROR;
        }

        conf->header.len = len;
        conf->header.data = p;

        for (i = 0; i < conf->headers->nelts; i++) {
            p = rp_cpymem(p, header[i].key.data, header[i].key.len);
            *p++ = ':'; *p++ = ' ';
            p = rp_cpymem(p, header[i].value.data, header[i].value.len);
            *p++ = CR; *p++ = LF;
        }
    }

    return RP_CONF_OK;
}


static char *
rp_mail_auth_http(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_auth_http_conf_t *ahcf = conf;

    rp_str_t  *value;
    rp_url_t   u;

    value = cf->args->elts;

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = value[1];
    u.default_port = 80;
    u.uri_part = 1;

    if (rp_strncmp(u.url.data, "http://", 7) == 0) {
        u.url.len -= 7;
        u.url.data += 7;
    }

    if (rp_parse_url(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "%s in auth_http \"%V\"", u.err, &u.url);
        }

        return RP_CONF_ERROR;
    }

    ahcf->peer = u.addrs;

    if (u.family != AF_UNIX) {
        ahcf->host_header = u.host;

    } else {
        rp_str_set(&ahcf->host_header, "localhost");
    }

    ahcf->uri = u.uri;

    if (ahcf->uri.len == 0) {
        rp_str_set(&ahcf->uri, "/");
    }

    return RP_CONF_OK;
}


static char *
rp_mail_auth_http_header(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_auth_http_conf_t *ahcf = conf;

    rp_str_t        *value;
    rp_table_elt_t  *header;

    if (ahcf->headers == NULL) {
        ahcf->headers = rp_array_create(cf->pool, 1, sizeof(rp_table_elt_t));
        if (ahcf->headers == NULL) {
            return RP_CONF_ERROR;
        }
    }

    header = rp_array_push(ahcf->headers);
    if (header == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    header->key = value[1];
    header->value = value[2];

    return RP_CONF_OK;
}
